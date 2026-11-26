import { describe, expect, test } from "bun:test";
import {
  E2eeCryptoError,
  WORKSPACE_E2EE_KDF_ALGORITHM,
  WORKSPACE_E2EE_KDF_ITERATIONS,
  WorkspaceE2eeKeyringUpsertSchema,
  decodeBase64Strict,
  decryptNoteContent,
  encodeBase64,
  encryptNoteContent,
  hasEncryptedNoteFencePrefix,
  hasEncryptedNoteMarker,
  initializeWorkspaceKeyring,
  isSuspiciousMemoOverwrite,
  isValidEncryptedNoteEnvelope,
  parseEncryptedNoteEnvelope,
  rotateWorkspacePassphrase,
  serializeEncryptedNoteEnvelope,
  unlockWorkspaceMasterKey,
  webCryptoE2eeProvider,
  zeroizeBytes,
} from "./index.ts";
import {
  EdgeEverZipImportError,
  createEdgeEverZip,
  parseEdgeEverZip,
  validateBackupRelationships,
} from "./backup-archive.ts";

describe("e2ee envelope parsing and serialization", () => {
  const validEnvelope = {
    v: 1,
    alg: "A256GCM",
    keyId: "ek_0123456789abcdef",
    wrappedDek: encodeBase64(new Uint8Array(48).fill(1)),
    dekIv: encodeBase64(new Uint8Array(12).fill(2)),
    iv: encodeBase64(new Uint8Array(12).fill(3)),
    ciphertext: encodeBase64(new Uint8Array(32).fill(4)),
  };

  test("round-trips a canonical encrypted note envelope", () => {
    const markdown = serializeEncryptedNoteEnvelope(validEnvelope);
    expect(hasEncryptedNoteMarker(markdown)).toBe(true);
    expect(parseEncryptedNoteEnvelope(markdown)).toEqual(validEnvelope);
    expect(parseEncryptedNoteEnvelope(`\r\n${markdown.replace(/\n/g, "\r\n")}\r\n`)).toEqual(validEnvelope);
  });

  test("separates cheap O(1) read-side marker check from strict write-side envelope validation", () => {
    const validMarkdown = serializeEncryptedNoteEnvelope(validEnvelope);
    expect(hasEncryptedNoteMarker(validMarkdown)).toBe(true);
    expect(isValidEncryptedNoteEnvelope(validMarkdown)).toBe(true);
    expect(hasEncryptedNoteMarker(`\r\n${validMarkdown.replace(/\n/g, "\r\n")}\r\n`)).toBe(true);
    expect(isValidEncryptedNoteEnvelope(`\r\n${validMarkdown.replace(/\n/g, "\r\n")}\r\n`)).toBe(true);

    const fencePrefixedMalformedCases = [
      `${validMarkdown}\n\nTrailing plaintext`,
      `${validMarkdown}\n\n<!-- edgeever-poster-v1:e30 -->`,
      `${validMarkdown}\n\n${validMarkdown}`,
      "```edgeever-encrypted-note\n{\"v\":1}\n```",
      "```edgeever-encrypted-note\n{\"v\":1,\"alg\":\"A256GCM\"",
      "~~~edgeever-encrypted-note\n" + JSON.stringify(validEnvelope) + "\n~~~",
      "```edgeever-encrypted-note\n" + JSON.stringify({ ...validEnvelope, extra: true }) + "\n```",
      "```edgeever-encrypted-note\n" + JSON.stringify({ ...validEnvelope, iv: encodeBase64(new Uint8Array(16)) }) + "\n```",
      "```edgeever-encrypted-note\n" + JSON.stringify({ ...validEnvelope, ciphertext: encodeBase64(new Uint8Array(8)) }) + "\n```",
    ];

    for (const candidate of fencePrefixedMalformedCases) {
      expect(hasEncryptedNoteFencePrefix(candidate)).toBe(true);
      expect(isValidEncryptedNoteEnvelope(candidate)).toBe(false);
      expect(parseEncryptedNoteEnvelope(candidate)).toBeNull();
    }

    // Cheap read-side marker rejects non-fenced, trailing-text, tilde-fenced, empty, and mid-body fences.
    expect(hasEncryptedNoteMarker(`${validMarkdown}\n\nTrailing plaintext`)).toBe(false);
    expect(hasEncryptedNoteMarker(`${validMarkdown}\n\n<!-- edgeever-poster-v1:e30 -->`)).toBe(false);
    expect(hasEncryptedNoteMarker("```edgeever-encrypted-note\n{\"v\":1,\"alg\":\"A256GCM\"")).toBe(false);
    expect(hasEncryptedNoteMarker("~~~edgeever-encrypted-note\n" + JSON.stringify(validEnvelope) + "\n~~~")).toBe(false);
    expect(hasEncryptedNoteMarker("```edgeever-encrypted-note\n\n```")).toBe(false);

    // Cheap read-side marker accepts structurally fenced blocks without JSON/base64 parsing,
    // while strict write-side validation rejects invalid payloads.
    const structurallyFencedMalformed = "```edgeever-encrypted-note\n{\"v\":1}\n```";
    expect(hasEncryptedNoteMarker(structurallyFencedMalformed)).toBe(true);
    expect(isValidEncryptedNoteEnvelope(structurallyFencedMalformed)).toBe(false);

    // Ordinary plaintext note mentioning or quoting an encrypted fence mid-body is NOT encrypted and NOT fence-prefixed.
    const proseWithFence = `Intro plaintext\n\n${validMarkdown}`;
    expect(hasEncryptedNoteFencePrefix(proseWithFence)).toBe(false);
    expect(hasEncryptedNoteMarker(proseWithFence)).toBe(false);
    expect(isValidEncryptedNoteEnvelope(proseWithFence)).toBe(false);
    expect(parseEncryptedNoteEnvelope(proseWithFence)).toBeNull();

    // Inline code prose mention should not trigger either check.
    expect(hasEncryptedNoteFencePrefix("EdgeEver uses `edgeever-encrypted-note` blocks.")).toBe(false);
    expect(hasEncryptedNoteMarker("EdgeEver uses `edgeever-encrypted-note` blocks.")).toBe(false);
    expect(isValidEncryptedNoteEnvelope("EdgeEver uses `edgeever-encrypted-note` blocks.")).toBe(false);
  });
});

describe("e2ee crypto protocol", () => {
  test("initializes keyring, unlocks WMK portably without workspaceId, encrypts/decrypts notes, and rejects tampering and transplant attacks", async () => {
    const passphrase = "correct horse battery staple";
    const { masterKey, keyring } = await initializeWorkspaceKeyring({
      passphrase,
    });

    expect(masterKey.byteLength).toBe(32);
    expect(keyring.kdfAlgorithm).toBe(WORKSPACE_E2EE_KDF_ALGORITHM);
    expect(keyring.kdfIterations).toBe(WORKSPACE_E2EE_KDF_ITERATIONS);
    expect(decodeBase64Strict(keyring.kdfSalt)?.byteLength).toBe(16);
    expect(decodeBase64Strict(keyring.masterKeyIv)?.byteLength).toBe(12);
    expect(decodeBase64Strict(keyring.wrappedMasterKey)?.byteLength).toBe(48);
    expect(WorkspaceE2eeKeyringUpsertSchema.safeParse(keyring).success).toBe(true);

    // Unlock with correct passphrase yields identical WMK.
    const unlocked = await unlockWorkspaceMasterKey({
      passphrase,
      keyring,
    });
    expect(unlocked).toEqual(masterKey);

    // Wrong passphrase is rejected.
    await expect(
      unlockWorkspaceMasterKey({
        passphrase: "wrong passphrase",
        keyring,
      }),
    ).rejects.toThrow(E2eeCryptoError);

    // Tampered keyId or kdfIterations fails WMK AAD verification.
    await expect(
      unlockWorkspaceMasterKey({
        passphrase,
        keyring: { ...keyring, keyId: "ek_tampered_key_id_123" },
      }),
    ).rejects.toThrow(E2eeCryptoError);
    await expect(
      unlockWorkspaceMasterKey({
        passphrase,
        keyring: { ...keyring, kdfIterations: WORKSPACE_E2EE_KDF_ITERATIONS + 1 },
      }),
    ).rejects.toThrow(E2eeCryptoError);

    // Encrypt and decrypt a note with Unicode/Markdown content.
    const plaintext = "# 机密计划\n\n- 密钥永不离端\n- AES-256-GCM + AAD 绑定";
    const encrypted1 = await encryptNoteContent({
      memoId: "memo_alpha",
      keyId: keyring.keyId,
      masterKey,
      plaintextMarkdown: plaintext,
    });
    expect(hasEncryptedNoteMarker(encrypted1.markdown)).toBe(true);
    expect(parseEncryptedNoteEnvelope(encrypted1.markdown)).toEqual(encrypted1.envelope);

    const decrypted1 = await decryptNoteContent({
      memoId: "memo_alpha",
      masterKey,
      envelopeOrMarkdown: encrypted1.markdown,
    });
    expect(decrypted1.plaintextMarkdown).toBe(plaintext);

    // Saving again reuses DEK binding while generating a brand new random 12-byte IV.
    const encrypted2 = await encryptNoteContent({
      memoId: "memo_alpha",
      keyId: keyring.keyId,
      masterKey,
      plaintextMarkdown: plaintext,
      existingEnvelope: encrypted1.envelope,
    });
    expect(encrypted2.envelope.wrappedDek).toBe(encrypted1.envelope.wrappedDek);
    expect(encrypted2.envelope.dekIv).toBe(encrypted1.envelope.dekIv);
    expect(encrypted2.envelope.iv).not.toBe(encrypted1.envelope.iv);
    expect(encrypted2.envelope.ciphertext).not.toBe(encrypted1.envelope.ciphertext);
    const decrypted2 = await decryptNoteContent({
      memoId: "memo_alpha",
      masterKey,
      envelopeOrMarkdown: encrypted2.markdown,
    });
    expect(decrypted2.plaintextMarkdown).toBe(plaintext);

    // Ciphertext bit-flip tampering is rejected.
    const tamperedBytes = decodeBase64Strict(encrypted1.envelope.ciphertext);
    expect(tamperedBytes).not.toBeNull();
    tamperedBytes[0] ^= 0xff;
    const tamperedEnvelope = {
      ...encrypted1.envelope,
      ciphertext: encodeBase64(tamperedBytes),
    };
    await expect(
      decryptNoteContent({
        memoId: "memo_alpha",
        masterKey,
        envelopeOrMarkdown: tamperedEnvelope,
      }),
    ).rejects.toThrow(E2eeCryptoError);

    // Cross-memoId transplant attack is rejected by AAD binding.
    await expect(
      decryptNoteContent({
        memoId: "memo_beta",
        masterKey,
        envelopeOrMarkdown: encrypted1.markdown,
      }),
    ).rejects.toThrow(E2eeCryptoError);

    // Empty string plaintext also round-trips cleanly.
    const encryptedEmpty = await encryptNoteContent({
      memoId: "memo_empty",
      keyId: keyring.keyId,
      masterKey,
      plaintextMarkdown: "",
    });
    const decryptedEmpty = await decryptNoteContent({
      memoId: "memo_empty",
      masterKey,
      envelopeOrMarkdown: encryptedEmpty.markdown,
    });
    expect(decryptedEmpty.plaintextMarkdown).toBe("");
  });

  test("passphrase rotation preserves WMK and keyId so existing notes decrypt without re-encryption", async () => {
    const oldPassphrase = "old-passphrase-value";
    const newPassphrase = "new-stronger-passphrase-value";

    const initial = await initializeWorkspaceKeyring({
      passphrase: oldPassphrase,
    });
    const storedKeyringV1 = {
      ...initial.keyring,
      revision: 1,
      createdAt: "2026-11-26T00:00:00.000Z",
      updatedAt: "2026-11-26T00:00:00.000Z",
    };

    const noteBeforeRotation = await encryptNoteContent({
      memoId: "memo_legacy",
      keyId: storedKeyringV1.keyId,
      masterKey: initial.masterKey,
      plaintextMarkdown: "Encrypted before passphrase rotation",
    });

    // Wrong current passphrase cannot rotate.
    await expect(
      rotateWorkspacePassphrase({
        currentPassphrase: "wrong-old-passphrase",
        newPassphrase,
        currentKeyring: storedKeyringV1,
      }),
    ).rejects.toThrow(E2eeCryptoError);

    const rotated = await rotateWorkspacePassphrase({
      currentPassphrase: oldPassphrase,
      newPassphrase,
      currentKeyring: storedKeyringV1,
    });

    expect(rotated.keyring.keyId).toBe(storedKeyringV1.keyId);
    expect(rotated.keyring.expectedRevision).toBe(1);
    expect(rotated.keyring.kdfSalt).not.toBe(storedKeyringV1.kdfSalt);
    expect(rotated.keyring.masterKeyIv).not.toBe(storedKeyringV1.masterKeyIv);
    expect(rotated.masterKey).toEqual(initial.masterKey);

    // Old passphrase fails on rotated keyring; new passphrase recovers the exact WMK.
    await expect(
      unlockWorkspaceMasterKey({
        passphrase: oldPassphrase,
        keyring: rotated.keyring,
      }),
    ).rejects.toThrow(E2eeCryptoError);

    const unlockedAfterRotation = await unlockWorkspaceMasterKey({
      passphrase: newPassphrase,
      keyring: rotated.keyring,
    });
    expect(unlockedAfterRotation).toEqual(initial.masterKey);

    // Old encrypted note still decrypts with zero re-encryption.
    const decrypted = await decryptNoteContent({
      memoId: "memo_legacy",
      masterKey: unlockedAfterRotation,
      envelopeOrMarkdown: noteBeforeRotation.markdown,
    });
    expect(decrypted.plaintextMarkdown).toBe("Encrypted before passphrase rotation");
  });

  test("zeroizeBytes wipes buffers and keyring operations zeroize derived KEKs and failed temporary WMKs", async () => {
    const sample = new Uint8Array([1, 2, 3, 4, 5]);
    zeroizeBytes(sample);
    expect(sample).toEqual(new Uint8Array(5));
    expect(() => zeroizeBytes(null)).not.toThrow();
    expect(() => zeroizeBytes(undefined)).not.toThrow();

    const derivedKeks = [];
    const decryptedWmkRefs = [];
    let failNextEncrypt = false;
    const trackingProvider = {
      randomBytes: (len) => webCryptoE2eeProvider.randomBytes(len),
      pbkdf2Sha256: async (passphrase, salt, iterations, len) => {
        const kek = await webCryptoE2eeProvider.pbkdf2Sha256(passphrase, salt, iterations, len);
        derivedKeks.push(kek);
        return kek;
      },
      aesGcmEncrypt: async (key, iv, plaintext, aad) => {
        if (failNextEncrypt) throw new Error("injected wrap failure");
        return webCryptoE2eeProvider.aesGcmEncrypt(key, iv, plaintext, aad);
      },
      aesGcmDecrypt: async (key, iv, ciphertext, aad) => {
        const plain = await webCryptoE2eeProvider.aesGcmDecrypt(key, iv, ciphertext, aad);
        decryptedWmkRefs.push(plain);
        return plain;
      },
    };

    const initialized = await initializeWorkspaceKeyring({ passphrase: "pw1" }, trackingProvider);
    expect(derivedKeks).toHaveLength(1);
    expect(derivedKeks[0].every((b) => b === 0)).toBe(true);

    await unlockWorkspaceMasterKey({ passphrase: "pw1", keyring: initialized.keyring }, trackingProvider);
    expect(derivedKeks).toHaveLength(2);
    expect(derivedKeks[1].every((b) => b === 0)).toBe(true);

    // Even when re-wrap fails during rotation, both nextKek and the temporary unwrapped WMK are zeroized.
    failNextEncrypt = true;
    await expect(
      rotateWorkspacePassphrase(
        {
          currentPassphrase: "pw1",
          newPassphrase: "pw2",
          currentKeyring: {
            ...initialized.keyring,
            revision: 1,
            createdAt: "2026-11-26T00:00:00.000Z",
            updatedAt: "2026-11-26T00:00:00.000Z",
          },
        },
        trackingProvider,
      ),
    ).rejects.toThrow("injected wrap failure");
    expect(derivedKeks.every((kek) => kek.every((b) => b === 0))).toBe(true);
    expect(decryptedWmkRefs.at(-1).every((b) => b === 0)).toBe(true);
  });

  test("schema rejects downgraded PBKDF2 iterations and suspicious overwrite allows valid encryption transitions", () => {
    const validEnvelopeMarkdown = serializeEncryptedNoteEnvelope({
      v: 1,
      alg: "A256GCM",
      keyId: "ek_0123456789abcdef",
      wrappedDek: encodeBase64(new Uint8Array(48).fill(1)),
      dekIv: encodeBase64(new Uint8Array(12).fill(2)),
      iv: encodeBase64(new Uint8Array(12).fill(3)),
      ciphertext: encodeBase64(new Uint8Array(32).fill(4)),
    });

    expect(
      WorkspaceE2eeKeyringUpsertSchema.safeParse({
        keyId: "ek_0123456789abcdef",
        kdfAlgorithm: "PBKDF2-SHA256",
        kdfSalt: encodeBase64(new Uint8Array(16).fill(1)),
        kdfIterations: 100_000,
        wrappedMasterKey: encodeBase64(new Uint8Array(48).fill(2)),
        masterKeyIv: encodeBase64(new Uint8Array(12).fill(3)),
      }).success,
    ).toBe(false);

    const longBody = "a".repeat(300);
    expect(isSuspiciousMemoOverwrite("Old title", longBody, "New title", "")).toBe(true);
    expect(
      isSuspiciousMemoOverwrite("Old title", longBody, "New title", "", {
        currentContentMarkdown: longBody,
        nextContentMarkdown: validEnvelopeMarkdown,
      }),
    ).toBe(false);
    expect(
      isSuspiciousMemoOverwrite("Old title", "", "New title", "Short", {
        currentContentMarkdown: validEnvelopeMarkdown,
        nextContentMarkdown: "Short",
        e2eeTransition: "decrypt",
      }),
    ).toBe(false);
    expect(
      isSuspiciousMemoOverwrite("Old title", longBody, "New title", "", {
        currentContentMarkdown: longBody,
        nextContentMarkdown: "```edgeever-encrypted-note\n{bad}\n```",
      }),
    ).toBe(true);
  });

  test("concurrent zeroization of caller-owned DEK or WMK during async randomBytes never produces undecryptable ciphertext", async () => {
    const delayedProvider = {
      randomBytes: (len) =>
        new Promise((resolve) => {
          setTimeout(() => resolve(webCryptoE2eeProvider.randomBytes(len)), 15);
        }),
      pbkdf2Sha256: (...args) => webCryptoE2eeProvider.pbkdf2Sha256(...args),
      aesGcmEncrypt: (...args) => webCryptoE2eeProvider.aesGcmEncrypt(...args),
      aesGcmDecrypt: (...args) => webCryptoE2eeProvider.aesGcmDecrypt(...args),
    };

    const { masterKey, keyring } = await initializeWorkspaceKeyring({ passphrase: "race-test-passphrase" });
    const masterKeyBackup = masterKey.slice();

    const first = await encryptNoteContent(
      {
        memoId: "memo_race_1",
        keyId: keyring.keyId,
        masterKey,
        plaintextMarkdown: "Version 1",
      },
      delayedProvider,
    );

    // Start a second encryption using cached noteKey, then immediately zeroize both noteKey.dek and masterKey while randomBytes is pending.
    const pendingSecond = encryptNoteContent(
      {
        memoId: "memo_race_1",
        keyId: keyring.keyId,
        masterKey,
        plaintextMarkdown: "Version 2 written right before lock/evict",
        noteKey: first.noteKey,
      },
      delayedProvider,
    );
    zeroizeBytes(first.noteKey.dek);
    zeroizeBytes(masterKey);

    const second = await pendingSecond;
    const decryptedSecond = await decryptNoteContent({
      memoId: "memo_race_1",
      masterKey: masterKeyBackup,
      envelopeOrMarkdown: second.markdown,
    });
    expect(decryptedSecond.plaintextMarkdown).toBe("Version 2 written right before lock/evict");

    // Also verify decryptNoteContent and unwrapNoteDek survive caller zeroizing masterKey immediately after invocation.
    const masterKeyForDecrypt = masterKeyBackup.slice();
    const delayedDecryptProvider = {
      ...webCryptoE2eeProvider,
      aesGcmDecrypt: async (...args) => {
        await new Promise((resolve) => setTimeout(resolve, 15));
        return webCryptoE2eeProvider.aesGcmDecrypt(...args);
      },
    };
    const pendingDecrypt = decryptNoteContent(
      {
        memoId: "memo_race_1",
        masterKey: masterKeyForDecrypt,
        envelopeOrMarkdown: second.markdown,
      },
      delayedDecryptProvider,
    );
    zeroizeBytes(masterKeyForDecrypt);
    const decryptedWithRace = await pendingDecrypt;
    expect(decryptedWithRace.plaintextMarkdown).toBe("Version 2 written right before lock/evict");
  });

  test("ZIP archive supports optional e2ee-keyring.json and validates encrypted memo keyId relationships", async () => {
    const now = "2026-11-26T00:00:00.000Z";
    const { masterKey, keyring } = await initializeWorkspaceKeyring({ passphrase: "zip-test-passphrase" });
    const storedKeyring = { ...keyring, revision: 1, createdAt: now, updatedAt: now };
    const encrypted = await encryptNoteContent({
      memoId: "memo_zip_1",
      keyId: storedKeyring.keyId,
      masterKey,
      plaintextMarkdown: "Zip secret note",
    });

    const notebook = {
      id: "nb_1",
      parentId: null,
      name: "Vault",
      slug: "vault",
      icon: null,
      color: null,
      sortOrder: 0,
      memoCount: 1,
      lastMemoUpdatedAt: now,
      createdAt: now,
      updatedAt: now,
    };
    const memo = {
      id: "memo_zip_1",
      notebookId: "nb_1",
      title: "Secret",
      excerpt: "",
      encrypted: true,
      tags: ["vault"],
      isPinned: false,
      isArchived: false,
      isDeleted: false,
      revision: 0,
      createdAt: now,
      updatedAt: now,
      deletedAt: null,
      contentJson: { type: "doc", content: [{ type: "paragraph" }] },
      contentMarkdown: encrypted.markdown,
      contentText: "",
      contentHash: "h".repeat(64),
      sourceMemoIds: [],
      mergeSourceCount: 0,
      mergedIntoMemoId: null,
    };

    const zipWithKeyring = await createEdgeEverZip(
      {
        listNotebooks: async () => ({ notebooks: [notebook] }),
        listPrompts: async () => ({ prompts: [] }),
        getE2eeKeyring: async () => ({ e2eeKeyring: storedKeyring }),
        getPage: async () => ({ memos: [memo], resources: [], revisions: [], totalCount: 1, nextOffset: null }),
      },
      { edgeeverVersion: "2.0.0", buildId: "test" },
    );

    const parsed = await parseEdgeEverZip(zipWithKeyring);
    expect(parsed.e2eeKeyring).toEqual(storedKeyring);
    expect(() => validateBackupRelationships(parsed)).not.toThrow();

    // Mismatched keyId between encrypted note and backup keyring fails validation.
    const badKeyringBackup = {
      ...parsed,
      e2eeKeyring: { ...storedKeyring, keyId: "ek_other_key_id_9999" },
    };
    expect(() => validateBackupRelationships(badKeyringBackup)).toThrow(EdgeEverZipImportError);

    // Legacy ZIP without e2ee-keyring.json parses cleanly with e2eeKeyring = null.
    const legacyZip = await createEdgeEverZip(
      {
        listNotebooks: async () => ({ notebooks: [notebook] }),
        listPrompts: async () => ({ prompts: [] }),
        getPage: async () => ({
          memos: [{ ...memo, encrypted: undefined, contentMarkdown: "Plain note", contentText: "Plain note", excerpt: "Plain note" }],
          resources: [],
          revisions: [],
          totalCount: 1,
          nextOffset: null,
        }),
      },
      { edgeeverVersion: "2.0.0", buildId: "test" },
    );
    const parsedLegacy = await parseEdgeEverZip(legacyZip);
    expect(parsedLegacy.e2eeKeyring).toBeNull();
    expect(() => validateBackupRelationships(parsedLegacy)).not.toThrow();
  });
});
