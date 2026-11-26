import { describe, expect, mock, test } from "bun:test";
import { readFileSync } from "node:fs";
import {
  decodeBase64Strict,
  decryptNoteContent,
  emptyDoc,
  encodeBase64,
  encryptNoteContent,
  initializeWorkspaceKeyring,
  parseEncryptedNoteEnvelope,
  webCryptoE2eeProvider,
} from "@edgeever/shared";

const defaultAsyncStorage = new Map<string, string>();
mock.module("@react-native-async-storage/async-storage", () => ({
  default: {
    getItem: async (key: string) => defaultAsyncStorage.get(key) ?? null,
    setItem: async (key: string, value: string) => { defaultAsyncStorage.set(key, value); },
    removeItem: async (key: string) => { defaultAsyncStorage.delete(key); },
  },
}));
mock.module("expo", () => ({
  requireOptionalNativeModule: () => null,
}));
mock.module("expo-secure-store", () => ({
  canUseBiometricAuthentication: () => false,
  getItemAsync: async () => null,
  setItemAsync: async () => undefined,
  deleteItemAsync: async () => undefined,
}));
mock.module("expo-sqlite", () => ({
  openDatabaseAsync: async () => { throw new Error("not used in unit test"); },
}));

const { createNativeMobileE2eeProvider } = await import("./crypto-provider");
const { MobileE2eeBiometricStore } = await import("./biometric-store");
const { MobileE2eeSessionManager } = await import("./session-store");
const { createOptimisticMemo } = await import("../../screens/workspace-memo-cache");
const { createMobileNoteSearchHighlightPlugin } = await import("../mobile-note-search");
const { writeMobileMemoDraft } = await import("../mobile-drafts");

const createMemoryAsyncStorage = () => {
  const map = new Map<string, string>();
  return {
    map,
    getItem: async (key: string) => map.get(key) ?? null,
    setItem: async (key: string, value: string) => {
      map.set(key, value);
    },
    removeItem: async (key: string) => {
      map.delete(key);
    },
  };
};

describe("Mobile E2EE crypto provider, session manager, biometric store, and security boundaries", () => {
  test("createNativeMobileE2eeProvider round-trips full keyring & note encryption over Base64 bridge", async () => {
    const mockNative = {
      randomBytes: async (length: number) => encodeBase64(await webCryptoE2eeProvider.randomBytes(length)),
      pbkdf2Sha256: async (passphrase: string, saltBase64: string, iterations: number, keyLengthBytes: number) =>
        encodeBase64(
          await webCryptoE2eeProvider.pbkdf2Sha256(
            passphrase,
            decodeBase64Strict(saltBase64)!,
            iterations,
            keyLengthBytes,
          ),
        ),
      aesGcmEncrypt: async (keyB64: string, ivB64: string, plainB64: string, aadB64: string) =>
        encodeBase64(
          await webCryptoE2eeProvider.aesGcmEncrypt(
            decodeBase64Strict(keyB64)!,
            decodeBase64Strict(ivB64)!,
            plainB64 ? decodeBase64Strict(plainB64)! : new Uint8Array(0),
            aadB64 ? decodeBase64Strict(aadB64)! : new Uint8Array(0),
          ),
        ),
      aesGcmDecrypt: async (keyB64: string, ivB64: string, cipherB64: string, aadB64: string) =>
        encodeBase64(
          await webCryptoE2eeProvider.aesGcmDecrypt(
            decodeBase64Strict(keyB64)!,
            decodeBase64Strict(ivB64)!,
            decodeBase64Strict(cipherB64)!,
            aadB64 ? decodeBase64Strict(aadB64)! : new Uint8Array(0),
          ),
        ),
    };

    const nativeProvider = createNativeMobileE2eeProvider(mockNative);
    const initialized = await initializeWorkspaceKeyring({ passphrase: "mobile-bridge-passphrase" }, nativeProvider);
    const sealed = await encryptNoteContent(
      {
        memoId: "memo-android-1",
        keyId: initialized.keyring.keyId,
        masterKey: initialized.masterKey,
        plaintextMarkdown: "Hello from Android native crypto bridge!",
      },
      nativeProvider,
    );
    // Cross-verify decryption with standard WebCrypto provider (proving cross-platform compatibility).
    const decrypted = await decryptNoteContent(
      {
        memoId: "memo-android-1",
        masterKey: initialized.masterKey,
        envelopeOrMarkdown: sealed.markdown,
      },
      webCryptoE2eeProvider,
    );
    expect(decrypted.plaintextMarkdown).toBe("Hello from Android native crypto bridge!");

    // Optional AAD omitted should round-trip cleanly over the native Base64 bridge.
    const rawKey = await nativeProvider.randomBytes(32);
    const rawIv = await nativeProvider.randomBytes(12);
    const rawPlaintext = new TextEncoder().encode("payload without aad");
    const rawCiphertext = await nativeProvider.aesGcmEncrypt(rawKey, rawIv, rawPlaintext);
    const rawDecrypted = await nativeProvider.aesGcmDecrypt(rawKey, rawIv, rawCiphertext);
    expect(new TextDecoder().decode(rawDecrypted)).toBe("payload without aad");
  });

  test("MobileE2eeSessionManager manages memory-only keys, AppState background lock, flush, rotation, and zeroization", async () => {
    const storage = createMemoryAsyncStorage();
    let clock = 2_000_000;
    const manager = new MobileE2eeSessionManager({
      storage,
      now: () => clock,
      provider: webCryptoE2eeProvider,
    });
    await manager.setScope("https://example.com|user-1");

    let storedKeyring: any = null;
    const putKeyring = async (payload: any) => {
      const nowIso = new Date(clock).toISOString();
      storedKeyring = {
        ...payload,
        revision: (storedKeyring?.revision ?? 0) + 1,
        createdAt: storedKeyring?.createdAt ?? nowIso,
        updatedAt: nowIso,
      };
      return { configured: true, keyring: storedKeyring };
    };

    const initKeyring = await manager.initializePassphrase("mobile secret passphrase", putKeyring);
    expect(manager.getSnapshot().unlocked).toBe(true);
    expect(manager.getSnapshot().keyId).toBe(initKeyring.keyId);

    const bioExport = manager.exportMasterKeyBase64ForBiometric();
    const persistedJson = JSON.stringify([...storage.map.entries()]);
    expect(persistedJson).not.toContain(bioExport.masterKeyBase64);
    expect(persistedJson).not.toContain("mobile secret passphrase");

    const sealed1 = await manager.encryptMemo("memo-m1", "Android note v1");
    const sealed2 = await manager.encryptMemo("memo-m1", "Android note v2");
    const env1 = parseEncryptedNoteEnvelope(sealed1.markdown);
    const env2 = parseEncryptedNoteEnvelope(sealed2.markdown);
    expect(env1?.iv).not.toBe(env2?.iv);
    expect(env1?.wrappedDek).toBe(env2?.wrappedDek);

    const dekRef = sealed2.noteKey.dek;
    expect(dekRef.some((b) => b !== 0)).toBe(true);

    // AppState background timeout triggers before-lock flush and zeroizes keys.
    await manager.setAutoLockMinutes(5);
    const flushed: string[] = [];
    const unregister = manager.registerBeforeLockFlush((reason) => {
      flushed.push(reason);
    });
    await manager.handleAppStateChange("background");
    clock += 6 * 60 * 1_000;
    const locked = await manager.handleAppStateChange("active");
    unregister();

    expect(locked).toBe(true);
    expect(flushed).toEqual(["background"]);
    expect(manager.getSnapshot().unlocked).toBe(false);
    expect(manager.getSnapshot().lastLockReason).toBe("background");
    expect(dekRef.every((b) => b === 0)).toBe(true);

    // Rotate passphrase keeps keyId and decrypts old notes.
    const rotated = await manager.rotatePassphrase(
      "mobile secret passphrase",
      "rotated mobile passphrase 2026",
      putKeyring,
    );
    expect(rotated.keyId).toBe(initKeyring.keyId);
    expect(rotated.revision).toBe(2);
    const decrypted = await manager.decryptMemo("memo-m1", sealed2.markdown);
    expect(decrypted.plaintextMarkdown).toBe("Android note v2");

    // Logout skips flush and clears keys.
    const logoutFlush: string[] = [];
    manager.registerBeforeLockFlush((reason) => {
      logoutFlush.push(reason);
    });
    await manager.lock("logout");
    expect(logoutFlush).toEqual([]);
    expect(manager.getSnapshot().unlocked).toBe(false);
  });

  test("MobileE2eeBiometricStore enforces requireAuthentication and purges mismatched keyId", async () => {
    const secureData = new Map<string, string>();
    const secureCalls: Array<{ op: string; key: string; options?: any }> = [];
    const metaStorage = createMemoryAsyncStorage();
    const store = new MobileE2eeBiometricStore({
      metaStorage,
      secureStore: {
        canUseBiometricAuthentication: () => true,
        setItemAsync: async (key, value, options) => {
          secureCalls.push({ op: "set", key, options });
          secureData.set(key, value);
        },
        getItemAsync: async (key, options) => {
          secureCalls.push({ op: "get", key, options });
          return secureData.get(key) ?? null;
        },
        deleteItemAsync: async (key) => {
          secureCalls.push({ op: "delete", key });
          secureData.delete(key);
        },
      },
    });

    const scope = "https://example.com|user-1";
    const keyId = "ek_0123456789abcdef";
    const masterKeyBase64 = encodeBase64(new Uint8Array(32).fill(7));

    expect(await store.status(scope)).toEqual({ available: true, enabled: false, keyId: null });
    expect(secureCalls).toEqual([]);

    await store.enable(scope, keyId, masterKeyBase64, "Authenticate to enable biometric unlock");
    expect(secureCalls.at(-1)?.options).toMatchObject({ requireAuthentication: true });
    expect(await store.status(scope)).toEqual({ available: true, enabled: true, keyId });

    const unlocked = await store.unlock(scope, keyId, "Authenticate to unlock");
    expect(unlocked).toEqual({ keyId, masterKeyBase64 });
    expect(secureCalls.at(-1)?.options).toMatchObject({ requireAuthentication: true });

    // Mismatched expectedKeyId purges stale record and throws.
    await expect(store.unlock(scope, "ek_different_key_id", "Unlock")).rejects.toThrow();
    expect(await store.status(scope)).toEqual({ available: true, enabled: false, keyId: null });
  });

  test("optimistic cache, search highlight plugin, and mobile UI enforce E2EE boundaries", async () => {
    const initialized = await initializeWorkspaceKeyring({ passphrase: "ui-boundary-passphrase" }, webCryptoE2eeProvider);
    const sealed = await encryptNoteContent(
      {
        memoId: "memo-opt-1",
        keyId: initialized.keyring.keyId,
        masterKey: initialized.masterKey,
        plaintextMarkdown: "Top secret mobile body",
      },
      webCryptoE2eeProvider,
    );

    const optimistic = createOptimisticMemo(
      {
        id: "memo-opt-1",
        notebookId: "nb-1",
        title: "Vault",
        excerpt: "old",
        tags: ["sec"],
        isPinned: false,
        isArchived: false,
        isDeleted: false,
        revision: 1,
        createdAt: "2026-01-01T00:00:00.000Z",
        updatedAt: "2026-01-01T00:00:00.000Z",
        deletedAt: null,
        contentJson: emptyDoc(),
        contentMarkdown: "",
        contentText: "old",
        contentHash: "h1",
        sourceMemoIds: [],
        mergeSourceCount: 0,
        mergedIntoMemoId: null,
      },
      { contentMarkdown: sealed.markdown, contentJson: emptyDoc() },
    );
    expect(optimistic.encrypted).toBe(true);
    expect(optimistic.excerpt).toBe("");
    expect(optimistic.contentText).toBe("");
    expect(optimistic.contentJson).toEqual(emptyDoc());

    // writeMobileMemoDraft refuses to persist encrypted note envelopes.
    defaultAsyncStorage.clear();
    await writeMobileMemoDraft({
      memoId: "memo-opt-1",
      expectedRevision: 1,
      title: "Vault",
      contentMarkdown: sealed.markdown,
      notebookId: "nb-1",
      tagsText: "sec",
      updatedAt: "2026-01-01T00:00:00.000Z",
    });
    expect(defaultAsyncStorage.size).toBe(0);

    // Search highlight plugin returns empty decorations when disabled.
    const disabledPlugin = createMobileNoteSearchHighlightPlugin({
      disabled: () => true,
      getActiveIndex: () => 0,
      getQuery: () => "secret",
    });
    const decorations = disabledPlugin.props.decorations?.({
      doc: { descendants: () => { throw new Error("should not scan doc when disabled"); } },
    } as any);
    expect(decorations).toBeDefined();

    // Source checks for mobile mirror, detail, editor, and revision history boundaries.
    const mirrorSrc = readFileSync(new URL("../local-mirror.ts", import.meta.url), "utf8");
    expect(mirrorSrc).toContain("sanitizeMobileMemoForLocalMirror");
    expect(mirrorSrc).toContain("contentText: \"\"");

    const detailSrc = readFileSync(new URL("../../screens/WorkspaceMemoDetail.tsx", import.meta.url), "utf8");
    expect(detailSrc).toContain("MobileEncryptedNoteLockView");
    expect(detailSrc).toContain("encryptedNote={isEncryptedNote}");
    expect(detailSrc).toContain("decryptedState.cipherMarkdown === memo.contentMarkdown");

    const revisionSrc = readFileSync(new URL("../../screens/WorkspaceRevisionHistory.tsx", import.meta.url), "utf8");
    expect(revisionSrc).toContain("useMobileE2eeSession()");
    expect(revisionSrc).toContain("setDecryptedRevisionMarkdown(\"\")");
  });
});
