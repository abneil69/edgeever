import { z } from "zod";

export const ENCRYPTED_NOTE_FENCE_LANGUAGE = "edgeever-encrypted-note" as const;
export const ENCRYPTED_NOTE_FENCE_PREFIX = "```edgeever-encrypted-note" as const;
export const ENCRYPTED_NOTE_ENVELOPE_VERSION = 1 as const;
export const ENCRYPTED_NOTE_AEAD_ALGORITHM = "A256GCM" as const;

export const WORKSPACE_E2EE_KDF_ALGORITHM = "PBKDF2-SHA256" as const;
export const WORKSPACE_E2EE_KDF_ITERATIONS = 600_000;
export const WORKSPACE_E2EE_KDF_MIN_ITERATIONS = 600_000;
export const WORKSPACE_E2EE_KDF_MAX_ITERATIONS = 5_000_000;
export const WORKSPACE_E2EE_KDF_SALT_BYTES = 16;
export const WORKSPACE_E2EE_KEY_BYTES = 32;
export const WORKSPACE_E2EE_IV_BYTES = 12;
export const WORKSPACE_E2EE_GCM_TAG_BYTES = 16;
export const WORKSPACE_E2EE_WRAPPED_KEY_BYTES =
  WORKSPACE_E2EE_KEY_BYTES + WORKSPACE_E2EE_GCM_TAG_BYTES;
export const WORKSPACE_E2EE_MAX_CIPHERTEXT_BYTES = 16 * 1024 * 1024;
export const WORKSPACE_E2EE_KEY_ID_PATTERN = /^ek_[A-Za-z0-9_-]{8,80}$/;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

export type E2eeCryptoErrorCode =
  | "crypto_unavailable"
  | "invalid_passphrase"
  | "invalid_keyring"
  | "invalid_envelope"
  | "invalid_key"
  | "key_mismatch"
  | "decryption_failed";

export class E2eeCryptoError extends Error {
  readonly code: E2eeCryptoErrorCode;

  constructor(
    code: E2eeCryptoErrorCode,
    message: string,
  ) {
    super(message);
    this.code = code;
    this.name = "E2eeCryptoError";
  }
}

export interface E2eeCryptoProvider {
  randomBytes(length: number): Promise<Uint8Array> | Uint8Array;
  pbkdf2Sha256(
    passphrase: string,
    salt: Uint8Array,
    iterations: number,
    keyLengthBytes: number,
  ): Promise<Uint8Array>;
  aesGcmEncrypt(
    key: Uint8Array,
    iv: Uint8Array,
    plaintext: Uint8Array,
    aad?: Uint8Array,
  ): Promise<Uint8Array>;
  aesGcmDecrypt(
    key: Uint8Array,
    iv: Uint8Array,
    ciphertext: Uint8Array,
    aad?: Uint8Array,
  ): Promise<Uint8Array>;
}

const STRICT_BASE64_PATTERN = /^[A-Za-z0-9+/]+={0,2}$/;

export const encodeBase64 = (bytes: Uint8Array): string => {
  const chunkSize = 0x8000;
  let binary = "";
  for (let offset = 0; offset < bytes.byteLength; offset += chunkSize) {
    const chunk = bytes.subarray(offset, offset + chunkSize);
    binary += String.fromCharCode(...chunk);
  }
  return btoa(binary);
};

export const decodeBase64Strict = (value: string): Uint8Array | null => {
  if (
    typeof value !== "string"
    || value.length === 0
    || value.length % 4 !== 0
    || !STRICT_BASE64_PATTERN.test(value)
  ) {
    return null;
  }
  try {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    // Reject non-canonical trailing padding bits so envelopes are uniquely encoded.
    if (encodeBase64(bytes) !== value) {
      return null;
    }
    return bytes;
  } catch {
    return null;
  }
};

const decodeBase64ExactBytes = (value: string, expectedBytes: number): Uint8Array | null => {
  const bytes = decodeBase64Strict(value);
  return bytes && bytes.byteLength === expectedBytes ? bytes : null;
};

export const EncryptedNoteEnvelopeSchema = z
  .object({
    v: z.literal(ENCRYPTED_NOTE_ENVELOPE_VERSION),
    alg: z.literal(ENCRYPTED_NOTE_AEAD_ALGORITHM),
    keyId: z.string().regex(WORKSPACE_E2EE_KEY_ID_PATTERN),
    wrappedDek: z
      .string()
      .refine((value) => decodeBase64ExactBytes(value, WORKSPACE_E2EE_WRAPPED_KEY_BYTES) !== null, {
        message: "wrappedDek must be valid base64 representing 48 bytes.",
      }),
    dekIv: z
      .string()
      .refine((value) => decodeBase64ExactBytes(value, WORKSPACE_E2EE_IV_BYTES) !== null, {
        message: "dekIv must be valid base64 representing 12 bytes.",
      }),
    iv: z
      .string()
      .refine((value) => decodeBase64ExactBytes(value, WORKSPACE_E2EE_IV_BYTES) !== null, {
        message: "iv must be valid base64 representing 12 bytes.",
      }),
    ciphertext: z.string().refine((value) => {
      const decoded = decodeBase64Strict(value);
      return (
        decoded !== null
        && decoded.byteLength >= WORKSPACE_E2EE_GCM_TAG_BYTES
        && decoded.byteLength <= WORKSPACE_E2EE_MAX_CIPHERTEXT_BYTES
      );
    }, {
      message: "ciphertext must be valid base64 representing at least 16 bytes.",
    }),
  })
  .strict();

export type EncryptedNoteEnvelope = z.infer<typeof EncryptedNoteEnvelopeSchema>;

export type WorkspaceE2eeKeyringParams = {
  keyId: string;
  kdfAlgorithm: typeof WORKSPACE_E2EE_KDF_ALGORITHM;
  kdfSalt: string;
  kdfIterations: number;
  wrappedMasterKey: string;
  masterKeyIv: string;
};

export type WorkspaceE2eeKeyring = WorkspaceE2eeKeyringParams & {
  revision: number;
  createdAt: string;
  updatedAt: string;
};

export type WorkspaceE2eeKeyringResponse =
  | { configured: false; keyring: null }
  | { configured: true; keyring: WorkspaceE2eeKeyring };

export type WorkspaceE2eeKeyringUpsertPayload = WorkspaceE2eeKeyringParams & {
  expectedRevision?: number;
};

const ENCRYPTED_NOTE_FENCE_PREFIX_PATTERN = /^(?:`{3,}|~{3,})[ \t]*edgeever-encrypted-note(?=$|[\s`~:-])/i;
const STRICT_ENCRYPTED_NOTE_BLOCK_PATTERN = /^```edgeever-encrypted-note\n([^\n`]+)\n```$/;
const ENCRYPTED_NOTE_OPEN_FENCE = `\`\`\`${ENCRYPTED_NOTE_FENCE_LANGUAGE}`;
const ENCRYPTED_NOTE_CLOSE_FENCE = "```";

export const hasEncryptedNoteFencePrefix = (markdown: string | null | undefined): boolean =>
  Boolean(markdown && ENCRYPTED_NOTE_FENCE_PREFIX_PATTERN.test(markdown.trimStart()));

/**
 * Cheap O(1) read-side structural check for stored/synced encrypted notes.
 * Verifies only that the trimmed document begins with the exact opening fence
 * followed by a newline, ends with a newline followed by the closing fence,
 * and has non-empty content between them—never matching fences mid-body and
 * never parsing/copying multi-megabyte ciphertexts on hot read paths.
 * Write boundaries must use `parseEncryptedNoteEnvelope` / `isValidEncryptedNoteEnvelope`.
 */
export const hasEncryptedNoteMarker = (markdown: string | null | undefined): boolean => {
  if (!markdown) return false;
  const trimmed = markdown.trim();
  if (!trimmed.startsWith(ENCRYPTED_NOTE_OPEN_FENCE) || !trimmed.endsWith(ENCRYPTED_NOTE_CLOSE_FENCE)) {
    return false;
  }
  const openLen = ENCRYPTED_NOTE_OPEN_FENCE.length;
  let bodyStart = openLen;
  const firstBreak = trimmed.charCodeAt(bodyStart);
  if (firstBreak === 13 /* \r */) {
    bodyStart += 1;
    if (trimmed.charCodeAt(bodyStart) === 10 /* \n */) {
      bodyStart += 1;
    }
  } else if (firstBreak === 10 /* \n */) {
    bodyStart += 1;
  } else {
    return false;
  }
  let bodyEnd = trimmed.length - ENCRYPTED_NOTE_CLOSE_FENCE.length;
  if (bodyEnd <= bodyStart) return false;
  const lastBreak = trimmed.charCodeAt(bodyEnd - 1);
  if (lastBreak === 10 /* \n */) {
    bodyEnd -= 1;
    if (bodyEnd > bodyStart && trimmed.charCodeAt(bodyEnd - 1) === 13 /* \r */) {
      bodyEnd -= 1;
    }
  } else if (lastBreak === 13 /* \r */) {
    bodyEnd -= 1;
  } else {
    return false;
  }
  return bodyEnd > bodyStart;
};

export const parseEncryptedNoteEnvelope = (
  markdown: string | null | undefined,
): EncryptedNoteEnvelope | null => {
  if (!hasEncryptedNoteMarker(markdown) || !markdown) return null;
  const normalized = markdown.replace(/\r\n?/g, "\n").trim();
  const match = STRICT_ENCRYPTED_NOTE_BLOCK_PATTERN.exec(normalized);
  if (!match) return null;
  try {
    const parsed = JSON.parse(match[1]) as unknown;
    const validated = EncryptedNoteEnvelopeSchema.safeParse(parsed);
    return validated.success ? validated.data : null;
  } catch {
    return null;
  }
};

export const isValidEncryptedNoteEnvelope = (markdown: string | null | undefined): boolean =>
  parseEncryptedNoteEnvelope(markdown) !== null;

export const serializeEncryptedNoteEnvelope = (envelope: EncryptedNoteEnvelope): string => {
  const safe = EncryptedNoteEnvelopeSchema.parse(envelope);
  const canonical: EncryptedNoteEnvelope = {
    v: safe.v,
    alg: safe.alg,
    keyId: safe.keyId,
    wrappedDek: safe.wrappedDek,
    dekIv: safe.dekIv,
    iv: safe.iv,
    ciphertext: safe.ciphertext,
  };
  return `\`\`\`${ENCRYPTED_NOTE_FENCE_LANGUAGE}\n${JSON.stringify(canonical)}\n\`\`\``;
};

export const getEncryptedNoteSummary = (
  markdown: string | null | undefined,
): { encrypted?: true } => (hasEncryptedNoteMarker(markdown) ? { encrypted: true } : {});

const assertNonEmptyId = (value: string, label: string) => {
  const trimmed = value.trim();
  if (!trimmed || trimmed !== value) {
    throw new E2eeCryptoError("invalid_key", `${label} must be a non-empty identifier without surrounding whitespace.`);
  }
};

const assertValidKeyId = (keyId: string) => {
  if (!WORKSPACE_E2EE_KEY_ID_PATTERN.test(keyId)) {
    throw new E2eeCryptoError("invalid_key", "keyId does not match the required ek_ format.");
  }
};

const assertValidSymmetricKey = (key: Uint8Array, label: string) => {
  if (!(key instanceof Uint8Array) || key.byteLength !== WORKSPACE_E2EE_KEY_BYTES) {
    throw new E2eeCryptoError("invalid_key", `${label} must be a 32-byte Uint8Array.`);
  }
};

const assertValidIv = (iv: Uint8Array, label: string) => {
  if (!(iv instanceof Uint8Array) || iv.byteLength !== WORKSPACE_E2EE_IV_BYTES) {
    throw new E2eeCryptoError("invalid_key", `${label} must be a 12-byte Uint8Array.`);
  }
};

const assertValidPassphrase = (passphrase: string) => {
  if (typeof passphrase !== "string" || passphrase.length === 0) {
    throw new E2eeCryptoError("invalid_passphrase", "Passphrase must be a non-empty string.");
  }
};

export const zeroizeBytes = (bytes: Uint8Array | null | undefined): void => {
  if (bytes instanceof Uint8Array) {
    bytes.fill(0);
  }
};

export const buildWorkspaceMasterKeyAad = (
  keyId: string,
  kdfAlgorithm: typeof WORKSPACE_E2EE_KDF_ALGORITHM = WORKSPACE_E2EE_KDF_ALGORITHM,
  kdfIterations: number = WORKSPACE_E2EE_KDF_ITERATIONS,
): Uint8Array => {
  assertValidKeyId(keyId);
  if (kdfAlgorithm !== WORKSPACE_E2EE_KDF_ALGORITHM) {
    throw new E2eeCryptoError("invalid_keyring", "Unsupported KDF algorithm.");
  }
  validateIterations(kdfIterations);
  return textEncoder.encode(`edgeever:e2ee:wmk:v1:${keyId}:${kdfAlgorithm}:${kdfIterations}`);
};

export const buildNoteDekAad = (memoId: string, keyId: string): Uint8Array => {
  assertNonEmptyId(memoId, "memoId");
  assertValidKeyId(keyId);
  return textEncoder.encode(`edgeever:e2ee:dek:v1:${memoId}:${keyId}`);
};

export const buildNoteBodyAad = (memoId: string, keyId: string): Uint8Array => {
  assertNonEmptyId(memoId, "memoId");
  assertValidKeyId(keyId);
  return textEncoder.encode(`edgeever:e2ee:body:v1:${memoId}:${keyId}`);
};

const toArrayBuffer = (bytes: Uint8Array): ArrayBuffer =>
  bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;

export const createWebCryptoE2eeProvider = (cryptoApi?: Crypto): E2eeCryptoProvider => {
  const resolveCrypto = (): Crypto => {
    const target = cryptoApi ?? globalThis.crypto;
    if (!target || typeof target.getRandomValues !== "function" || !target.subtle) {
      throw new E2eeCryptoError("crypto_unavailable", "WebCrypto API (crypto.subtle) is unavailable in this runtime.");
    }
    return target;
  };

  return {
    randomBytes(length: number): Uint8Array {
      if (!Number.isInteger(length) || length < 1) {
        throw new E2eeCryptoError("invalid_key", "randomBytes length must be a positive integer.");
      }
      const bytes = new Uint8Array(length);
      resolveCrypto().getRandomValues(bytes);
      return bytes;
    },

    async pbkdf2Sha256(
      passphrase: string,
      salt: Uint8Array,
      iterations: number,
      keyLengthBytes: number,
    ): Promise<Uint8Array> {
      const subtle = resolveCrypto().subtle;
      const baseKey = await subtle.importKey(
        "raw",
        toArrayBuffer(textEncoder.encode(passphrase)),
        "PBKDF2",
        false,
        ["deriveBits"],
      );
      const bits = await subtle.deriveBits(
        {
          name: "PBKDF2",
          hash: "SHA-256",
          salt: toArrayBuffer(salt),
          iterations,
        },
        baseKey,
        keyLengthBytes * 8,
      );
      return new Uint8Array(bits);
    },

    async aesGcmEncrypt(
      key: Uint8Array,
      iv: Uint8Array,
      plaintext: Uint8Array,
      aad?: Uint8Array,
    ): Promise<Uint8Array> {
      assertValidSymmetricKey(key, "AES-256-GCM key");
      assertValidIv(iv, "AES-256-GCM iv");
      const subtle = resolveCrypto().subtle;
      const cryptoKey = await subtle.importKey(
        "raw",
        toArrayBuffer(key),
        { name: "AES-GCM" },
        false,
        ["encrypt"],
      );
      const encrypted = await subtle.encrypt(
        {
          name: "AES-GCM",
          iv: toArrayBuffer(iv),
          ...(aad ? { additionalData: toArrayBuffer(aad) } : {}),
          tagLength: WORKSPACE_E2EE_GCM_TAG_BYTES * 8,
        },
        cryptoKey,
        toArrayBuffer(plaintext),
      );
      return new Uint8Array(encrypted);
    },

    async aesGcmDecrypt(
      key: Uint8Array,
      iv: Uint8Array,
      ciphertext: Uint8Array,
      aad?: Uint8Array,
    ): Promise<Uint8Array> {
      assertValidSymmetricKey(key, "AES-256-GCM key");
      assertValidIv(iv, "AES-256-GCM iv");
      if (ciphertext.byteLength < WORKSPACE_E2EE_GCM_TAG_BYTES) {
        throw new E2eeCryptoError("decryption_failed", "Ciphertext is shorter than the AES-GCM authentication tag.");
      }
      const subtle = resolveCrypto().subtle;
      const cryptoKey = await subtle.importKey(
        "raw",
        toArrayBuffer(key),
        { name: "AES-GCM" },
        false,
        ["decrypt"],
      );
      try {
        const decrypted = await subtle.decrypt(
          {
            name: "AES-GCM",
            iv: toArrayBuffer(iv),
            ...(aad ? { additionalData: toArrayBuffer(aad) } : {}),
            tagLength: WORKSPACE_E2EE_GCM_TAG_BYTES * 8,
          },
          cryptoKey,
          toArrayBuffer(ciphertext),
        );
        return new Uint8Array(decrypted);
      } catch {
        throw new E2eeCryptoError("decryption_failed", "AES-256-GCM authentication or decryption failed.");
      }
    },
  };
};

export const webCryptoE2eeProvider: E2eeCryptoProvider = createWebCryptoE2eeProvider();

export const generateE2eeKeyId = async (
  provider: E2eeCryptoProvider = webCryptoE2eeProvider,
): Promise<string> => {
  const bytes = await provider.randomBytes(16);
  const encoded = encodeBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  return `ek_${encoded}`;
};

const validateIterations = (iterations: number) => {
  if (
    !Number.isInteger(iterations)
    || iterations < WORKSPACE_E2EE_KDF_MIN_ITERATIONS
    || iterations > WORKSPACE_E2EE_KDF_MAX_ITERATIONS
  ) {
    throw new E2eeCryptoError(
      "invalid_keyring",
      `PBKDF2 iterations must be an integer between ${WORKSPACE_E2EE_KDF_MIN_ITERATIONS} and ${WORKSPACE_E2EE_KDF_MAX_ITERATIONS}.`,
    );
  }
};

export const initializeWorkspaceKeyring = async (
  input: {
    passphrase: string;
    iterations?: number;
    keyId?: string;
  },
  provider: E2eeCryptoProvider = webCryptoE2eeProvider,
): Promise<{
  masterKey: Uint8Array;
  keyring: WorkspaceE2eeKeyringUpsertPayload;
}> => {
  assertValidPassphrase(input.passphrase);
  const iterations = input.iterations ?? WORKSPACE_E2EE_KDF_ITERATIONS;
  validateIterations(iterations);

  const keyId = input.keyId ?? (await generateE2eeKeyId(provider));
  assertValidKeyId(keyId);

  const masterKey = await provider.randomBytes(WORKSPACE_E2EE_KEY_BYTES);
  assertValidSymmetricKey(masterKey, "masterKey");
  let kek: Uint8Array | null = null;
  try {
    const salt = await provider.randomBytes(WORKSPACE_E2EE_KDF_SALT_BYTES);
    const masterKeyIv = await provider.randomBytes(WORKSPACE_E2EE_IV_BYTES);

    kek = await provider.pbkdf2Sha256(
      input.passphrase,
      salt,
      iterations,
      WORKSPACE_E2EE_KEY_BYTES,
    );
    const aad = buildWorkspaceMasterKeyAad(keyId, WORKSPACE_E2EE_KDF_ALGORITHM, iterations);
    const wrappedMasterKey = await provider.aesGcmEncrypt(kek, masterKeyIv, masterKey, aad);

    return {
      masterKey,
      keyring: {
        keyId,
        kdfAlgorithm: WORKSPACE_E2EE_KDF_ALGORITHM,
        kdfSalt: encodeBase64(salt),
        kdfIterations: iterations,
        wrappedMasterKey: encodeBase64(wrappedMasterKey),
        masterKeyIv: encodeBase64(masterKeyIv),
      },
    };
  } catch (error) {
    zeroizeBytes(masterKey);
    throw error;
  } finally {
    zeroizeBytes(kek);
  }
};

export const unlockWorkspaceMasterKey = async (
  input: {
    passphrase: string;
    keyring: WorkspaceE2eeKeyringParams;
  },
  provider: E2eeCryptoProvider = webCryptoE2eeProvider,
): Promise<Uint8Array> => {
  assertValidPassphrase(input.passphrase);
  assertValidKeyId(input.keyring.keyId);

  if (input.keyring.kdfAlgorithm !== WORKSPACE_E2EE_KDF_ALGORITHM) {
    throw new E2eeCryptoError("invalid_keyring", "Unsupported KDF algorithm.");
  }
  validateIterations(input.keyring.kdfIterations);

  const salt = decodeBase64ExactBytes(input.keyring.kdfSalt, WORKSPACE_E2EE_KDF_SALT_BYTES);
  const masterKeyIv = decodeBase64ExactBytes(input.keyring.masterKeyIv, WORKSPACE_E2EE_IV_BYTES);
  const wrappedMasterKey = decodeBase64ExactBytes(
    input.keyring.wrappedMasterKey,
    WORKSPACE_E2EE_WRAPPED_KEY_BYTES,
  );
  if (!salt || !masterKeyIv || !wrappedMasterKey) {
    throw new E2eeCryptoError("invalid_keyring", "Workspace keyring contains invalid base64 parameters.");
  }

  let kek: Uint8Array | null = null;
  try {
    kek = await provider.pbkdf2Sha256(
      input.passphrase,
      salt,
      input.keyring.kdfIterations,
      WORKSPACE_E2EE_KEY_BYTES,
    );
    const aad = buildWorkspaceMasterKeyAad(
      input.keyring.keyId,
      input.keyring.kdfAlgorithm,
      input.keyring.kdfIterations,
    );

    let masterKey: Uint8Array;
    try {
      masterKey = await provider.aesGcmDecrypt(kek, masterKeyIv, wrappedMasterKey, aad);
    } catch {
      throw new E2eeCryptoError("invalid_passphrase", "Incorrect encryption passphrase or tampered workspace keyring.");
    }
    if (masterKey.byteLength !== WORKSPACE_E2EE_KEY_BYTES) {
      zeroizeBytes(masterKey);
      throw new E2eeCryptoError("invalid_keyring", "Unwrapped workspace master key has an unexpected length.");
    }
    return masterKey;
  } finally {
    zeroizeBytes(kek);
  }
};

export const rotateWorkspacePassphrase = async (
  input: {
    currentPassphrase: string;
    newPassphrase: string;
    currentKeyring: WorkspaceE2eeKeyring;
    iterations?: number;
  },
  provider: E2eeCryptoProvider = webCryptoE2eeProvider,
): Promise<{
  masterKey: Uint8Array;
  keyring: WorkspaceE2eeKeyringUpsertPayload & { expectedRevision: number };
}> => {
  assertValidPassphrase(input.newPassphrase);
  if (!Number.isInteger(input.currentKeyring.revision) || input.currentKeyring.revision < 1) {
    throw new E2eeCryptoError("invalid_keyring", "Current keyring revision must be a positive integer.");
  }
  const iterations = input.iterations ?? input.currentKeyring.kdfIterations;
  validateIterations(iterations);

  // Verify current passphrase and recover the exact existing WMK.
  // Keeping the same WMK and keyId allows all existing encrypted notes to remain
  // readable without re-wrapping any note DEKs.
  const masterKey = await unlockWorkspaceMasterKey(
    {
      passphrase: input.currentPassphrase,
      keyring: input.currentKeyring,
    },
    provider,
  );

  let nextKek: Uint8Array | null = null;
  try {
    const nextSalt = await provider.randomBytes(WORKSPACE_E2EE_KDF_SALT_BYTES);
    const nextMasterKeyIv = await provider.randomBytes(WORKSPACE_E2EE_IV_BYTES);
    nextKek = await provider.pbkdf2Sha256(
      input.newPassphrase,
      nextSalt,
      iterations,
      WORKSPACE_E2EE_KEY_BYTES,
    );
    const aad = buildWorkspaceMasterKeyAad(
      input.currentKeyring.keyId,
      WORKSPACE_E2EE_KDF_ALGORITHM,
      iterations,
    );
    const nextWrappedMasterKey = await provider.aesGcmEncrypt(
      nextKek,
      nextMasterKeyIv,
      masterKey,
      aad,
    );

    return {
      masterKey,
      keyring: {
        expectedRevision: input.currentKeyring.revision,
        keyId: input.currentKeyring.keyId,
        kdfAlgorithm: WORKSPACE_E2EE_KDF_ALGORITHM,
        kdfSalt: encodeBase64(nextSalt),
        kdfIterations: iterations,
        wrappedMasterKey: encodeBase64(nextWrappedMasterKey),
        masterKeyIv: encodeBase64(nextMasterKeyIv),
      },
    };
  } catch (error) {
    zeroizeBytes(masterKey);
    throw error;
  } finally {
    zeroizeBytes(nextKek);
  }
};

export type NoteDekBinding = {
  keyId: string;
  dek: Uint8Array;
  wrappedDek: string;
  dekIv: string;
};

export const unwrapNoteDek = async (
  input: {
    memoId: string;
    masterKey: Uint8Array;
    envelope: EncryptedNoteEnvelope;
    expectedKeyId?: string;
  },
  provider: E2eeCryptoProvider = webCryptoE2eeProvider,
): Promise<Uint8Array> => {
  assertNonEmptyId(input.memoId, "memoId");
  assertValidSymmetricKey(input.masterKey, "masterKey");
  const safeEnvelope = EncryptedNoteEnvelopeSchema.safeParse(input.envelope);
  if (!safeEnvelope.success) {
    throw new E2eeCryptoError("invalid_envelope", "Encrypted note envelope is invalid.");
  }
  const envelope = safeEnvelope.data;
  if (input.expectedKeyId && envelope.keyId !== input.expectedKeyId) {
    throw new E2eeCryptoError("key_mismatch", "Encrypted note keyId does not match the active workspace key.");
  }

  const wrappedDek = decodeBase64ExactBytes(envelope.wrappedDek, WORKSPACE_E2EE_WRAPPED_KEY_BYTES);
  const dekIv = decodeBase64ExactBytes(envelope.dekIv, WORKSPACE_E2EE_IV_BYTES);
  if (!wrappedDek || !dekIv) {
    throw new E2eeCryptoError("invalid_envelope", "Encrypted note envelope has invalid DEK fields.");
  }

  // Copy caller-owned key bytes before the first await so concurrent zeroization
  // (e.g. session lock or logout) cannot corrupt in-flight crypto operations.
  const masterKeyCopy = input.masterKey.slice();
  try {
    const dekAad = buildNoteDekAad(input.memoId, envelope.keyId);
    const dek = await provider.aesGcmDecrypt(masterKeyCopy, dekIv, wrappedDek, dekAad);
    if (dek.byteLength !== WORKSPACE_E2EE_KEY_BYTES) {
      zeroizeBytes(dek);
      throw new E2eeCryptoError("decryption_failed", "Unwrapped note DEK has an unexpected length.");
    }
    return dek;
  } finally {
    zeroizeBytes(masterKeyCopy);
  }
};

export const encryptNoteContent = async (
  input: {
    memoId: string;
    keyId: string;
    masterKey: Uint8Array;
    plaintextMarkdown: string;
    existingEnvelope?: EncryptedNoteEnvelope | null;
    noteKey?: NoteDekBinding | null;
  },
  provider: E2eeCryptoProvider = webCryptoE2eeProvider,
): Promise<{
  envelope: EncryptedNoteEnvelope;
  markdown: string;
  dek: Uint8Array;
  noteKey: NoteDekBinding;
}> => {
  assertNonEmptyId(input.memoId, "memoId");
  assertValidKeyId(input.keyId);
  assertValidSymmetricKey(input.masterKey, "masterKey");

  // Copy caller-owned keys synchronously before any await so concurrent
  // zeroization cannot cause encryption with an all-zero key.
  const masterKeyCopy = input.masterKey.slice();
  let workingDek: Uint8Array | null = null;
  let wrappedDekBase64 = "";
  let dekIvBase64 = "";
  let plaintextBytes: Uint8Array | null = null;

  try {
    if (input.noteKey && input.noteKey.keyId === input.keyId) {
      assertValidSymmetricKey(input.noteKey.dek, "note DEK");
      if (
        !decodeBase64ExactBytes(input.noteKey.wrappedDek, WORKSPACE_E2EE_WRAPPED_KEY_BYTES)
        || !decodeBase64ExactBytes(input.noteKey.dekIv, WORKSPACE_E2EE_IV_BYTES)
      ) {
        throw new E2eeCryptoError("invalid_envelope", "Cached note DEK binding has invalid fields.");
      }
      workingDek = input.noteKey.dek.slice();
      wrappedDekBase64 = input.noteKey.wrappedDek;
      dekIvBase64 = input.noteKey.dekIv;
    } else if (input.existingEnvelope && input.existingEnvelope.keyId === input.keyId) {
      workingDek = await unwrapNoteDek(
        {
          memoId: input.memoId,
          masterKey: masterKeyCopy,
          envelope: input.existingEnvelope,
          expectedKeyId: input.keyId,
        },
        provider,
      );
      wrappedDekBase64 = input.existingEnvelope.wrappedDek;
      dekIvBase64 = input.existingEnvelope.dekIv;
    } else {
      workingDek = await provider.randomBytes(WORKSPACE_E2EE_KEY_BYTES);
      assertValidSymmetricKey(workingDek, "note DEK");
      const dekIv = await provider.randomBytes(WORKSPACE_E2EE_IV_BYTES);
      const dekAad = buildNoteDekAad(input.memoId, input.keyId);
      const wrappedDek = await provider.aesGcmEncrypt(masterKeyCopy, dekIv, workingDek, dekAad);
      wrappedDekBase64 = encodeBase64(wrappedDek);
      dekIvBase64 = encodeBase64(dekIv);
    }

    // Always generate a fresh 12-byte random IV for every body encryption.
    const bodyIv = await provider.randomBytes(WORKSPACE_E2EE_IV_BYTES);
    const bodyAad = buildNoteBodyAad(input.memoId, input.keyId);
    plaintextBytes = textEncoder.encode(input.plaintextMarkdown);
    const ciphertext = await provider.aesGcmEncrypt(workingDek, bodyIv, plaintextBytes, bodyAad);

    const envelope: EncryptedNoteEnvelope = {
      v: ENCRYPTED_NOTE_ENVELOPE_VERSION,
      alg: ENCRYPTED_NOTE_AEAD_ALGORITHM,
      keyId: input.keyId,
      wrappedDek: wrappedDekBase64,
      dekIv: dekIvBase64,
      iv: encodeBase64(bodyIv),
      ciphertext: encodeBase64(ciphertext),
    };

    const resultDek = workingDek.slice();
    return {
      envelope,
      markdown: serializeEncryptedNoteEnvelope(envelope),
      dek: resultDek,
      noteKey: {
        keyId: input.keyId,
        dek: resultDek,
        wrappedDek: wrappedDekBase64,
        dekIv: dekIvBase64,
      },
    };
  } finally {
    zeroizeBytes(masterKeyCopy);
    zeroizeBytes(workingDek);
    zeroizeBytes(plaintextBytes);
  }
};

export const decryptNoteContent = async (
  input: {
    memoId: string;
    masterKey: Uint8Array;
    envelopeOrMarkdown: string | EncryptedNoteEnvelope;
    expectedKeyId?: string;
  },
  provider: E2eeCryptoProvider = webCryptoE2eeProvider,
): Promise<{
  plaintextMarkdown: string;
  envelope: EncryptedNoteEnvelope;
  dek: Uint8Array;
  noteKey: NoteDekBinding;
}> => {
  assertNonEmptyId(input.memoId, "memoId");
  assertValidSymmetricKey(input.masterKey, "masterKey");
  const envelope =
    typeof input.envelopeOrMarkdown === "string"
      ? parseEncryptedNoteEnvelope(input.envelopeOrMarkdown)
      : (() => {
          const parsed = EncryptedNoteEnvelopeSchema.safeParse(input.envelopeOrMarkdown);
          return parsed.success ? parsed.data : null;
        })();

  if (!envelope) {
    throw new E2eeCryptoError("invalid_envelope", "Encrypted note envelope is invalid.");
  }

  const bodyIv = decodeBase64ExactBytes(envelope.iv, WORKSPACE_E2EE_IV_BYTES);
  const ciphertext = decodeBase64Strict(envelope.ciphertext);
  if (!bodyIv || !ciphertext) {
    throw new E2eeCryptoError("invalid_envelope", "Encrypted note envelope has invalid body fields.");
  }

  const masterKeyCopy = input.masterKey.slice();
  let dek: Uint8Array | null = null;
  let plaintextBytes: Uint8Array | null = null;
  try {
    dek = await unwrapNoteDek(
      {
        memoId: input.memoId,
        masterKey: masterKeyCopy,
        envelope,
        expectedKeyId: input.expectedKeyId,
      },
      provider,
    );

    const bodyAad = buildNoteBodyAad(input.memoId, envelope.keyId);
    plaintextBytes = await provider.aesGcmDecrypt(dek, bodyIv, ciphertext, bodyAad);
    let plaintextMarkdown: string;
    try {
      plaintextMarkdown = textDecoder.decode(plaintextBytes);
    } catch {
      throw new E2eeCryptoError("decryption_failed", "Decrypted note body is not valid UTF-8.");
    }

    const resultDek = dek.slice();
    return {
      plaintextMarkdown,
      envelope,
      dek: resultDek,
      noteKey: {
        keyId: envelope.keyId,
        dek: resultDek,
        wrappedDek: envelope.wrappedDek,
        dekIv: envelope.dekIv,
      },
    };
  } finally {
    zeroizeBytes(masterKeyCopy);
    zeroizeBytes(dek);
    zeroizeBytes(plaintextBytes);
  }
};
