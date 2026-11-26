import {
  decodeBase64Strict,
  E2eeCryptoError,
  encodeBase64,
  webCryptoE2eeProvider,
  type E2eeCryptoProvider,
} from "@edgeever/shared";
import {
  getEdgeEverCryptoNativeModule,
  type EdgeEverCryptoNativeModule,
} from "../../../modules/edgeever-crypto";

const decodeNativeResult = (base64: string, label: string): Uint8Array => {
  if (base64 === "") return new Uint8Array(0);
  const decoded = decodeBase64Strict(base64);
  if (!decoded) {
    throw new E2eeCryptoError("decryption_failed", `Native crypto module returned invalid base64 for ${label}.`);
  }
  return decoded;
};

export const createNativeMobileE2eeProvider = (
  nativeModule: EdgeEverCryptoNativeModule,
): E2eeCryptoProvider => ({
  async randomBytes(length: number): Promise<Uint8Array> {
    const encoded = await nativeModule.randomBytes(length);
    return decodeNativeResult(encoded, "randomBytes");
  },

  async pbkdf2Sha256(
    passphrase: string,
    salt: Uint8Array,
    iterations: number,
    keyLengthBytes: number,
  ): Promise<Uint8Array> {
    const encoded = await nativeModule.pbkdf2Sha256(
      passphrase,
      encodeBase64(salt),
      iterations,
      keyLengthBytes,
    );
    return decodeNativeResult(encoded, "pbkdf2Sha256");
  },

  async aesGcmEncrypt(
    key: Uint8Array,
    iv: Uint8Array,
    plaintext: Uint8Array,
    aad?: Uint8Array,
  ): Promise<Uint8Array> {
    const encoded = await nativeModule.aesGcmEncrypt(
      encodeBase64(key),
      encodeBase64(iv),
      encodeBase64(plaintext),
      aad ? encodeBase64(aad) : "",
    );
    return decodeNativeResult(encoded, "aesGcmEncrypt");
  },

  async aesGcmDecrypt(
    key: Uint8Array,
    iv: Uint8Array,
    ciphertext: Uint8Array,
    aad?: Uint8Array,
  ): Promise<Uint8Array> {
    try {
      const encoded = await nativeModule.aesGcmDecrypt(
        encodeBase64(key),
        encodeBase64(iv),
        encodeBase64(ciphertext),
        aad ? encodeBase64(aad) : "",
      );
      return decodeNativeResult(encoded, "aesGcmDecrypt");
    } catch {
      throw new E2eeCryptoError("decryption_failed", "Failed to decrypt AES-GCM payload.");
    }
  },
});

export const resolveMobileE2eeCryptoProvider = (): E2eeCryptoProvider => {
  const nativeModule = getEdgeEverCryptoNativeModule();
  if (nativeModule) {
    return createNativeMobileE2eeProvider(nativeModule);
  }
  return webCryptoE2eeProvider;
};

export const mobileE2eeCryptoProvider: E2eeCryptoProvider = resolveMobileE2eeCryptoProvider();
