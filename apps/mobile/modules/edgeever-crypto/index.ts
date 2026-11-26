import { requireOptionalNativeModule } from "expo";

export type EdgeEverCryptoNativeModule = {
  randomBytes: (length: number) => Promise<string>;
  pbkdf2Sha256: (
    passphrase: string,
    saltBase64: string,
    iterations: number,
    keyLengthBytes: number,
  ) => Promise<string>;
  aesGcmEncrypt: (
    keyBase64: string,
    ivBase64: string,
    plaintextBase64: string,
    aadBase64: string,
  ) => Promise<string>;
  aesGcmDecrypt: (
    keyBase64: string,
    ivBase64: string,
    ciphertextBase64: string,
    aadBase64: string,
  ) => Promise<string>;
};

export const getEdgeEverCryptoNativeModule = (): EdgeEverCryptoNativeModule | null => {
  try {
    return requireOptionalNativeModule<EdgeEverCryptoNativeModule>("EdgeEverCrypto");
  } catch {
    return null;
  }
};
