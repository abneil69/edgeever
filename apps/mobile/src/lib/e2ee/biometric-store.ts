import AsyncStorage from "@react-native-async-storage/async-storage";
import * as SecureStore from "expo-secure-store";
import { decodeBase64Strict, WORKSPACE_E2EE_KEY_ID_PATTERN } from "@edgeever/shared";

const BIOMETRIC_KEY_PREFIX = "edgeever.e2ee.bio.";
const BIOMETRIC_META_PREFIX = "edgeever.e2ee.bio.meta.";

export type MobileBiometricStatus = {
  available: boolean;
  enabled: boolean;
  keyId: string | null;
};

type BiometricMetaRecord = {
  keyId: string;
  updatedAt: string;
};

type BiometricSecretRecord = {
  version: 1;
  scope: string;
  keyId: string;
  masterKeyBase64: string;
};

type SecureStoreLike = Pick<
  typeof SecureStore,
  "canUseBiometricAuthentication" | "getItemAsync" | "setItemAsync" | "deleteItemAsync"
>;

type AsyncStorageLike = Pick<typeof AsyncStorage, "getItem" | "setItem" | "removeItem">;

const hashScopeKey = (scope: string): string => {
  // Deterministic 64-bit FNV-1a pair producing only [0-9a-f] safe for SecureStore keys.
  let h1 = 0x811c9dc5;
  let h2 = 0x811c9dc5 ^ 0x9e3779b9;
  for (let i = 0; i < scope.length; i += 1) {
    const code = scope.charCodeAt(i);
    h1 ^= code;
    h1 = Math.imul(h1, 0x01000193);
    h2 ^= code + i;
    h2 = Math.imul(h2, 0x01000193);
  }
  return `${(h1 >>> 0).toString(16).padStart(8, "0")}${(h2 >>> 0).toString(16).padStart(8, "0")}`;
};

export class MobileE2eeBiometricStore {
  private readonly secureStore: SecureStoreLike;
  private readonly metaStorage: AsyncStorageLike;

  constructor(options?: { secureStore?: SecureStoreLike; metaStorage?: AsyncStorageLike }) {
    this.secureStore = options?.secureStore ?? SecureStore;
    this.metaStorage = options?.metaStorage ?? AsyncStorage;
  }

  private secretKey(scope: string) {
    return `${BIOMETRIC_KEY_PREFIX}${hashScopeKey(scope)}`;
  }

  private metaKey(scope: string) {
    return `${BIOMETRIC_META_PREFIX}${hashScopeKey(scope)}`;
  }

  private isAvailable(): boolean {
    try {
      return typeof this.secureStore.canUseBiometricAuthentication === "function"
        && this.secureStore.canUseBiometricAuthentication();
    } catch {
      return false;
    }
  }

  private async readMeta(scope: string): Promise<BiometricMetaRecord | null> {
    try {
      const raw = await this.metaStorage.getItem(this.metaKey(scope));
      if (!raw) return null;
      const parsed = JSON.parse(raw) as Partial<BiometricMetaRecord>;
      if (typeof parsed.keyId === "string" && WORKSPACE_E2EE_KEY_ID_PATTERN.test(parsed.keyId)) {
        return { keyId: parsed.keyId, updatedAt: typeof parsed.updatedAt === "string" ? parsed.updatedAt : "" };
      }
      return null;
    } catch {
      return null;
    }
  }

  status = async (scope: string): Promise<MobileBiometricStatus> => {
    const available = this.isAvailable();
    if (!available) {
      return { available: false, enabled: false, keyId: null };
    }
    const meta = await this.readMeta(scope);
    return {
      available: true,
      enabled: Boolean(meta),
      keyId: meta?.keyId ?? null,
    };
  };

  enable = async (
    scope: string,
    keyId: string,
    masterKeyBase64: string,
    authenticationPrompt: string,
  ): Promise<void> => {
    if (!this.isAvailable()) {
      throw new Error("Biometric authentication is unavailable on this device.");
    }
    if (!WORKSPACE_E2EE_KEY_ID_PATTERN.test(keyId)) {
      throw new Error("Invalid workspace keyId.");
    }
    const decoded = decodeBase64Strict(masterKeyBase64);
    if (!decoded || decoded.byteLength !== 32) {
      throw new Error("Invalid workspace master key.");
    }
    decoded.fill(0);

    const record: BiometricSecretRecord = {
      version: 1,
      scope,
      keyId,
      masterKeyBase64,
    };
    await this.secureStore.setItemAsync(this.secretKey(scope), JSON.stringify(record), {
      requireAuthentication: true,
      authenticationPrompt,
    });
    await this.metaStorage.setItem(
      this.metaKey(scope),
      JSON.stringify({ keyId, updatedAt: new Date().toISOString() } satisfies BiometricMetaRecord),
    );
  };

  unlock = async (
    scope: string,
    expectedKeyId: string | null | undefined,
    authenticationPrompt: string,
  ): Promise<{ keyId: string; masterKeyBase64: string }> => {
    if (!this.isAvailable()) {
      throw new Error("Biometric authentication is unavailable on this device.");
    }
    const meta = await this.readMeta(scope);
    if (expectedKeyId && meta && meta.keyId !== expectedKeyId) {
      await this.disable(scope);
      throw new Error("Stored biometric key does not match the current workspace keyring.");
    }
    const raw = await this.secureStore.getItemAsync(this.secretKey(scope), {
      requireAuthentication: true,
      authenticationPrompt,
    });
    if (!raw) {
      await this.metaStorage.removeItem(this.metaKey(scope)).catch(() => undefined);
      throw new Error("No biometric E2EE key stored for this account.");
    }
    let parsed: Partial<BiometricSecretRecord>;
    try {
      parsed = JSON.parse(raw) as Partial<BiometricSecretRecord>;
    } catch {
      await this.disable(scope);
      throw new Error("Stored biometric key is corrupted.");
    }
    if (
      parsed.version !== 1
      || parsed.scope !== scope
      || typeof parsed.keyId !== "string"
      || typeof parsed.masterKeyBase64 !== "string"
      || (expectedKeyId && parsed.keyId !== expectedKeyId)
    ) {
      await this.disable(scope);
      throw new Error("Stored biometric key does not match the current workspace keyring.");
    }
    const decoded = decodeBase64Strict(parsed.masterKeyBase64);
    if (!decoded || decoded.byteLength !== 32) {
      await this.disable(scope);
      throw new Error("Stored biometric key is invalid.");
    }
    decoded.fill(0);
    return { keyId: parsed.keyId, masterKeyBase64: parsed.masterKeyBase64 };
  };

  disable = async (scope: string): Promise<void> => {
    await Promise.all([
      this.secureStore.deleteItemAsync(this.secretKey(scope)).catch(() => undefined),
      this.metaStorage.removeItem(this.metaKey(scope)).catch(() => undefined),
    ]);
  };
}

export const mobileE2eeBiometricStore = new MobileE2eeBiometricStore();
