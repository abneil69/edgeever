import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { accountDataDirectory } from "./account-scope.mjs";
import { restrictDirectory, restrictFile } from "./file-permissions.mjs";
import { instanceOrigin } from "./session-credential.mjs";

const KEY_ID_PATTERN = /^ek_[A-Za-z0-9_-]{8,80}$/;
const STRICT_BASE64_PATTERN = /^[A-Za-z0-9+/]+={0,2}$/;
const MASTER_KEY_BYTES = 32;
const BIOMETRIC_RECORD_VERSION = 1;

const createError = (code, message) => Object.assign(new Error(message), { code });

const isValidKeyId = (value) => typeof value === "string" && KEY_ID_PATTERN.test(value);

const isValidMasterKeyBase64 = (value) => {
  if (typeof value !== "string" || value.length === 0 || value.length % 4 !== 0 || !STRICT_BASE64_PATTERN.test(value)) {
    return false;
  }
  const bytes = Buffer.from(value, "base64");
  return bytes.length === MASTER_KEY_BYTES && bytes.toString("base64") === value;
};

export const e2eeBiometricPath = (userDataDirectory, apiBaseUrl, accountId) =>
  join(accountDataDirectory(userDataDirectory, apiBaseUrl, accountId), "e2ee-biometric.enc");

const readStoredRecord = async (filePath) => {
  let raw;
  try {
    raw = await readFile(filePath, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
  try {
    const parsed = JSON.parse(raw);
    if (
      !parsed
      || typeof parsed !== "object"
      || parsed.version !== BIOMETRIC_RECORD_VERSION
      || !isValidKeyId(parsed.keyId)
      || typeof parsed.origin !== "string"
      || typeof parsed.ciphertextBase64 !== "string"
      || !parsed.ciphertextBase64
    ) {
      return { invalid: true };
    }
    return parsed;
  } catch {
    return { invalid: true };
  }
};

export const createE2eeBiometricStore = ({
  platform = process.platform,
  systemPreferences,
  safeStorage,
  getScope,
}) => {
  const isAvailable = () =>
    platform === "darwin"
    && Boolean(systemPreferences?.canPromptTouchID?.())
    && Boolean(safeStorage?.isEncryptionAvailable?.());

  const resolveScope = () => {
    const scope = getScope?.() ?? {};
    const userDataDirectory = typeof scope.userDataDirectory === "string" ? scope.userDataDirectory : "";
    const apiBaseUrl = typeof scope.apiBaseUrl === "string" ? scope.apiBaseUrl : "";
    const accountId = typeof scope.accountId === "string" && scope.accountId.trim() ? scope.accountId.trim() : null;
    const origin = instanceOrigin(apiBaseUrl) ?? "local";
    const filePath = userDataDirectory ? e2eeBiometricPath(userDataDirectory, apiBaseUrl, accountId) : "";
    return { userDataDirectory, apiBaseUrl, accountId, origin, filePath };
  };

  const clearFile = async (filePath) => {
    if (filePath) await rm(filePath, { force: true });
  };

  let inFlightUnlock = null;

  const status = async () => {
    const available = isAvailable();
    const { filePath, origin } = resolveScope();
    if (!available || !filePath) {
      return { available, enabled: false, keyId: null };
    }
    const record = await readStoredRecord(filePath);
    if (!record) return { available: true, enabled: false, keyId: null };
    if (record.invalid || record.origin !== origin) {
      await clearFile(filePath);
      return { available: true, enabled: false, keyId: null };
    }
    return { available: true, enabled: true, keyId: record.keyId };
  };

  const enable = async ({ keyId, masterKeyBase64, reason } = {}) => {
    if (!isAvailable()) {
      throw createError("e2ee_biometric_unavailable", "Touch ID and system encryption are unavailable on this device.");
    }
    if (!isValidKeyId(keyId)) {
      throw createError("e2ee_biometric_invalid_input", "Invalid E2EE key identifier.");
    }
    if (!isValidMasterKeyBase64(masterKeyBase64)) {
      throw createError("e2ee_biometric_invalid_input", "Invalid workspace master key.");
    }
    const { filePath, origin } = resolveScope();
    if (!filePath) {
      throw createError("e2ee_biometric_unavailable", "Account storage scope is unavailable.");
    }
    const promptReason = typeof reason === "string" && reason.trim()
      ? reason.trim().slice(0, 200)
      : "enable Touch ID unlock for EdgeEver encrypted notes";
    try {
      await systemPreferences.promptTouchID(promptReason);
    } catch {
      throw createError("e2ee_biometric_cancelled", "Touch ID verification was cancelled or failed.");
    }
    const secretPayload = JSON.stringify({
      version: BIOMETRIC_RECORD_VERSION,
      keyId,
      origin,
      masterKeyBase64,
    });
    const encryptedBuffer = safeStorage.encryptString(secretPayload);
    const record = JSON.stringify({
      version: BIOMETRIC_RECORD_VERSION,
      keyId,
      origin,
      ciphertextBase64: Buffer.from(encryptedBuffer).toString("base64"),
    });
    const parent = dirname(filePath);
    await mkdir(parent, { recursive: true, mode: 0o700 });
    await restrictDirectory(parent);
    const temporaryPath = `${filePath}.tmp`;
    await writeFile(temporaryPath, record, { mode: 0o600 });
    await restrictFile(temporaryPath);
    await rename(temporaryPath, filePath);
    await restrictFile(filePath);
    return { enabled: true, keyId };
  };

  const unlock = async ({ expectedKeyId, reason } = {}) => {
    if (!isAvailable()) {
      throw createError("e2ee_biometric_unavailable", "Touch ID and system encryption are unavailable on this device.");
    }
    if (expectedKeyId !== undefined && expectedKeyId !== null && !isValidKeyId(expectedKeyId)) {
      throw createError("e2ee_biometric_invalid_input", "Invalid expected E2EE key identifier.");
    }
    const { filePath, origin } = resolveScope();
    if (!filePath) {
      throw createError("e2ee_biometric_unavailable", "Account storage scope is unavailable.");
    }
    const unlockKey = `${filePath}|${expectedKeyId ?? ""}`;
    if (inFlightUnlock) {
      if (inFlightUnlock.key === unlockKey) {
        return inFlightUnlock.promise;
      }
      throw createError("e2ee_biometric_cancelled", "Another Touch ID prompt is already active.");
    }
    const run = (async () => {
      const record = await readStoredRecord(filePath);
      if (!record) {
        throw createError("e2ee_biometric_not_configured", "Touch ID unlock is not enabled for this account.");
      }
      if (record.invalid || record.origin !== origin) {
        await clearFile(filePath);
        throw createError("e2ee_biometric_stale", "Stored Touch ID credential was invalid and has been cleared.");
      }
      if (expectedKeyId && record.keyId !== expectedKeyId) {
        await clearFile(filePath);
        throw createError("e2ee_biometric_key_mismatch", "Stored Touch ID key does not match the current workspace keyring and has been cleared.");
      }
      const promptReason = typeof reason === "string" && reason.trim()
        ? reason.trim().slice(0, 200)
        : "unlock EdgeEver encrypted notes";
      try {
        await systemPreferences.promptTouchID(promptReason);
      } catch {
        throw createError("e2ee_biometric_cancelled", "Touch ID verification was cancelled or failed.");
      }
      let decryptedText;
      try {
        decryptedText = safeStorage.decryptString(Buffer.from(record.ciphertextBase64, "base64"));
      } catch {
        await clearFile(filePath);
        throw createError("e2ee_biometric_decrypt_failed", "Stored Touch ID credential could not be decrypted and has been cleared.");
      }
      let payload;
      try {
        payload = JSON.parse(decryptedText);
      } catch {
        await clearFile(filePath);
        throw createError("e2ee_biometric_stale", "Stored Touch ID credential was corrupted and has been cleared.");
      }
      if (
        !payload
        || typeof payload !== "object"
        || payload.version !== BIOMETRIC_RECORD_VERSION
        || payload.origin !== origin
        || payload.keyId !== record.keyId
        || (expectedKeyId && payload.keyId !== expectedKeyId)
        || !isValidMasterKeyBase64(payload.masterKeyBase64)
      ) {
        await clearFile(filePath);
        throw createError("e2ee_biometric_key_mismatch", "Stored Touch ID credential did not match the expected key and has been cleared.");
      }
      return {
        keyId: payload.keyId,
        masterKeyBase64: payload.masterKeyBase64,
      };
    })();
    inFlightUnlock = { key: unlockKey, promise: run };
    try {
      return await run;
    } finally {
      if (inFlightUnlock?.promise === run) {
        inFlightUnlock = null;
      }
    }
  };

  const disable = async () => {
    const { filePath } = resolveScope();
    await clearFile(filePath);
    return { enabled: false, keyId: null };
  };

  return {
    isAvailable,
    status,
    enable,
    unlock,
    disable,
  };
};

const wrapIpc = (handler) => async (event, ...args) => {
  try {
    const value = await handler(event, ...args);
    return { ok: true, value };
  } catch (error) {
    return {
      ok: false,
      error: {
        code: typeof error?.code === "string" ? error.code : "e2ee_biometric_error",
        message: error instanceof Error ? error.message : String(error),
      },
    };
  }
};

export const registerE2eeBiometricIpc = ({
  ipcMain,
  store,
  isTrustedSender,
}) => {
  const assertTrusted = (event) => {
    if (!isTrustedSender(event)) {
      throw createError("forbidden", "E2EE biometric operations must come from an EdgeEver app window.");
    }
  };
  ipcMain.handle("desktop:e2ee-biometric-status", wrapIpc(async (event) => {
    assertTrusted(event);
    return store.status();
  }));
  ipcMain.handle("desktop:e2ee-biometric-enable", wrapIpc(async (event, input) => {
    assertTrusted(event);
    return store.enable(input && typeof input === "object" ? input : {});
  }));
  ipcMain.handle("desktop:e2ee-biometric-unlock", wrapIpc(async (event, input) => {
    assertTrusted(event);
    return store.unlock(input && typeof input === "object" ? input : {});
  }));
  ipcMain.handle("desktop:e2ee-biometric-disable", wrapIpc(async (event) => {
    assertTrusted(event);
    return store.disable();
  }));
};
