import { expect, test } from "bun:test";
import { randomBytes } from "node:crypto";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createE2eeBiometricStore, e2eeBiometricPath, registerE2eeBiometricIpc } from "./e2ee-biometric.mjs";

const makeSafeStorage = ({ available = true } = {}) => ({
  isEncryptionAvailable: () => available,
  encryptString: (plaintext) => Buffer.from(`sealed:${plaintext}`, "utf8"),
  decryptString: (buffer) => {
    const text = Buffer.from(buffer).toString("utf8");
    if (!text.startsWith("sealed:")) throw new Error("corrupt");
    return text.slice("sealed:".length);
  },
});

test("macOS Touch ID store requires biometric prompt before enable and unlock, enforces 0o600, and isolates by account", async () => {
  const userDataDirectory = await mkdtemp(join(tmpdir(), "edgeever-e2ee-bio-"));
  try {
    const prompts = [];
    let currentAccount = "user_a";
    let shouldApproveTouchId = true;
    const store = createE2eeBiometricStore({
      platform: "darwin",
      systemPreferences: {
        canPromptTouchID: () => true,
        promptTouchID: async (reason) => {
          prompts.push(reason);
          if (!shouldApproveTouchId) throw new Error("User cancelled Touch ID");
        },
      },
      safeStorage: makeSafeStorage(),
      getScope: () => ({
        userDataDirectory,
        apiBaseUrl: "https://notes.example.test",
        accountId: currentAccount,
      }),
    });

    expect(await store.status()).toEqual({ available: true, enabled: false, keyId: null });

    const masterKeyBase64 = randomBytes(32).toString("base64");
    const enabled = await store.enable({
      keyId: "ek_account_a_1234",
      masterKeyBase64,
      reason: "enable Touch ID",
    });
    expect(enabled).toEqual({ enabled: true, keyId: "ek_account_a_1234" });
    expect(prompts).toEqual(["enable Touch ID"]);

    const filePath = e2eeBiometricPath(userDataDirectory, "https://notes.example.test", "user_a");
    if (process.platform !== "win32") {
      expect((await stat(filePath)).mode & 0o777).toBe(0o600);
    }
    const rawOnDisk = await readFile(filePath, "utf8");
    expect(rawOnDisk).not.toContain(masterKeyBase64);

    // Status checks do not prompt Touch ID.
    expect(await store.status()).toEqual({ available: true, enabled: true, keyId: "ek_account_a_1234" });
    expect(prompts).toHaveLength(1);

    // Unlock must prompt Touch ID before decrypting.
    shouldApproveTouchId = false;
    await expect(store.unlock({ expectedKeyId: "ek_account_a_1234", reason: "unlock notes" }))
      .rejects.toMatchObject({ code: "e2ee_biometric_cancelled" });
    expect(prompts).toEqual(["enable Touch ID", "unlock notes"]);

    shouldApproveTouchId = true;
    const unlocked = await store.unlock({ expectedKeyId: "ek_account_a_1234", reason: "unlock notes" });
    expect(unlocked).toEqual({ keyId: "ek_account_a_1234", masterKeyBase64 });
    expect(prompts).toEqual(["enable Touch ID", "unlock notes", "unlock notes"]);

    // Switching account isolates credentials completely.
    currentAccount = "user_b";
    expect(await store.status()).toEqual({ available: true, enabled: false, keyId: null });
    await expect(store.unlock({ expectedKeyId: "ek_account_a_1234" }))
      .rejects.toMatchObject({ code: "e2ee_biometric_not_configured" });

    // Switching back and unlocking with a mismatched expectedKeyId clears the stale credential automatically.
    currentAccount = "user_a";
    await expect(store.unlock({ expectedKeyId: "ek_different_9999" }))
      .rejects.toMatchObject({ code: "e2ee_biometric_key_mismatch" });
    expect(await store.status()).toEqual({ available: true, enabled: false, keyId: null });
  } finally {
    await rm(userDataDirectory, { recursive: true, force: true });
  }
});

test("biometric store reports unavailable on non-darwin platforms and rejects untrusted IPC senders", async () => {
  const userDataDirectory = await mkdtemp(join(tmpdir(), "edgeever-e2ee-bio-win-"));
  try {
    const store = createE2eeBiometricStore({
      platform: "win32",
      systemPreferences: { canPromptTouchID: () => true, promptTouchID: async () => {} },
      safeStorage: makeSafeStorage(),
      getScope: () => ({ userDataDirectory, apiBaseUrl: "https://notes.example.test", accountId: "u1" }),
    });
    expect(await store.status()).toEqual({ available: false, enabled: false, keyId: null });
    await expect(store.enable({
      keyId: "ek_win_test_1234",
      masterKeyBase64: randomBytes(32).toString("base64"),
    })).rejects.toMatchObject({ code: "e2ee_biometric_unavailable" });

    const handlers = new Map();
    const trustedSender = { id: 1 };
    registerE2eeBiometricIpc({
      ipcMain: { handle: (channel, fn) => handlers.set(channel, fn) },
      store,
      isTrustedSender: (event) => event.sender === trustedSender,
    });

    const untrustedResult = await handlers.get("desktop:e2ee-biometric-status")({ sender: { id: 2 } });
    expect(untrustedResult).toMatchObject({ ok: false, error: { code: "forbidden" } });

    const trustedResult = await handlers.get("desktop:e2ee-biometric-status")({ sender: trustedSender });
    expect(trustedResult).toEqual({ ok: true, value: { available: false, enabled: false, keyId: null } });
  } finally {
    await rm(userDataDirectory, { recursive: true, force: true });
  }
});

test("concurrent Touch ID unlock calls share a single biometric prompt", async () => {
  const userDataDirectory = await mkdtemp(join(tmpdir(), "edgeever-e2ee-bio-dedupe-"));
  try {
    let promptCount = 0;
    let releasePrompt;
    const store = createE2eeBiometricStore({
      platform: "darwin",
      systemPreferences: {
        canPromptTouchID: () => true,
        promptTouchID: async () => {
          promptCount += 1;
          if (promptCount === 1) return;
          await new Promise((resolve) => { releasePrompt = resolve; });
        },
      },
      safeStorage: makeSafeStorage(),
      getScope: () => ({
        userDataDirectory,
        apiBaseUrl: "https://notes.example.test",
        accountId: "user_a",
      }),
    });

    const masterKeyBase64 = randomBytes(32).toString("base64");
    await store.enable({ keyId: "ek_dedupe_123456", masterKeyBase64 });

    const first = store.unlock({ expectedKeyId: "ek_dedupe_123456" });
    const second = store.unlock({ expectedKeyId: "ek_dedupe_123456" });
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(promptCount).toBe(2);
    releasePrompt();
    const [r1, r2] = await Promise.all([first, second]);
    expect(r1).toEqual({ keyId: "ek_dedupe_123456", masterKeyBase64 });
    expect(r2).toEqual({ keyId: "ek_dedupe_123456", masterKeyBase64 });
  } finally {
    await rm(userDataDirectory, { recursive: true, force: true });
  }
});
