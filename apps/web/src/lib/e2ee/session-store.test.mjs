import { describe, expect, test } from "bun:test";
import { parseEncryptedNoteEnvelope } from "@edgeever/shared";
import { E2eeSessionManager } from "./session-store.ts";

const createMemoryStorage = () => {
  const data = new Map();
  return {
    data,
    getItem: (key) => data.get(key) ?? null,
    setItem: (key, value) => {
      data.set(key, String(value));
    },
    removeItem: (key) => {
      data.delete(key);
    },
  };
};

describe("E2eeSessionManager", () => {
  test("initializes, unlocks, encrypts with fresh IVs, rotates passphrase keeping keyId, and never persists key material", async () => {
    const storage = createMemoryStorage();
    let clock = 1_000_000;
    const manager = new E2eeSessionManager({ storage, now: () => clock });
    manager.setScope("https://example.com|user-1");

    let storedKeyring = null;
    const putKeyring = async (payload) => {
      const nowIso = new Date(clock).toISOString();
      storedKeyring = {
        keyId: payload.keyId,
        kdfAlgorithm: payload.kdfAlgorithm,
        kdfSalt: payload.kdfSalt,
        kdfIterations: payload.kdfIterations,
        wrappedMasterKey: payload.wrappedMasterKey,
        masterKeyIv: payload.masterKeyIv,
        revision: (storedKeyring?.revision ?? 0) + 1,
        createdAt: storedKeyring?.createdAt ?? nowIso,
        updatedAt: nowIso,
      };
      return { configured: true, keyring: storedKeyring };
    };

    const initialized = await manager.initializePassphrase("correct horse battery staple", putKeyring);
    expect(manager.getSnapshot().configured).toBe(true);
    expect(manager.getSnapshot().unlocked).toBe(true);
    expect(manager.getSnapshot().keyId).toBe(initialized.keyId);

    const exported = manager.exportMasterKeyBase64ForBiometric();
    expect(exported.keyId).toBe(initialized.keyId);

    // Ensure localStorage only holds public keyring metadata and never raw WMK/DEK.
    const serializedStorage = JSON.stringify([...storage.data.entries()]);
    expect(serializedStorage).not.toContain(exported.masterKeyBase64);
    expect(serializedStorage).not.toContain("correct horse battery staple");

    // Encrypt twice and verify fresh random IV per save while reusing DEK envelope binding.
    const firstSealed = await manager.encryptMemo("memo-1", "Secret note v1");
    const secondSealed = await manager.encryptMemo("memo-1", "Secret note v2");
    const firstEnv = parseEncryptedNoteEnvelope(firstSealed.markdown);
    const secondEnv = parseEncryptedNoteEnvelope(secondSealed.markdown);
    expect(firstEnv).not.toBeNull();
    expect(secondEnv).not.toBeNull();
    expect(firstEnv.iv).not.toBe(secondEnv.iv);
    expect(firstEnv.wrappedDek).toBe(secondEnv.wrappedDek);
    expect(firstEnv.dekIv).toBe(secondEnv.dekIv);

    // Capture DEK buffer reference to verify zeroization on lock.
    const dekBuffer = secondSealed.noteKey.dek;
    expect(dekBuffer.some((byte) => byte !== 0)).toBe(true);

    // Rotate passphrase: keyId stays identical, old encrypted notes stay decryptable.
    const rotated = await manager.rotatePassphrase(
      "correct horse battery staple",
      "new strong passphrase 2026!",
      putKeyring,
    );
    expect(rotated.keyId).toBe(initialized.keyId);
    expect(rotated.revision).toBe(2);
    expect(rotated.kdfSalt).not.toBe(initialized.kdfSalt);
    expect(rotated.masterKeyIv).not.toBe(initialized.masterKeyIv);

    // Old DEK buffer from before rotation was zeroized during key reload.
    expect(dekBuffer.every((byte) => byte === 0)).toBe(true);

    const decryptedAfterRotate = await manager.decryptMemo("memo-1", secondSealed.markdown);
    expect(decryptedAfterRotate.plaintextMarkdown).toBe("Secret note v2");

    // Lock manually: triggers before-lock flush first, then zeroizes all keys.
    const flushEvents = [];
    const unregisterFlush = manager.registerBeforeLockFlush(async (reason) => {
      flushEvents.push({ reason, unlockedDuringFlush: manager.getSnapshot().unlocked });
    });
    const activeDek = decryptedAfterRotate.noteKey.dek;
    expect(activeDek.some((byte) => byte !== 0)).toBe(true);

    await manager.lock("manual");
    unregisterFlush();

    expect(flushEvents).toEqual([{ reason: "manual", unlockedDuringFlush: true }]);
    expect(manager.getSnapshot().unlocked).toBe(false);
    expect(manager.getSnapshot().lastLockReason).toBe("manual");
    expect(activeDek.every((byte) => byte === 0)).toBe(true);
    await expect(manager.decryptMemo("memo-1", secondSealed.markdown)).rejects.toThrow("locked");

    // Unlock again using the rotated passphrase (old passphrase must fail).
    await expect(manager.unlockWithPassphrase("correct horse battery staple")).rejects.toThrow();
    await manager.unlockWithPassphrase("new strong passphrase 2026!");
    expect((await manager.decryptMemo("memo-1", firstSealed.markdown)).plaintextMarkdown).toBe("Secret note v1");

    // Unlock via biometric master key Base64 works and rejects mismatched keyId.
    await manager.lock("lock-screen");
    expect(() => manager.unlockWithMasterKeyBase64("ek_wrong_key", exported.masterKeyBase64)).toThrow();
    manager.unlockWithMasterKeyBase64(exported.keyId, exported.masterKeyBase64);
    expect(manager.getSnapshot().unlocked).toBe(true);
    expect((await manager.decryptMemo("memo-1", secondSealed.markdown)).plaintextMarkdown).toBe("Secret note v2");

    // Idle auto-lock timeout locks after configured minutes.
    manager.setAutoLockMinutes(5);
    clock += 4 * 60 * 1_000;
    expect(await manager.checkIdleTimeout()).toBe(false);
    expect(manager.getSnapshot().unlocked).toBe(true);
    clock += 2 * 60 * 1_000;
    expect(await manager.checkIdleTimeout()).toBe(true);
    expect(manager.getSnapshot().unlocked).toBe(false);
    expect(manager.getSnapshot().lastLockReason).toBe("idle");

    // Logout lock skips flush handlers and clears keys; scope switch clears keys.
    manager.unlockWithMasterKeyBase64(exported.keyId, exported.masterKeyBase64);
    const logoutFlushCalls = [];
    manager.registerBeforeLockFlush(() => {
      logoutFlushCalls.push("called");
    });
    await manager.lock("logout");
    expect(logoutFlushCalls).toEqual([]);
    expect(manager.getSnapshot().unlocked).toBe(false);

    manager.unlockWithMasterKeyBase64(exported.keyId, exported.masterKeyBase64);
    manager.setScope("https://example.com|user-2");
    expect(manager.getSnapshot().unlocked).toBe(false);
    expect(manager.getSnapshot().configured).toBe(false);
    expect(manager.getSnapshot().lastLockReason).toBe("account-changed");
  });
});
