import {
  decryptNoteContent,
  decodeBase64Strict,
  encodeBase64,
  encryptNoteContent,
  initializeWorkspaceKeyring,
  parseEncryptedNoteEnvelope,
  rotateWorkspacePassphrase,
  unlockWorkspaceMasterKey,
  zeroizeBytes,
  type E2eeCryptoProvider,
  type EncryptedNoteEnvelope,
  type NoteDekBinding,
  type WorkspaceE2eeKeyring,
  type WorkspaceE2eeKeyringResponse,
  type WorkspaceE2eeKeyringUpsertPayload,
} from "@edgeever/shared";

export type E2eeAutoLockMinutes = 5 | 15 | 30;
export type E2eeLockReason = "manual" | "idle" | "lock-screen" | "suspend" | "logout" | "account-changed" | "system";

export type E2eeSessionSnapshot = {
  scope: string;
  configured: boolean;
  keyring: WorkspaceE2eeKeyring | null;
  unlocked: boolean;
  keyId: string | null;
  autoLockMinutes: E2eeAutoLockMinutes;
  loading: boolean;
  lastLockReason: E2eeLockReason | null;
};

type CachedDekEntry = {
  keyId: string;
  dek: Uint8Array;
  wrappedDek: string;
  dekIv: string;
};

type BeforeLockFlushHandler = (reason: E2eeLockReason) => void | Promise<void>;

type E2eeSessionManagerOptions = {
  storage?: Pick<Storage, "getItem" | "setItem" | "removeItem"> | null;
  now?: () => number;
  provider?: E2eeCryptoProvider;
};

const AUTO_LOCK_STORAGE_KEY = "edgeever.e2ee.auto-lock-minutes";
const KEYRING_CACHE_PREFIX = "edgeever.e2ee.keyring.";
const DEFAULT_AUTO_LOCK_MINUTES: E2eeAutoLockMinutes = 15;
const BEFORE_LOCK_FLUSH_TIMEOUT_MS = 1_500;
const IDLE_CHECK_INTERVAL_MS = 15_000;
const ACTIVITY_TOUCH_THROTTLE_MS = 10_000;

const isAutoLockMinutes = (value: unknown): value is E2eeAutoLockMinutes =>
  value === 5 || value === 15 || value === 30;

const getDefaultStorage = (): Pick<Storage, "getItem" | "setItem" | "removeItem"> | null => {
  try {
    return typeof window !== "undefined" ? window.localStorage : null;
  } catch {
    return null;
  }
};

const isValidCachedKeyring = (value: unknown): value is WorkspaceE2eeKeyring => {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Record<string, unknown>;
  return (
    typeof candidate.keyId === "string"
    && typeof candidate.kdfAlgorithm === "string"
    && typeof candidate.kdfSalt === "string"
    && typeof candidate.kdfIterations === "number"
    && typeof candidate.wrappedMasterKey === "string"
    && typeof candidate.masterKeyIv === "string"
    && typeof candidate.revision === "number"
    && typeof candidate.createdAt === "string"
    && typeof candidate.updatedAt === "string"
  );
};

export class E2eeSessionManager {
  private readonly storage: Pick<Storage, "getItem" | "setItem" | "removeItem"> | null;
  private readonly now: () => number;
  private readonly provider?: E2eeCryptoProvider;

  private scope = "default";
  private keyring: WorkspaceE2eeKeyring | null = null;
  private loading = false;
  private lastLockReason: E2eeLockReason | null = null;
  private autoLockMinutes: E2eeAutoLockMinutes = DEFAULT_AUTO_LOCK_MINUTES;

  // Strictly in-memory cryptographic key material — never persisted.
  private masterKey: Uint8Array | null = null;
  private masterKeyId: string | null = null;
  private readonly noteDekCache = new Map<string, CachedDekEntry>();
  private keyGeneration = 0;
  private inFlightCryptoOps = 0;
  private readonly inFlightWaiters: Array<() => void> = [];
  private readonly pendingZeroizeBuffers: Uint8Array[] = [];
  private lastActivityAt = 0;
  private lastTouchAt = 0;

  private readonly listeners = new Set<() => void>();
  private readonly beforeLockFlushHandlers = new Set<BeforeLockFlushHandler>();
  private snapshot: E2eeSessionSnapshot;
  private lockPromise: Promise<void> | null = null;

  constructor(options: E2eeSessionManagerOptions = {}) {
    this.storage = options.storage !== undefined ? options.storage : getDefaultStorage();
    this.now = options.now ?? (() => Date.now());
    this.provider = options.provider;
    this.autoLockMinutes = this.readAutoLockMinutes();
    this.snapshot = this.buildSnapshot();
  }

  private buildSnapshot(): E2eeSessionSnapshot {
    return {
      scope: this.scope,
      configured: Boolean(this.keyring),
      keyring: this.keyring,
      unlocked: Boolean(this.masterKey && this.masterKeyId),
      keyId: this.masterKeyId ?? this.keyring?.keyId ?? null,
      autoLockMinutes: this.autoLockMinutes,
      loading: this.loading,
      lastLockReason: this.lastLockReason,
    };
  }

  private emit() {
    this.snapshot = this.buildSnapshot();
    for (const listener of Array.from(this.listeners)) {
      try {
        listener();
      } catch {
        // Listener errors must never block lock/state transitions.
      }
    }
  }

  getSnapshot = (): E2eeSessionSnapshot => this.snapshot;

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  registerBeforeLockFlush = (handler: BeforeLockFlushHandler): (() => void) => {
    this.beforeLockFlushHandlers.add(handler);
    return () => {
      this.beforeLockFlushHandlers.delete(handler);
    };
  };

  private readAutoLockMinutes(): E2eeAutoLockMinutes {
    try {
      const raw = this.storage?.getItem(AUTO_LOCK_STORAGE_KEY);
      const parsed = raw ? Number(raw) : Number.NaN;
      return isAutoLockMinutes(parsed) ? parsed : DEFAULT_AUTO_LOCK_MINUTES;
    } catch {
      return DEFAULT_AUTO_LOCK_MINUTES;
    }
  }

  setAutoLockMinutes = (minutes: E2eeAutoLockMinutes) => {
    if (!isAutoLockMinutes(minutes)) return;
    this.autoLockMinutes = minutes;
    try {
      this.storage?.setItem(AUTO_LOCK_STORAGE_KEY, String(minutes));
    } catch {
      // Ignore restricted storage contexts.
    }
    this.emit();
  };

  private keyringCacheKey(scope: string) {
    return `${KEYRING_CACHE_PREFIX}${scope}`;
  }

  private readCachedKeyring(scope: string): WorkspaceE2eeKeyring | null {
    try {
      const raw = this.storage?.getItem(this.keyringCacheKey(scope));
      if (!raw) return null;
      const parsed = JSON.parse(raw) as unknown;
      return isValidCachedKeyring(parsed) ? parsed : null;
    } catch {
      return null;
    }
  }

  private writeCachedKeyring(scope: string, keyring: WorkspaceE2eeKeyring | null) {
    try {
      if (keyring) {
        this.storage?.setItem(this.keyringCacheKey(scope), JSON.stringify(keyring));
      } else {
        this.storage?.removeItem(this.keyringCacheKey(scope));
      }
    } catch {
      // Ignore storage quota or restricted storage contexts.
    }
  }

  private flushPendingZeroize() {
    while (this.pendingZeroizeBuffers.length > 0) {
      zeroizeBytes(this.pendingZeroizeBuffers.pop());
    }
  }

  private waitForInFlightCryptoOps(): Promise<void> {
    if (this.inFlightCryptoOps === 0) return Promise.resolve();
    return new Promise<void>((resolve) => {
      this.inFlightWaiters.push(resolve);
    });
  }

  private async runCryptoOp<T>(fn: () => Promise<T>): Promise<T> {
    this.inFlightCryptoOps += 1;
    try {
      return await fn();
    } finally {
      this.inFlightCryptoOps -= 1;
      if (this.inFlightCryptoOps === 0) {
        this.flushPendingZeroize();
        const waiters = this.inFlightWaiters.splice(0);
        for (const resolve of waiters) {
          resolve();
        }
      }
    }
  }

  private zeroizeAllKeys() {
    this.keyGeneration += 1;
    const buffers: Uint8Array[] = [];
    if (this.masterKey) buffers.push(this.masterKey);
    this.masterKey = null;
    this.masterKeyId = null;
    for (const entry of this.noteDekCache.values()) {
      buffers.push(entry.dek);
    }
    this.noteDekCache.clear();
    if (this.inFlightCryptoOps === 0) {
      for (const buffer of buffers) {
        zeroizeBytes(buffer);
      }
    } else {
      this.pendingZeroizeBuffers.push(...buffers);
    }
  }

  setScope = (nextScope: string) => {
    const normalized = nextScope.trim() || "default";
    if (normalized === this.scope) return;
    this.zeroizeAllKeys();
    this.scope = normalized;
    this.lastLockReason = "account-changed";
    this.keyring = this.readCachedKeyring(normalized);
    this.emit();
  };

  refreshKeyring = async (fetcher: () => Promise<WorkspaceE2eeKeyringResponse>): Promise<WorkspaceE2eeKeyring | null> => {
    const targetScope = this.scope;
    this.loading = true;
    this.emit();
    try {
      const response = await fetcher();
      if (this.scope !== targetScope) return this.keyring;
      const nextKeyring = response.configured ? response.keyring : null;
      this.keyring = nextKeyring;
      this.writeCachedKeyring(targetScope, nextKeyring);
      if (!nextKeyring || (this.masterKeyId && nextKeyring.keyId !== this.masterKeyId)) {
        this.zeroizeAllKeys();
      }
      return nextKeyring;
    } catch (error) {
      if (this.scope === targetScope && !this.keyring) {
        this.keyring = this.readCachedKeyring(targetScope);
      }
      throw error;
    } finally {
      if (this.scope === targetScope) {
        this.loading = false;
        this.emit();
      }
    }
  };

  setKeyringMetadata = (keyring: WorkspaceE2eeKeyring | null) => {
    this.keyring = keyring;
    this.writeCachedKeyring(this.scope, keyring);
    if (!keyring || (this.masterKeyId && keyring.keyId !== this.masterKeyId)) {
      this.zeroizeAllKeys();
    }
    this.emit();
  };

  initializePassphrase = async (
    passphrase: string,
    putKeyring: (payload: WorkspaceE2eeKeyringUpsertPayload) => Promise<WorkspaceE2eeKeyringResponse>,
  ): Promise<WorkspaceE2eeKeyring> => {
    const initialized = await initializeWorkspaceKeyring(
      { passphrase },
      this.provider,
    );
    try {
      const response = await putKeyring(initialized.keyring);
      if (!response.configured || !response.keyring) {
        throw new Error("Server did not return a configured E2EE keyring.");
      }
      this.zeroizeAllKeys();
      this.keyring = response.keyring;
      this.writeCachedKeyring(this.scope, response.keyring);
      this.masterKey = initialized.masterKey;
      this.masterKeyId = response.keyring.keyId;
      this.lastActivityAt = this.now();
      this.lastLockReason = null;
      this.emit();
      return response.keyring;
    } catch (error) {
      zeroizeBytes(initialized.masterKey);
      throw error;
    }
  };

  unlockWithPassphrase = async (passphrase: string): Promise<{ keyId: string }> => {
    const keyring = this.keyring ?? this.readCachedKeyring(this.scope);
    if (!keyring) {
      throw new Error("E2EE keyring is not configured.");
    }
    const masterKey = await unlockWorkspaceMasterKey(
      {
        passphrase,
        keyring,
      },
      this.provider,
    );
    this.zeroizeAllKeys();
    this.keyring = keyring;
    this.masterKey = masterKey;
    this.masterKeyId = keyring.keyId;
    this.lastActivityAt = this.now();
    this.lastLockReason = null;
    this.emit();
    return { keyId: keyring.keyId };
  };

  unlockWithMasterKeyBase64 = (keyId: string, masterKeyBase64: string): { keyId: string } => {
    const keyring = this.keyring ?? this.readCachedKeyring(this.scope);
    if (!keyring || keyring.keyId !== keyId) {
      throw new Error("Stored biometric key does not match the current workspace keyring.");
    }
    const decoded = decodeBase64Strict(masterKeyBase64);
    if (!decoded || decoded.byteLength !== 32) {
      throw new Error("Stored biometric master key is invalid.");
    }
    this.zeroizeAllKeys();
    this.keyring = keyring;
    this.masterKey = decoded;
    this.masterKeyId = keyring.keyId;
    this.lastActivityAt = this.now();
    this.lastLockReason = null;
    this.emit();
    return { keyId: keyring.keyId };
  };

  exportMasterKeyBase64ForBiometric = (): { keyId: string; masterKeyBase64: string } => {
    if (!this.masterKey || !this.masterKeyId) {
      throw new Error("Unlock encrypted notes before enabling Touch ID.");
    }
    return {
      keyId: this.masterKeyId,
      masterKeyBase64: encodeBase64(this.masterKey),
    };
  };

  rotatePassphrase = async (
    currentPassphrase: string,
    newPassphrase: string,
    putKeyring: (payload: WorkspaceE2eeKeyringUpsertPayload) => Promise<WorkspaceE2eeKeyringResponse>,
  ): Promise<WorkspaceE2eeKeyring> => {
    const currentKeyring = this.keyring ?? this.readCachedKeyring(this.scope);
    if (!currentKeyring) {
      throw new Error("E2EE keyring is not configured.");
    }
    const rotated = await rotateWorkspacePassphrase(
      {
        currentPassphrase,
        newPassphrase,
        currentKeyring,
      },
      this.provider,
    );
    try {
      const response = await putKeyring(rotated.keyring);
      if (!response.configured || !response.keyring) {
        throw new Error("Server did not return the updated E2EE keyring.");
      }
      this.zeroizeAllKeys();
      this.keyring = response.keyring;
      this.writeCachedKeyring(this.scope, response.keyring);
      this.masterKey = rotated.masterKey;
      this.masterKeyId = response.keyring.keyId;
      this.lastActivityAt = this.now();
      this.lastLockReason = null;
      this.emit();
      return response.keyring;
    } catch (error) {
      zeroizeBytes(rotated.masterKey);
      throw error;
    }
  };

  private cacheDek(memoId: string, binding: NoteDekBinding) {
    // Do not zeroize the replaced DEK buffer in place: a concurrent crypto call
    // may still hold a reference to it before copying. It will be scrubbed when
    // detached/locked or garbage collected once no references remain.
    this.noteDekCache.set(memoId, {
      keyId: binding.keyId,
      dek: binding.dek,
      wrappedDek: binding.wrappedDek,
      dekIv: binding.dekIv,
    });
  }

  evictMemoDek = (memoId: string) => {
    const existing = this.noteDekCache.get(memoId);
    if (existing) {
      this.noteDekCache.delete(memoId);
      if (this.inFlightCryptoOps === 0) {
        zeroizeBytes(existing.dek);
      } else {
        this.pendingZeroizeBuffers.push(existing.dek);
      }
    }
  };

  decryptMemo = async (memoId: string, envelopeOrMarkdown: string | EncryptedNoteEnvelope) => {
    const masterKey = this.masterKey;
    const masterKeyId = this.masterKeyId;
    if (!masterKey || !masterKeyId) {
      throw new Error("Encrypted notes are locked.");
    }
    const generation = this.keyGeneration;
    this.touchActivity();
    return this.runCryptoOp(async () => {
      const result = await decryptNoteContent(
        {
          memoId,
          masterKey,
          envelopeOrMarkdown,
          expectedKeyId: masterKeyId,
        },
        this.provider,
      );
      if (this.keyGeneration === generation && this.masterKey && this.masterKeyId === result.noteKey.keyId) {
        this.cacheDek(memoId, result.noteKey);
      } else {
        zeroizeBytes(result.dek);
      }
      return result;
    });
  };

  encryptMemo = async (
    memoId: string,
    plaintextMarkdown: string,
    existingMarkdown?: string | null,
  ) => {
    const masterKey = this.masterKey;
    const masterKeyId = this.masterKeyId;
    if (!masterKey || !masterKeyId) {
      throw new Error("Encrypted notes are locked.");
    }
    const generation = this.keyGeneration;
    this.touchActivity();
    const cached = this.noteDekCache.get(memoId);
    const matchingCached = cached && cached.keyId === masterKeyId ? cached : undefined;
    const existingEnvelope = matchingCached
      ? undefined
      : (existingMarkdown ? parseEncryptedNoteEnvelope(existingMarkdown) ?? undefined : undefined);

    return this.runCryptoOp(async () => {
      const result = await encryptNoteContent(
        {
          memoId,
          keyId: masterKeyId,
          masterKey,
          plaintextMarkdown,
          ...(matchingCached
            ? { noteKey: matchingCached }
            : existingEnvelope && existingEnvelope.keyId === masterKeyId
              ? { existingEnvelope }
              : {}),
        },
        this.provider,
      );
      if (this.keyGeneration === generation && this.masterKey && this.masterKeyId === result.noteKey.keyId) {
        this.cacheDek(memoId, result.noteKey);
      } else {
        zeroizeBytes(result.dek);
      }
      return result;
    });
  };

  touchActivity = (force = false) => {
    if (!this.masterKey) return;
    const current = this.now();
    if (!force && current - this.lastTouchAt < ACTIVITY_TOUCH_THROTTLE_MS) return;
    this.lastTouchAt = current;
    this.lastActivityAt = current;
  };

  checkIdleTimeout = async (): Promise<boolean> => {
    if (!this.masterKey) return false;
    const elapsed = this.now() - this.lastActivityAt;
    if (elapsed >= this.autoLockMinutes * 60 * 1_000) {
      await this.lock("idle");
      return true;
    }
    return false;
  };

  lock = async (reason: E2eeLockReason = "manual"): Promise<void> => {
    if (this.lockPromise) return this.lockPromise;
    if (!this.masterKey && this.noteDekCache.size === 0) {
      if (this.lastLockReason !== reason) {
        this.lastLockReason = reason;
        this.emit();
      }
      return;
    }

    const shouldFlush = reason !== "logout" && reason !== "account-changed";
    const task = (async () => {
      if (shouldFlush && this.beforeLockFlushHandlers.size > 0) {
        const flushes = Array.from(this.beforeLockFlushHandlers).map((handler) =>
          Promise.resolve().then(() => handler(reason)).catch(() => undefined)
        );
        await Promise.race([
          Promise.all(flushes),
          new Promise<void>((resolve) => globalThis.setTimeout(resolve, BEFORE_LOCK_FLUSH_TIMEOUT_MS)),
        ]);
      }
      this.zeroizeAllKeys();
      this.lastLockReason = reason;
      this.emit();
      await this.waitForInFlightCryptoOps();
    })().finally(() => {
      this.lockPromise = null;
    });

    this.lockPromise = task;
    return task;
  };

  attachBrowserListeners = (): (() => void) => {
    if (typeof window === "undefined") return () => {};
    const onActivity = () => this.touchActivity();
    const onVisibilityChange = () => {
      if (typeof document !== "undefined" && document.visibilityState === "visible") {
        void this.checkIdleTimeout();
      }
    };
    const events: Array<keyof WindowEventMap> = ["pointerdown", "keydown", "wheel"];
    for (const event of events) {
      window.addEventListener(event, onActivity, { passive: true });
    }
    document.addEventListener("visibilitychange", onVisibilityChange);
    const interval = window.setInterval(() => {
      void this.checkIdleTimeout();
    }, IDLE_CHECK_INTERVAL_MS);
    const removeDesktopLock = window.edgeeverDesktop?.onE2eeLock?.((payload) => {
      const reason: E2eeLockReason =
        payload?.reason === "lock-screen"
          ? "lock-screen"
          : payload?.reason === "suspend"
            ? "suspend"
            : payload?.reason === "logout"
              ? "logout"
              : payload?.reason === "account-changed"
                ? "account-changed"
                : "system";
      void this.lock(reason);
    });

    return () => {
      for (const event of events) {
        window.removeEventListener(event, onActivity);
      }
      document.removeEventListener("visibilitychange", onVisibilityChange);
      window.clearInterval(interval);
      removeDesktopLock?.();
    };
  };
}

export const e2eeSession = new E2eeSessionManager();
