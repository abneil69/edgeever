import { useSyncExternalStore } from "react";
import { emptyDoc, hasEncryptedNoteMarker, type MemoDetail } from "@edgeever/shared";
import { api } from "@/lib/api";
import { putLocalMemo } from "@/lib/local-mirror";
import { isBrowserOffline } from "@/lib/network-status";
import { isNativeDesktopRuntime } from "@/lib/runtime";
import { e2eeSession, type E2eeSessionSnapshot } from "./session-store";

export * from "./session-store";

export const useE2eeSession = (): E2eeSessionSnapshot =>
  useSyncExternalStore(e2eeSession.subscribe, e2eeSession.getSnapshot, e2eeSession.getSnapshot);

export const isEncryptedMemo = (memo: { encrypted?: boolean; contentMarkdown?: string | null } | null | undefined): boolean => {
  if (!memo) return false;
  if (typeof memo.contentMarkdown === "string") {
    return hasEncryptedNoteMarker(memo.contentMarkdown);
  }
  return memo.encrypted === true;
};

/**
 * Create a brand-new encrypted note whose ciphertext envelope is bound to the
 * authoritative server `memoId` before any user plaintext ever exists.
 */
export const createEncryptedMemoOnline = async (input: {
  scope: string;
  notebookId: string;
  title?: string;
  tags?: string[];
}): Promise<{ memo: MemoDetail }> => {
  if (isBrowserOffline()) {
    throw Object.assign(new Error("Creating a new encrypted note requires an internet connection."), {
      code: "e2ee_offline_create_unsupported",
    });
  }
  const snapshot = e2eeSession.getSnapshot();
  if (!snapshot.unlocked) {
    throw Object.assign(new Error("Unlock encrypted notes before creating an encrypted note."), {
      code: "e2ee_locked",
    });
  }

  // Step 1: Allocate the authoritative server memoId with an empty container (zero user content).
  const created = await api.createMemo({
    notebookId: input.notebookId,
    title: input.title ?? "",
    contentJson: emptyDoc(),
    contentMarkdown: "",
    tags: input.tags ?? [],
  });

  // Step 2: Seal the initial empty body with the real memoId in AAD.
  const sealed = await e2eeSession.encryptMemo(created.memo.id, "");
  const { editSession } = await api.createMemoEditSession(created.memo.id);
  const updated = await api.updateMemo(created.memo.id, {
    title: input.title ?? "",
    contentJson: emptyDoc(),
    contentMarkdown: sealed.markdown,
    tags: input.tags ?? [],
    expectedRevision: created.memo.revision,
    expectedContentHash: created.memo.contentHash,
    editSessionId: editSession.id,
  });

  // Step 3: Mirror the sealed ciphertext into local storage (sidecar or IndexedDB).
  if (isNativeDesktopRuntime() && window.edgeeverDesktop?.sidecarRequest) {
    await window.edgeeverDesktop.sidecarRequest("sync.apply", {
      changes: [{
        entityType: "memo",
        operation: "upsert",
        entityId: updated.memo.id,
        memo: updated.memo,
        notebook: null,
      }],
    }).catch(() => undefined);
  } else {
    await putLocalMemo(input.scope, updated.memo).catch(() => undefined);
  }

  return updated;
};
