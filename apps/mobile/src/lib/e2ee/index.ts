import { useSyncExternalStore } from "react";
import type { createEdgeEverClient } from "@edgeever/client";
import { emptyDoc, hasEncryptedNoteMarker, type MemoDetail, type MemoSummary } from "@edgeever/shared";
import { upsertLocalMemo } from "../local-mirror";
import { mobileE2eeSession } from "./session-store";

export { mobileE2eeCryptoProvider, createNativeMobileE2eeProvider, resolveMobileE2eeCryptoProvider } from "./crypto-provider";
export { mobileE2eeBiometricStore, MobileE2eeBiometricStore, type MobileBiometricStatus } from "./biometric-store";
export {
  mobileE2eeSession,
  MobileE2eeSessionManager,
  type MobileE2eeAutoLockMinutes,
  type MobileE2eeLockReason,
  type MobileE2eeSessionSnapshot,
} from "./session-store";

export const useMobileE2eeSession = () =>
  useSyncExternalStore(mobileE2eeSession.subscribe, mobileE2eeSession.getSnapshot, mobileE2eeSession.getSnapshot);

export const isMobileEncryptedMemo = (
  memo: Pick<MemoSummary, "encrypted"> & { contentMarkdown?: string | null } | null | undefined,
): boolean => Boolean(memo && (memo.encrypted === true || hasEncryptedNoteMarker(memo.contentMarkdown)));

/**
 * Create a brand-new encrypted note online so its authoritative server `memoId`
 * is bound into AES-GCM AAD before any user plaintext ever touches disk or network.
 */
export const createEncryptedMobileMemoOnline = async ({
  client,
  dataScope,
  notebookId,
  title = "",
  tags = [],
}: {
  client: ReturnType<typeof createEdgeEverClient>;
  dataScope: string;
  notebookId: string;
  title?: string;
  tags?: string[];
}): Promise<MemoDetail> => {
  const created = await client.createMemo({
    notebookId,
    title,
    contentJson: emptyDoc(),
    contentMarkdown: "",
    tags,
  });
  const sealed = await mobileE2eeSession.encryptMemo(created.memo.id, "");
  const editSession = await client.createMemoEditSession(created.memo.id);
  const updated = await client.updateMemo(created.memo.id, {
    expectedRevision: created.memo.revision,
    expectedContentHash: created.memo.contentHash,
    editSessionId: editSession.editSession.id,
    title,
    contentJson: emptyDoc(),
    contentMarkdown: sealed.markdown,
    tags,
  });
  await upsertLocalMemo(dataScope, updated.memo);
  return updated.memo;
};
