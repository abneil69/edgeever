import {
  createExcerpt,
  DEFAULT_MEMO_TITLE,
  docToMarkdown,
  docToText,
  emptyDoc,
  hasEncryptedNoteMarker,
  normalizeTags,
  parseEncryptedNoteEnvelope,
  WORKSPACE_E2EE_KDF_ALGORITHM,
  WorkspaceE2eeKeyringSchema,
  type JsonBackupMemo,
  type JsonBackupNotebook,
  type TiptapDoc,
  type WorkspaceE2eeKeyring,
} from "@edgeever/shared";
import { AppError } from "./app-error";
import { audit } from "./audit";
import { createId } from "./entity-utils";
import { sha256 } from "./hash-utils";
import { upsertMemoSearchDocumentStatement } from "./memo-search-index";
import type { DatabaseAdapter } from "./storage-contract";

const parseBackupDoc = (value: unknown): TiptapDoc => {
  try {
    const parsed = JSON.parse(JSON.stringify(value));
    return parsed && typeof parsed === "object" ? parsed as TiptapDoc : emptyDoc();
  } catch {
    return emptyDoc();
  }
};

const normalizeMemoTitle = (value: string | null | undefined) => {
  const title = value?.trim();
  return title || DEFAULT_MEMO_TITLE;
};

const assertIdsAvailableInWorkspace = async (
  db: DatabaseAdapter,
  table: "notebooks" | "memos",
  workspaceId: string,
  ids: string[],
) => {
  if (ids.length === 0) return;
  const placeholders = ids.map(() => "?").join(", ");
  const collision = await db.prepare(
    `SELECT id FROM ${table} WHERE workspace_id <> ? AND id IN (${placeholders}) LIMIT 1`,
  ).bind(workspaceId, ...ids).first<{ id: string }>();
  if (collision) {
    throw new AppError("cross_workspace_id_conflict", "Backup contains an ID already used by another user.", 409);
  }
};

const assertNotebookIdsInWorkspace = async (
  db: DatabaseAdapter,
  workspaceId: string,
  ids: string[],
) => {
  const uniqueIds = Array.from(new Set(ids));
  if (uniqueIds.length === 0) return;
  const placeholders = uniqueIds.map(() => "?").join(", ");
  const rows = await db.prepare(
    `SELECT id FROM notebooks WHERE workspace_id = ? AND id IN (${placeholders})`,
  ).bind(workspaceId, ...uniqueIds).all<{ id: string }>();
  if (rows.results.length !== uniqueIds.length) {
    throw new AppError("invalid_backup_workspace", "Backup references a notebook outside the current workspace.", 400);
  }
};

export const restoreJsonNotebooks = async (
  db: DatabaseAdapter,
  workspaceId: string,
  notebooks: JsonBackupNotebook[],
) => {
  await assertIdsAvailableInWorkspace(db, "notebooks", workspaceId, notebooks.map((notebook) => notebook.id));
  const importedIds = new Set(notebooks.map((notebook) => notebook.id));
  const externalParentIds = notebooks
    .map((notebook) => notebook.parentId)
    .filter((id): id is string => Boolean(id) && !importedIds.has(id as string));
  await assertNotebookIdsInWorkspace(db, workspaceId, externalParentIds);

  await db.batch(notebooks.map((notebook) => db.prepare(
    `INSERT INTO notebooks (
      id, workspace_id, parent_id, name, slug, icon, color, text_color, color_target, is_bold, icon_inverted, row_inverted, sort_order, is_deleted, created_at, updated_at, deleted_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, NULL)
    ON CONFLICT(id) DO UPDATE SET
      parent_id = excluded.parent_id,
      name = excluded.name,
      slug = excluded.slug,
      icon = excluded.icon,
      color = excluded.color,
      text_color = excluded.text_color,
      color_target = excluded.color_target,
      is_bold = excluded.is_bold,
      icon_inverted = excluded.icon_inverted,
      row_inverted = excluded.row_inverted,
      sort_order = excluded.sort_order,
      is_deleted = 0,
      updated_at = excluded.updated_at,
      deleted_at = NULL`,
  ).bind(
    notebook.id,
    workspaceId,
    notebook.parentId,
    notebook.name,
    notebook.slug,
    notebook.icon,
    notebook.color,
    notebook.textColor ?? null,
    notebook.colorTarget ?? "icon",
    Number(notebook.isBold ?? false),
    Number(notebook.iconInverted ?? false),
    Number(notebook.rowInverted ?? false),
    notebook.sortOrder,
    notebook.createdAt,
    notebook.updatedAt,
  )));
};

type WorkspaceE2eeKeyringRow = {
  workspace_id: string;
  key_id: string;
  revision: number;
  kdf_algorithm: string;
  kdf_salt: string;
  kdf_iterations: number;
  wrapped_master_key: string;
  master_key_iv: string;
  created_at: string;
  updated_at: string;
};

const mapKeyringRow = (row: WorkspaceE2eeKeyringRow): WorkspaceE2eeKeyring => ({
  keyId: row.key_id,
  revision: row.revision,
  kdfAlgorithm: row.kdf_algorithm as typeof WORKSPACE_E2EE_KDF_ALGORITHM,
  kdfSalt: row.kdf_salt,
  kdfIterations: row.kdf_iterations,
  wrappedMasterKey: row.wrapped_master_key,
  masterKeyIv: row.master_key_iv,
  createdAt: row.created_at,
  updatedAt: row.updated_at,
});

const readWorkspaceKeyringRow = (db: DatabaseAdapter, workspaceId: string) =>
  db
    .prepare(
      `SELECT workspace_id, key_id, revision, kdf_algorithm, kdf_salt, kdf_iterations,
              wrapped_master_key, master_key_iv, created_at, updated_at
       FROM workspace_e2ee_keyrings
       WHERE workspace_id = ?`,
    )
    .bind(workspaceId)
    .first<WorkspaceE2eeKeyringRow>();

export const restoreJsonE2eeKeyring = async (
  db: DatabaseAdapter,
  workspaceId: string,
  input: WorkspaceE2eeKeyring,
): Promise<WorkspaceE2eeKeyring> => {
  const keyring = WorkspaceE2eeKeyringSchema.parse(input);
  let existing = await readWorkspaceKeyringRow(db, workspaceId);

  if (!existing) {
    const inserted = await db
      .prepare(
        `INSERT OR IGNORE INTO workspace_e2ee_keyrings (
           workspace_id, key_id, revision, kdf_algorithm, kdf_salt, kdf_iterations,
           wrapped_master_key, master_key_iv, created_at, updated_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        workspaceId,
        keyring.keyId,
        keyring.revision,
        keyring.kdfAlgorithm,
        keyring.kdfSalt,
        keyring.kdfIterations,
        keyring.wrappedMasterKey,
        keyring.masterKeyIv,
        keyring.createdAt,
        keyring.updatedAt,
      )
      .run();

    if (Number(inserted.meta.changes) > 0) {
      await audit(db, "user", null, "backup.restore_e2ee_keyring", "workspace", workspaceId, {
        keyId: keyring.keyId,
        revision: keyring.revision,
        mode: "insert",
      });
      const created = await readWorkspaceKeyringRow(db, workspaceId);
      if (!created) {
        throw new Error("Restored encryption keyring could not be read.");
      }
      return mapKeyringRow(created);
    }

    existing = await readWorkspaceKeyringRow(db, workspaceId);
    if (!existing) {
      throw new Error("Workspace encryption keyring restore failed.");
    }
  }

  if (existing.key_id !== keyring.keyId) {
    throw new AppError(
      "keyring_key_id_mismatch",
      "Target workspace already has an encryption keyring with a different keyId.",
      409,
    );
  }

  if (keyring.revision > existing.revision) {
    const updated = await db
      .prepare(
        `UPDATE workspace_e2ee_keyrings
         SET revision = ?, kdf_algorithm = ?, kdf_salt = ?, kdf_iterations = ?,
             wrapped_master_key = ?, master_key_iv = ?, updated_at = ?
         WHERE workspace_id = ? AND key_id = ? AND revision < ?`,
      )
      .bind(
        keyring.revision,
        keyring.kdfAlgorithm,
        keyring.kdfSalt,
        keyring.kdfIterations,
        keyring.wrappedMasterKey,
        keyring.masterKeyIv,
        keyring.updatedAt,
        workspaceId,
        keyring.keyId,
        keyring.revision,
      )
      .run();

    if (Number(updated.meta.changes) > 0) {
      await audit(db, "user", null, "backup.restore_e2ee_keyring", "workspace", workspaceId, {
        keyId: keyring.keyId,
        revision: keyring.revision,
        mode: "upgrade",
      });
    }
  }

  const latest = await readWorkspaceKeyringRow(db, workspaceId);
  if (!latest) {
    throw new Error("Workspace encryption keyring could not be read after restore.");
  }
  if (latest.key_id !== keyring.keyId) {
    throw new AppError(
      "keyring_key_id_mismatch",
      "Target workspace already has an encryption keyring with a different keyId.",
      409,
    );
  }
  return mapKeyringRow(latest);
};

export const restoreJsonMemos = async (
  db: DatabaseAdapter,
  workspaceId: string,
  backups: JsonBackupMemo[],
) => {
  await assertIdsAvailableInWorkspace(db, "memos", workspaceId, backups.map((backup) => backup.memo.id));
  await assertNotebookIdsInWorkspace(db, workspaceId, backups.map((backup) => backup.memo.notebookId));
  // Validate the whole page before writing, so an invalid note never leaves
  // the notes before it restored.
  if (backups.some((backup) => backup.revisions.some((revision) => revision.memoId !== backup.memo.id))) {
    throw new AppError("invalid_backup", "A backup revision belongs to a different memo.", 400);
  }

  const targetKeyring = await readWorkspaceKeyringRow(db, workspaceId);
  const encryptedMemoIds: string[] = [];
  for (const backup of backups) {
    const parsedJson = parseBackupDoc(backup.memo.contentJson);
    const contentMarkdown = backup.memo.contentMarkdown || docToMarkdown(parsedJson);
    if (hasEncryptedNoteMarker(contentMarkdown)) {
      const envelope = parseEncryptedNoteEnvelope(contentMarkdown);
      if (!envelope) {
        throw new AppError(
          "invalid_encrypted_memo",
          "Encrypted note content must be a single valid edgeever-encrypted-note envelope.",
          400,
        );
      }
      if (backup.resources.length > 0) {
        throw new AppError(
          "encrypted_memo_resources_forbidden",
          "Encrypted notes cannot be restored with images or attachments.",
          409,
        );
      }
      if (targetKeyring && envelope.keyId !== targetKeyring.key_id) {
        throw new AppError(
          "keyring_key_id_mismatch",
          "Encrypted note keyId does not match the target workspace encryption keyring.",
          409,
        );
      }
      encryptedMemoIds.push(backup.memo.id);
    }

    for (const revision of backup.revisions) {
      const parsedRevJson = parseBackupDoc(revision.contentJson);
      const revMarkdown = revision.contentMarkdown || docToMarkdown(parsedRevJson);
      if (hasEncryptedNoteMarker(revMarkdown)) {
        const revEnvelope = parseEncryptedNoteEnvelope(revMarkdown);
        if (!revEnvelope) {
          throw new AppError(
            "invalid_encrypted_memo",
            "Encrypted note revision contains an invalid envelope.",
            400,
          );
        }
        if (targetKeyring && revEnvelope.keyId !== targetKeyring.key_id) {
          throw new AppError(
            "keyring_key_id_mismatch",
            "Encrypted note revision keyId does not match the target workspace encryption keyring.",
            409,
          );
        }
      }
    }
  }

  if (encryptedMemoIds.length > 0) {
    const placeholders = encryptedMemoIds.map(() => "?").join(", ");
    const existingResource = await db
      .prepare(
        `SELECT memo_id FROM resources
         WHERE is_deleted = 0 AND memo_id IN (${placeholders})
         LIMIT 1`,
      )
      .bind(...encryptedMemoIds)
      .first<{ memo_id: string }>();
    if (existingResource) {
      throw new AppError(
        "encrypted_memo_resources_forbidden",
        "Encrypted notes cannot be restored over a note with existing attachments.",
        409,
      );
    }
  }

  const revisionOwners = new Map<string, string>();
  const revisionConflict = () => new AppError("backup_revision_id_conflict", "A backup revision ID is already used by another memo.", 409);
  for (const backup of backups) {
    for (const revision of backup.revisions) {
      const owner = revisionOwners.get(revision.id);
      if (owner && owner !== backup.memo.id) throw revisionConflict();
      revisionOwners.set(revision.id, backup.memo.id);
    }
  }
  const revisionIds = [...revisionOwners.keys()];
  for (let index = 0; index < revisionIds.length; index += 50) {
    const ids = revisionIds.slice(index, index + 50);
    const existing = await db.prepare(
      `SELECT id, memo_id FROM memo_revisions WHERE id IN (${ids.map(() => "?").join(", ")})`,
    ).bind(...ids).all<{ id: string; memo_id: string }>();
    if (existing.results.some((row) => revisionOwners.get(row.id) !== row.memo_id)) throw revisionConflict();
  }

  for (const backup of backups) {
    const memo = backup.memo;
    const parsedJson = parseBackupDoc(memo.contentJson);
    const contentMarkdown = memo.contentMarkdown || docToMarkdown(parsedJson);
    const isEncrypted = hasEncryptedNoteMarker(contentMarkdown);
    if (isEncrypted && !parseEncryptedNoteEnvelope(contentMarkdown)) {
      throw new AppError(
        "invalid_encrypted_memo",
        "Encrypted note content must be a single valid edgeever-encrypted-note envelope.",
        400,
      );
    }
    const contentJson = isEncrypted ? emptyDoc() : parsedJson;
    const contentText = isEncrypted ? "" : docToText(contentJson);
    const excerpt = isEncrypted ? "" : createExcerpt(contentText);
    const contentHash = await sha256(contentMarkdown + JSON.stringify(contentJson));
    const title = normalizeMemoTitle(memo.title);
    const tags = normalizeTags(memo.tags);

    await db.batch([
      db.prepare(
        `INSERT INTO memos (
          id, workspace_id, notebook_id, title, excerpt, tags_json, is_pinned, is_archived, is_deleted,
          source_memo_ids, merge_source_count, merged_into_memo_id,
          created_by, updated_by, created_at, updated_at, deleted_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, NULL, 'restore', 'restore', ?, ?, NULL)
        ON CONFLICT(id) DO UPDATE SET
          notebook_id = excluded.notebook_id,
          title = excluded.title,
          excerpt = excluded.excerpt,
          tags_json = excluded.tags_json,
          is_pinned = excluded.is_pinned,
          is_archived = excluded.is_archived,
          is_deleted = 0,
          source_memo_ids = excluded.source_memo_ids,
          merge_source_count = excluded.merge_source_count,
          merged_into_memo_id = NULL,
          updated_by = 'restore',
          updated_at = excluded.updated_at,
          deleted_at = NULL`,
      ).bind(
        memo.id,
        workspaceId,
        memo.notebookId,
        title,
        excerpt,
        JSON.stringify(tags),
        memo.isPinned ? 1 : 0,
        memo.isArchived ? 1 : 0,
        JSON.stringify(memo.sourceMemoIds),
        memo.mergeSourceCount,
        memo.createdAt,
        memo.updatedAt,
      ),
      db.prepare(
        `INSERT INTO memo_contents (
          memo_id, content_json, content_markdown, content_text, content_hash, revision, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(memo_id) DO UPDATE SET
          content_json = excluded.content_json,
          content_markdown = excluded.content_markdown,
          content_text = excluded.content_text,
          content_hash = excluded.content_hash,
          revision = excluded.revision,
          updated_at = excluded.updated_at`,
      ).bind(
        memo.id,
        JSON.stringify(contentJson),
        contentMarkdown,
        contentText,
        contentHash,
        memo.revision,
        memo.createdAt,
        memo.updatedAt,
      ),
      upsertMemoSearchDocumentStatement(db, memo.id, title, contentText, tags.join(" ")),
      db.prepare("DELETE FROM memo_revisions WHERE memo_id = ?").bind(memo.id),
      ...(isEncrypted
        ? [
            db.prepare(
              `DELETE FROM memo_share_slug_claims
               WHERE workspace_id = ?
                 AND slug IN (
                   SELECT slug FROM memo_shares
                   WHERE workspace_id = ? AND memo_id = ? AND slug IS NOT NULL
                 )`,
            ).bind(workspaceId, workspaceId, memo.id),
            db.prepare("DELETE FROM memo_shares WHERE workspace_id = ? AND memo_id = ?").bind(workspaceId, memo.id),
          ]
        : []),
    ]);

    for (let index = 0; index < backup.revisions.length; index += 50) {
      const statements = backup.revisions.slice(index, index + 50).map((revision) => {
        const parsedRevisionJson = parseBackupDoc(revision.contentJson);
        const revisionMarkdown = revision.contentMarkdown || docToMarkdown(parsedRevisionJson);
        const revisionEncrypted = hasEncryptedNoteMarker(revisionMarkdown);
        const revisionJson = revisionEncrypted ? emptyDoc() : parsedRevisionJson;
        const revisionText = revisionEncrypted ? "" : docToText(revisionJson);
        return db.prepare(
          `INSERT INTO memo_revisions (
            id, memo_id, revision, title, content_json, content_markdown,
            content_hash, created_by, created_at, tags_json, content_text
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        ).bind(
          revision.id,
          memo.id,
          revision.revision,
          normalizeMemoTitle(revision.title),
          JSON.stringify(revisionJson),
          revisionMarkdown,
          revision.contentHash || "",
          revision.createdBy,
          revision.createdAt,
          JSON.stringify(normalizeTags(revision.tags)),
          revisionText,
        );
      });
      await db.batch(statements);
    }
  }

  await audit(db, "user", null, "backup.restore", "backup", createId("restore"), {
    memoCount: backups.length,
  });
};
