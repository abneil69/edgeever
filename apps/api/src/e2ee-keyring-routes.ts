import {
  WORKSPACE_E2EE_KDF_ALGORITHM,
  WorkspaceE2eeKeyringUpsertSchema,
  type WorkspaceE2eeKeyring,
  type WorkspaceE2eeKeyringResponse,
} from "@edgeever/shared";
import { zValidator } from "@hono/zod-validator";
import type { Hono } from "hono";
import type { AppEnv, Bindings } from "./api-context";
import { audit } from "./audit";
import { isoNow } from "./entity-utils";
import { apiError } from "./http-errors";
import { getAuditActor, getWorkspaceId, requireUser } from "./request-auth";
import type { DatabaseAdapter } from "./storage-contract";

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

type E2eeKeyringRouteDependencies = {
  isDemoMode: (env: Bindings) => boolean;
};

const selectKeyringRow = (db: DatabaseAdapter, workspaceId: string) =>
  db
    .prepare(
      `SELECT workspace_id, key_id, revision, kdf_algorithm, kdf_salt, kdf_iterations,
              wrapped_master_key, master_key_iv, created_at, updated_at
       FROM workspace_e2ee_keyrings
       WHERE workspace_id = ?`,
    )
    .bind(workspaceId)
    .first<WorkspaceE2eeKeyringRow>();

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

export const registerE2eeKeyringRoutes = (
  app: Hono<AppEnv>,
  dependencies: E2eeKeyringRouteDependencies,
) => {
  app.get("/api/v1/e2ee/keyring", async (c) => {
    const denied = requireUser(c);
    if (denied) return denied;

    c.header("Cache-Control", "private, no-store");
    const row = await selectKeyringRow(c.env.storage.db, getWorkspaceId(c));
    if (!row) {
      const response: WorkspaceE2eeKeyringResponse = { configured: false, keyring: null };
      return c.json(response);
    }

    const response: WorkspaceE2eeKeyringResponse = {
      configured: true,
      keyring: mapKeyringRow(row),
    };
    return c.json(response);
  });

  app.put(
    "/api/v1/e2ee/keyring",
    zValidator("json", WorkspaceE2eeKeyringUpsertSchema),
    async (c) => {
      const denied = requireUser(c);
      if (denied) return denied;

      c.header("Cache-Control", "private, no-store");
      if (dependencies.isDemoMode(c.env)) {
        return apiError(
          c,
          "e2ee_keyring_demo_disabled",
          "Encryption keyring cannot be modified in demo mode.",
          403,
        );
      }

      const db = c.env.storage.db;
      const workspaceId = getWorkspaceId(c);
      const actor = getAuditActor(c);
      const input = c.req.valid("json");
      const now = isoNow();

      if (input.expectedRevision === undefined) {
        const inserted = await db
          .prepare(
            `INSERT OR IGNORE INTO workspace_e2ee_keyrings (
               workspace_id, key_id, revision, kdf_algorithm, kdf_salt, kdf_iterations,
               wrapped_master_key, master_key_iv, created_at, updated_at
             ) VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?)`,
          )
          .bind(
            workspaceId,
            input.keyId,
            input.kdfAlgorithm,
            input.kdfSalt,
            input.kdfIterations,
            input.wrappedMasterKey,
            input.masterKeyIv,
            now,
            now,
          )
          .run();

        if (Number(inserted.meta.changes) !== 1) {
          return apiError(
            c,
            "keyring_already_exists",
            "Workspace encryption keyring already exists. Pass expectedRevision to rotate the passphrase.",
            409,
          );
        }

        const created = await selectKeyringRow(db, workspaceId);
        if (!created) {
          throw new Error("Workspace encryption keyring was created but could not be read.");
        }
        await audit(db, actor.actorType, actor.actorId, "e2ee.keyring_create", "workspace", workspaceId, {
          keyId: created.key_id,
          revision: created.revision,
        });
        const response: WorkspaceE2eeKeyringResponse = {
          configured: true,
          keyring: mapKeyringRow(created),
        };
        return c.json(response, 201);
      }

      const existing = await selectKeyringRow(db, workspaceId);
      if (!existing) {
        return apiError(
          c,
          "keyring_not_configured",
          "Workspace encryption keyring has not been initialized.",
          409,
        );
      }
      if (existing.key_id !== input.keyId) {
        return apiError(
          c,
          "keyring_key_id_mismatch",
          "Keyring keyId cannot be replaced during passphrase rotation; re-wrap the existing workspace master key.",
          409,
        );
      }

      const updated = await db
        .prepare(
          `UPDATE workspace_e2ee_keyrings
           SET kdf_algorithm = ?, kdf_salt = ?, kdf_iterations = ?,
               wrapped_master_key = ?, master_key_iv = ?,
               revision = revision + 1, updated_at = ?
           WHERE workspace_id = ? AND key_id = ? AND revision = ?`,
        )
        .bind(
          input.kdfAlgorithm,
          input.kdfSalt,
          input.kdfIterations,
          input.wrappedMasterKey,
          input.masterKeyIv,
          now,
          workspaceId,
          input.keyId,
          input.expectedRevision,
        )
        .run();

      if (Number(updated.meta.changes) !== 1) {
        const latest = await selectKeyringRow(db, workspaceId);
        if (latest && latest.key_id !== input.keyId) {
          return apiError(
            c,
            "keyring_key_id_mismatch",
            "Keyring keyId cannot be replaced during passphrase rotation; re-wrap the existing workspace master key.",
            409,
          );
        }
        return c.json(
          {
            error: {
              code: "keyring_revision_conflict",
              message: "Workspace encryption keyring was updated elsewhere. Reload and retry.",
              details: {
                expectedRevision: input.expectedRevision,
                currentRevision: latest?.revision ?? null,
              },
            },
          },
          409,
        );
      }

      const row = await selectKeyringRow(db, workspaceId);
      if (!row) {
        throw new Error("Workspace encryption keyring was updated but could not be read.");
      }
      await audit(db, actor.actorType, actor.actorId, "e2ee.keyring_rotate", "workspace", workspaceId, {
        keyId: row.key_id,
        revision: row.revision,
      });
      const response: WorkspaceE2eeKeyringResponse = {
        configured: true,
        keyring: mapKeyringRow(row),
      };
      return c.json(response, 200);
    },
  );
};
