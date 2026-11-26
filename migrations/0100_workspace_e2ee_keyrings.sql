PRAGMA foreign_keys = ON;

CREATE TABLE workspace_e2ee_keyrings (
  workspace_id TEXT PRIMARY KEY,
  key_id TEXT NOT NULL,
  revision INTEGER NOT NULL DEFAULT 1,
  kdf_algorithm TEXT NOT NULL,
  kdf_salt TEXT NOT NULL,
  kdf_iterations INTEGER NOT NULL,
  wrapped_master_key TEXT NOT NULL,
  master_key_iv TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
    ON UPDATE CASCADE
    ON DELETE CASCADE
);

-- Keep triggers on one line for D1 compatibility (matching 0080_backup_revision.sql).
CREATE TRIGGER trg_backup_workspace_e2ee_keyrings_insert AFTER INSERT ON workspace_e2ee_keyrings BEGIN UPDATE workspaces SET backup_revision = backup_revision + 1 WHERE id IN (SELECT NEW.workspace_id); END;
CREATE TRIGGER trg_backup_workspace_e2ee_keyrings_update AFTER UPDATE ON workspace_e2ee_keyrings BEGIN UPDATE workspaces SET backup_revision = backup_revision + 1 WHERE id IN (SELECT OLD.workspace_id UNION SELECT NEW.workspace_id); END;
CREATE TRIGGER trg_backup_workspace_e2ee_keyrings_delete BEFORE DELETE ON workspace_e2ee_keyrings BEGIN UPDATE workspaces SET backup_revision = backup_revision + 1 WHERE id IN (SELECT OLD.workspace_id); END;
