import { afterEach, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { globSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Hono } from "hono";
import {
  createPosterDocument,
  decryptNoteContent,
  emptyDoc,
  encodeBase64,
  encryptNoteContent,
  hasEncryptedNoteMarker,
  initializeWorkspaceKeyring,
  rotateWorkspacePassphrase,
  serializePosterDocument,
  unlockWorkspaceMasterKey,
} from "@edgeever/shared";
import {
  createEdgeEverZip,
  parseEdgeEverZip,
  restoreEdgeEverZip,
  validateBackupRelationships,
} from "@edgeever/shared/backup-archive";
import { createSelfHostedStorageAdapter } from "./self-hosted-storage-adapter.ts";
import { registerE2eeKeyringRoutes } from "./e2ee-keyring-routes.ts";
import { registerBackupRoutes } from "./backup-routes.ts";
import {
  restoreJsonE2eeKeyring,
  restoreJsonMemos,
  restoreJsonNotebooks,
} from "./backup-service.ts";
import { sha256Bytes } from "./hash-utils.ts";
import {
  createMemoEditSession,
  createMemoRecord,
  deleteMemoRecord,
  deleteMemosRecord,
  emptyTrashMemosRecord,
  getMemoDetail,
  getMemoDetailRow,
  mapMemoDetail,
  mergeMemosRecord,
  moveMemosRecord,
  restoreMemoRecord,
  searchMemoSummaries,
  updateMemoRecord,
} from "./memo-service.ts";
import { registerMemoRoutes } from "./memo-routes.ts";
import { listMemos } from "./memo-list-service.ts";
import { listMemoRevisions, restoreMemoRevision } from "./memo-revision-service.ts";
import { duplicateMemoRecord } from "./memo-duplicate-service.ts";
import { registerResourceRoutes } from "./resource-routes.ts";
import {
  createAttachmentResource,
  createImageResource,
  getResourceRow,
  replaceResourceContent,
} from "./resource-service.ts";
import {
  abortResourceUpload,
  completeResourceUpload,
  initiateResourceRestoreUpload,
  initiateResourceUpload,
  uploadResourcePart,
} from "./resource-upload-service.ts";
import { registerMemoShareRoutes, registerPublicShareRoutes } from "./share-routes.ts";
import {
  registerNotebookShareRoutes,
  registerPublicNotebookShareRoutes,
} from "./notebook-share-routes.ts";
import { renderNotebookSitePage } from "./notebook-site-page.ts";
import { renderPublicMemoSharePage } from "./share-page.ts";
import { registerAiRoutes } from "./ai-routes.ts";
import { registerPluginCapabilityRoutes } from "./plugin-capability-routes.ts";
import { registerTemplateRoutes } from "./template-routes.ts";
import {
  checkDiscoveries,
  getDiscoverySettings,
  saveDiscoverySettings,
} from "./companion-discovery.ts";
import { companionUserContent } from "./companion-prepare.ts";
import { executeCompanionTurnTool, emptyCompanionAgentSession } from "./companion-agent-tools.ts";
import { executeWorkspaceTool } from "./mcp-tool-executor.ts";
import { clampNumber } from "./entity-utils.ts";
import { AppError } from "./app-error.ts";
import { apiError } from "./http-errors.ts";

const cleanups = [];
afterEach(() => {
  while (cleanups.length) cleanups.pop()();
});

const WORKSPACE_ID = "ws_e2ee";
const NOTEBOOK_ID = "nb_e2ee";
const USER_AUTH = {
  kind: "user",
  actorType: "user",
  actorId: "usr_owner",
  username: "owner",
  displayName: "Owner",
  scopes: ["read:notebooks", "write:notebooks", "read:memos", "write:memos", "read:resources", "write:resources", "read:tags", "write:tags"],
  workspaceId: WORKSPACE_ID,
  role: "owner",
};
const AGENT_AUTH = {
  kind: "agent",
  actorType: "agent",
  actorId: "tok_agent",
  username: "mcp-agent",
  displayName: null,
  scopes: ["read:notebooks", "write:notebooks", "read:memos", "write:memos", "read:resources", "write:resources", "read:tags", "write:tags"],
  workspaceId: WORKSPACE_ID,
  role: "member",
};

const setupFixture = (options = {}) => {
  const workspaceId = options.workspaceId ?? WORKSPACE_ID;
  const notebookId = options.notebookId ?? NOTEBOOK_ID;
  const sqlite = new Database(":memory:");
  const blobDir = join(tmpdir(), `edgeever-e2ee-test-${crypto.randomUUID()}`);
  cleanups.push(() => {
    sqlite.close();
    rmSync(blobDir, { recursive: true, force: true });
  });
  for (const file of globSync("migrations/*.sql").sort()) {
    sqlite.exec(readFileSync(file, "utf8"));
  }
  sqlite.exec(`
    INSERT INTO workspaces (id, name) VALUES ('${workspaceId}', 'E2EE Test');
    INSERT INTO users (id, username, display_name, password_hash)
      VALUES ('usr_owner', 'owner', 'Owner', 'hash');
    INSERT INTO notebooks (id, workspace_id, name, slug)
      VALUES ('${notebookId}', '${workspaceId}', 'Vault', 'vault');
  `);

  const storage = createSelfHostedStorageAdapter(sqlite, blobDir);
  const env = {
    storage,
    ...(options.demoMode ? { EDGE_EVER_DEMO_MODE: "true" } : {}),
  };
  let activeAuth = options.auth ?? { ...USER_AUTH, workspaceId };

  const app = new Hono();
  app.onError((error, c) => {
    if (error instanceof AppError) return apiError(c, error.code, error.message, error.status);
    throw error;
  });
  app.use("/api/v1/*", async (c, next) => {
    c.set("auth", activeAuth);
    await next();
  });

  const isDemoMode = (e) => e.EDGE_EVER_DEMO_MODE === "true";
  registerE2eeKeyringRoutes(app, { isDemoMode });
  registerBackupRoutes(app, {
    clampNumber,
    getMemoDetail,
    mapMemoDetail,
    restoreJsonMemos,
    restoreJsonNotebooks,
    restoreJsonE2eeKeyring,
    isDemoMode,
    sha256Bytes,
    initiateResourceRestoreUpload,
  });
  registerResourceRoutes(app, {
    clampNumber,
    createAttachmentResource,
    createImageResource,
    getMemoDetail,
    getResourceRow,
    initiateResourceUpload,
    uploadResourcePart,
    completeResourceUpload,
    abortResourceUpload,
    replaceResourceContent,
  });
  registerMemoShareRoutes(app);
  registerPublicShareRoutes(app);
  registerNotebookShareRoutes(app);
  registerPublicNotebookShareRoutes(app);
  registerAiRoutes(app, { isDemoMode });
  registerPluginCapabilityRoutes(app, { isDemoMode });
  registerTemplateRoutes(app, { createMemoRecord, getMemoDetail });
  registerMemoRoutes(app, {
    clampNumber,
    createImageResource,
    createMemo: createMemoRecord,
    createMemoEditSession,
    deleteMemo: deleteMemoRecord,
    deleteMemos: deleteMemosRecord,
    emptyTrash: emptyTrashMemosRecord,
    getMemoDetail,
    listMemos,
    listMemoRevisions: (...args) => listMemoRevisions(...args, getMemoDetail, false),
    duplicateMemo: duplicateMemoRecord,
    mergeMemos: mergeMemosRecord,
    moveMemos: moveMemosRecord,
    restoreMemo: restoreMemoRecord,
    restoreMemoRevision: (db, wsId, memoId, revId, actor, actorLabel, options) =>
      restoreMemoRevision(db, wsId, memoId, revId, actor, actorLabel, { getMemoDetail, getMemoDetailRow }, options),
    updateMemo: updateMemoRecord,
  });

  const req = (path, init) =>
    app.fetch(new Request(`http://edgeever.test${path}`, init), env);

  const contextFor = (auth = activeAuth) => ({
    env,
    req: { url: "http://edgeever.test/api/v1/mcp" },
    get: (key) => (key === "auth" ? auth : undefined),
  });

  return {
    sqlite,
    db: storage.db,
    env,
    app,
    req,
    contextFor,
    setAuth: (next) => {
      activeAuth = next;
    },
  };
};

// Fast valid envelope fixture for server-side tests (no need to burn 600k PBKDF2 in every test).
const makeValidEnvelope = async (memoId, plaintext = "Secret body text", keyId = "ek_0123456789abcdef") => {
  const masterKey = new Uint8Array(32).fill(7);
  const encrypted = await encryptNoteContent({
    memoId,
    keyId,
    masterKey,
    plaintextMarkdown: plaintext,
  });
  return { ...encrypted, masterKey };
};

describe("E2EE workspace keyring API", () => {
  test("supports initialize, optimistic-locked rotation, rejects keyId replacement, API tokens, and demo mode", async () => {
    const f = setupFixture();

    // Unconfigured initially.
    let res = await f.req("/api/v1/e2ee/keyring");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ configured: false, keyring: null });

    // Initialize via real PBKDF2-600k + AES-GCM keyring (portable, no workspaceId).
    const initialized = await initializeWorkspaceKeyring({
      passphrase: "initial-passphrase",
    });

    // API token is forbidden on GET and PUT.
    f.setAuth(AGENT_AUTH);
    expect((await f.req("/api/v1/e2ee/keyring")).status).toBe(403);
    expect(
      (
        await f.req("/api/v1/e2ee/keyring", {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(initialized.keyring),
        })
      ).status,
    ).toBe(403);
    f.setAuth(USER_AUTH);

    // First PUT creates revision 1.
    res = await f.req("/api/v1/e2ee/keyring", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(initialized.keyring),
    });
    expect(res.status).toBe(201);
    const createdBody = await res.json();
    expect(createdBody.configured).toBe(true);
    expect(createdBody.keyring.keyId).toBe(initialized.keyring.keyId);
    expect(createdBody.keyring.revision).toBe(1);

    // Re-creating without expectedRevision fails with 409.
    res = await f.req("/api/v1/e2ee/keyring", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(initialized.keyring),
    });
    expect(res.status).toBe(409);
    expect((await res.json()).error.code).toBe("keyring_already_exists");

    // Replacing keyId during rotation is rejected with 409.
    res = await f.req("/api/v1/e2ee/keyring", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...initialized.keyring,
        expectedRevision: 1,
        keyId: "ek_different_key_id_1234",
      }),
    });
    expect(res.status).toBe(409);
    expect((await res.json()).error.code).toBe("keyring_key_id_mismatch");

    // Valid passphrase rotation increments revision while preserving keyId.
    const rotated = await rotateWorkspacePassphrase({
      currentPassphrase: "initial-passphrase",
      newPassphrase: "rotated-passphrase",
      currentKeyring: createdBody.keyring,
    });
    res = await f.req("/api/v1/e2ee/keyring", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(rotated.keyring),
    });
    expect(res.status).toBe(200);
    const rotatedBody = await res.json();
    expect(rotatedBody.keyring.keyId).toBe(createdBody.keyring.keyId);
    expect(rotatedBody.keyring.revision).toBe(2);

    // Stale expectedRevision returns 409 conflict.
    res = await f.req("/api/v1/e2ee/keyring", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(rotated.keyring),
    });
    expect(res.status).toBe(409);
    expect((await res.json()).error.code).toBe("keyring_revision_conflict");

    // Demo mode rejects keyring writes.
    const demo = setupFixture({ demoMode: true });
    res = await demo.req("/api/v1/e2ee/keyring", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(initialized.keyring),
    });
    expect(res.status).toBe(403);
    expect((await res.json()).error.code).toBe("e2ee_keyring_demo_disabled");
  });
});

describe("E2EE memo lifecycle, FTS5 isolation, and trace cleanup", () => {
  test("validates envelopes, isolates FTS5 to title/tags, and wipes revisions and shares on plaintext->encrypted", async () => {
    const f = setupFixture();
    const actor = { actorType: "user", actorId: "usr_owner" };

    // Creating a memo with a fence-prefixed malformed envelope fails with 400.
    await expect(
      createMemoRecord(
        f.db,
        WORKSPACE_ID,
        {
          notebookId: NOTEBOOK_ID,
          title: "Bad Envelope",
          contentMarkdown: "```edgeever-encrypted-note\n{\"v\":1}\n```",
        },
        actor,
        "user:usr_owner",
      ),
    ).rejects.toMatchObject({ code: "invalid_encrypted_memo", status: 400 });

    // Ordinary plaintext note quoting an encrypted fence mid-body saves & indexes normally.
    const docWithFence = await createMemoRecord(
      f.db,
      WORKSPACE_ID,
      {
        notebookId: NOTEBOOK_ID,
        title: "E2EE Spec Guide",
        contentMarkdown: "Prefix with FenceGuideToken\n```edgeever-encrypted-note\n{\"v\":1}\n```",
      },
      actor,
      "user:usr_owner",
    );
    expect(docWithFence.encrypted).toBeFalsy();
    expect(docWithFence.excerpt).toContain("FenceGuideToken");
    const foundFenceDoc = await listMemos(f.db, { workspaceId: WORKSPACE_ID, query: "FenceGuideToken" });
    expect(foundFenceDoc.memos.map((m) => m.id)).toEqual([docWithFence.id]);
    await deleteMemoRecord(f.env, WORKSPACE_ID, docWithFence.id, false, actor);

    // Create a plaintext note with >=200 chars, edit it to produce a revision, and create a public share with slug.
    const longPlaintext = `TopSecretKeywordInBody ${"x".repeat(250)}`;
    const plainMemo = await createMemoRecord(
      f.db,
      WORKSPACE_ID,
      {
        notebookId: NOTEBOOK_ID,
        title: "Quarterly Tax Plan",
        contentMarkdown: longPlaintext,
        tags: ["finance", "private"],
      },
      actor,
      "user:usr_owner",
    );

    const updatedPlain = await updateMemoRecord(
      f.db,
      WORKSPACE_ID,
      plainMemo.id,
      {
        contentMarkdown: `${longPlaintext}\nSecond draft with SecretDraftTerm`,
      },
      actor,
      "user:usr_owner",
    );
    expect("memo" in updatedPlain).toBe(true);

    // Verify revision exists before encryption.
    const revsBefore = await listMemoRevisions(f.db, WORKSPACE_ID, plainMemo.id, 50, getMemoDetail);
    expect(revsBefore.length).toBe(1);

    // Create public share and assign custom slug.
    const shareCreateRes = await f.req(`/api/v1/memos/${plainMemo.id}/share`, { method: "POST" });
    expect(shareCreateRes.status).toBe(201);
    const { share } = await shareCreateRes.json();
    const slugRes = await f.req(`/api/v1/memos/${plainMemo.id}/share`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ slug: "tax-plan-2026" }),
    });
    expect(slugRes.status).toBe(200);

    // Convert plaintext note to encrypted note AND change title simultaneously (tests isSuspiciousMemoOverwrite bypass).
    const encrypted = await makeValidEnvelope(plainMemo.id, "Sensitive encrypted payload");
    const convertResult = await updateMemoRecord(
      f.db,
      WORKSPACE_ID,
      plainMemo.id,
      {
        title: "Locked Vault Entry",
        contentMarkdown: encrypted.markdown,
      },
      actor,
      "user:usr_owner",
    );
    expect("memo" in convertResult).toBe(true);
    expect(convertResult.memo.encrypted).toBe(true);
    expect(convertResult.memo.excerpt).toBe("");
    expect(convertResult.memo.contentText).toBe("");
    expect(convertResult.memo.contentJson).toEqual(emptyDoc());

    // All old plaintext revisions MUST be physically wiped.
    const revsAfter = f.sqlite
      .prepare("SELECT COUNT(*) AS count FROM memo_revisions WHERE memo_id = ?")
      .get(plainMemo.id);
    expect(revsAfter.count).toBe(0);

    // Public share and slug claim MUST be physically wiped.
    const sharesAfter = f.sqlite
      .prepare("SELECT COUNT(*) AS count FROM memo_shares WHERE memo_id = ?")
      .get(plainMemo.id);
    expect(sharesAfter.count).toBe(0);
    const slugClaimsAfter = f.sqlite
      .prepare("SELECT COUNT(*) AS count FROM memo_share_slug_claims WHERE slug = 'tax-plan-2026'")
      .get();
    expect(slugClaimsAfter.count).toBe(0);
    expect((await f.req(`/api/public/shares/${share.token}`)).status).toBe(404);
    expect((await f.req("/api/public/shares/tax-plan-2026")).status).toBe(404);

    // List summary flags encrypted: true and keeps excerpt empty.
    const listed = await listMemos(f.db, { workspaceId: WORKSPACE_ID });
    expect(listed.memos).toHaveLength(1);
    expect(listed.memos[0].encrypted).toBe(true);
    expect(listed.memos[0].excerpt).toBe("");

    // FTS5 search matches title and tags, NEVER body plaintext or ciphertext fields.
    const byTitle = await listMemos(f.db, { workspaceId: WORKSPACE_ID, query: "Locked Vault" });
    expect(byTitle.memos.map((m) => m.id)).toEqual([plainMemo.id]);

    const byTag = await searchMemoSummaries(f.db, { workspaceId: WORKSPACE_ID, query: "finance", limit: 10 });
    expect(byTag.map((m) => m.id)).toEqual([plainMemo.id]);
    expect(byTag[0].encrypted).toBe(true);
    expect(byTag[0].excerpt).toBe("");
    expect(byTag[0].snippet).toBeUndefined();

    const byOldPlaintext = await listMemos(f.db, { workspaceId: WORKSPACE_ID, query: "TopSecretKeywordInBody" });
    expect(byOldPlaintext.memos).toHaveLength(0);

    const byCiphertextMarker = await listMemos(f.db, { workspaceId: WORKSPACE_ID, query: "A256GCM" });
    expect(byCiphertextMarker.memos).toHaveLength(0);

    // Subsequent encrypted edit generates a ciphertext revision snapshot, and restoring it keeps excerpt/content_text empty.
    const encryptedV2 = await makeValidEnvelope(plainMemo.id, "Updated encrypted payload");
    const editEncrypted = await updateMemoRecord(
      f.db,
      WORKSPACE_ID,
      plainMemo.id,
      { contentMarkdown: encryptedV2.markdown },
      actor,
      "user:usr_owner",
    );
    expect("memo" in editEncrypted).toBe(true);
    const encRevs = await listMemoRevisions(f.db, WORKSPACE_ID, plainMemo.id, 50, getMemoDetail);
    expect(encRevs).toHaveLength(1);
    expect(encRevs[0].contentText).toBe("");

    const restored = await restoreMemoRevision(
      f.db,
      WORKSPACE_ID,
      plainMemo.id,
      encRevs[0].id,
      actor,
      "user:usr_owner",
      { getMemoDetail, getMemoDetailRow },
    );
    expect(restored.encrypted).toBe(true);
    expect(restored.excerpt).toBe("");
    expect(restored.contentText).toBe("");

    // Corrupted update to encrypted note is rejected with 400.
    const badUpdate = await updateMemoRecord(
      f.db,
      WORKSPACE_ID,
      plainMemo.id,
      { contentMarkdown: "```edgeever-encrypted-note\nnot-json\n```" },
      actor,
      "user:usr_owner",
    );
    expect(badUpdate.error).toBe("invalid_encrypted_memo");
    expect(badUpdate.status).toBe(400);

    // Server-side duplicate and merge reject encrypted memos.
    await expect(
      duplicateMemoRecord(f.contextFor(), plainMemo.id, {}, actor, "user:usr_owner"),
    ).rejects.toMatchObject({ code: "encrypted_memo_duplicate_forbidden", status: 409 });

    const otherPlain = await createMemoRecord(
      f.db,
      WORKSPACE_ID,
      { notebookId: NOTEBOOK_ID, title: "Plain Note", contentMarkdown: "Hello" },
      actor,
      "user:usr_owner",
    );
    await expect(
      mergeMemosRecord(f.db, WORKSPACE_ID, { memoIds: [plainMemo.id, otherPlain.id] }, actor, "user:usr_owner"),
    ).rejects.toMatchObject({ code: "encrypted_memo_merge_forbidden", status: 409 });
  });

  test("rejects encrypting memos with attachments or structured notes, and blocks attaching resources or sharing encrypted memos", async () => {
    const f = setupFixture();
    const actor = { actorType: "user", actorId: "usr_owner" };

    // 1. Plaintext memo with resource cannot be converted to encrypted.
    const memoWithFile = await createMemoRecord(
      f.db,
      WORKSPACE_ID,
      { notebookId: NOTEBOOK_ID, title: "With Attachment", contentMarkdown: "See file" },
      actor,
      "user:usr_owner",
    );
    const pngBytes = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    await createImageResource(f.contextFor(), {
      memoId: memoWithFile.id,
      filename: "photo.png",
      mimeType: "image/png",
      bytes: pngBytes,
      actor,
      source: "upload",
    });

    const encForFileMemo = await makeValidEnvelope(memoWithFile.id, "Try encrypt");
    const blockedEncrypt = await updateMemoRecord(
      f.db,
      WORKSPACE_ID,
      memoWithFile.id,
      { contentMarkdown: encForFileMemo.markdown },
      actor,
      "user:usr_owner",
    );
    expect(blockedEncrypt.error).toBe("encrypted_memo_resources_forbidden");
    expect(blockedEncrypt.status).toBe(409);

    // 2. Structured note (poster) cannot be converted to encrypted.
    const posterMemo = await createMemoRecord(
      f.db,
      WORKSPACE_ID,
      {
        notebookId: NOTEBOOK_ID,
        title: "Poster",
        contentMarkdown: serializePosterDocument(createPosterDocument("Hi", "Sub")),
      },
      actor,
      "user:usr_owner",
    );
    const encForPoster = await makeValidEnvelope(posterMemo.id, "Try encrypt poster");
    const blockedPoster = await updateMemoRecord(
      f.db,
      WORKSPACE_ID,
      posterMemo.id,
      { contentMarkdown: encForPoster.markdown },
      actor,
      "user:usr_owner",
    );
    expect(blockedPoster.error).toBe("encrypted_memo_structured_forbidden");
    expect(blockedPoster.status).toBe(409);

    // 3. Encrypted memo rejects resource uploads (legacy & multipart) and public share creation.
    const encMemo = await createMemoRecord(
      f.db,
      WORKSPACE_ID,
      { notebookId: NOTEBOOK_ID, title: "Encrypted Note", contentMarkdown: "temp" },
      actor,
      "user:usr_owner",
    );
    const envelope = await makeValidEnvelope(encMemo.id, "Private secret");
    await updateMemoRecord(
      f.db,
      WORKSPACE_ID,
      encMemo.id,
      { contentMarkdown: envelope.markdown },
      actor,
      "user:usr_owner",
    );

    const form = new FormData();
    form.set("file", new File([pngBytes], "secret.png", { type: "image/png" }));
    const uploadRes = await f.req(`/api/v1/memos/${encMemo.id}/resources`, {
      method: "POST",
      body: form,
    });
    expect(uploadRes.status).toBe(409);
    expect((await uploadRes.json()).error.code).toBe("encrypted_memo_resources_forbidden");

    const multipartRes = await f.req(`/api/v1/memos/${encMemo.id}/resource-uploads`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ filename: "big.pdf", mimeType: "application/pdf", byteSize: 1024 }),
    });
    expect(multipartRes.status).toBe(409);
    expect((await multipartRes.json()).error.code).toBe("encrypted_memo_resources_forbidden");

    const shareRes = await f.req(`/api/v1/memos/${encMemo.id}/share`, { method: "POST" });
    expect(shareRes.status).toBe(409);
    expect((await shareRes.json()).error.code).toBe("encrypted_memo_share_forbidden");

    // 4. Template routes reject encrypted memos/envelopes.
    const tplFromMemo = await f.req("/api/v1/templates", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "Bad Template", memoId: encMemo.id }),
    });
    expect(tplFromMemo.status).toBe(409);
    expect((await tplFromMemo.json()).error.code).toBe("encrypted_memo_forbidden");

    // 5. AI routes reject encrypted envelopes.
    const aiGenRes = await f.req("/api/v1/ai/generate/prepare", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        action: "summarize",
        title: "Encrypted",
        contentMarkdown: envelope.markdown,
      }),
    });
    expect(aiGenRes.status).toBe(409);
    expect((await aiGenRes.json()).error.code).toBe("encrypted_memo_ai_forbidden");

    const aiTagRes = await f.req("/api/v1/ai/tag-suggestions/prepare", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        title: "Encrypted",
        contentMarkdown: envelope.markdown,
      }),
    });
    expect(aiTagRes.status).toBe(409);
    expect((await aiTagRes.json()).error.code).toBe("encrypted_memo_ai_forbidden");

    const pluginAiRes = await f.req("/api/v1/plugins/ai/generate/prepare", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        system: "Summarize the note",
        prompt: envelope.markdown,
      }),
    });
    expect(pluginAiRes.status).toBe(409);
    expect((await pluginAiRes.json()).error.code).toBe("encrypted_memo_ai_forbidden");

    // 6. POST /api/v1/memos/with-image rejects encrypted note marker.
    const withImageForm = new FormData();
    withImageForm.set("notebookId", NOTEBOOK_ID);
    withImageForm.set("title", "Encrypted with image");
    withImageForm.set("contentMarkdown", `${envelope.markdown}\nEDGEVERRESOURCEID`);
    withImageForm.set("file", new File([pngBytes], "img.png", { type: "image/png" }));
    const withImageRes = await f.req("/api/v1/memos/with-image", {
      method: "POST",
      body: withImageForm,
    });
    expect(withImageRes.status).toBe(409);
    expect((await withImageRes.json()).error.code).toBe("encrypted_memo_resources_forbidden");

    // 7. Pending resource binding via MCP update_memo rejects encrypted memo.
    f.sqlite
      .prepare(
        `INSERT INTO pending_resources (
           id, workspace_id, token_hash, state, kind, mime_type, filename, byte_size, object_key,
           bucket_name, storage_config_id, sha256, metadata_json, actor_type, actor_id,
           created_at, upload_expires_at, uploaded_at, expires_at
         ) VALUES (
           'res_pending_1', ?, 'hash_1', 'uploaded', 'image', 'image/png', 'p.png', 8,
           'workspaces/ws_e2ee/uploads/res_pending_1.png', 'local', 'builtin', 'sha_1', '{}',
           'agent', 'tok_agent', '2026-11-26T00:00:00.000Z', '2099-01-01T00:00:00.000Z', '2026-11-26T00:00:00.000Z', '2099-01-01T00:00:00.000Z'
         )`,
      )
      .run(WORKSPACE_ID);
    await expect(
      executeWorkspaceTool(f.contextFor(AGENT_AUTH), AGENT_AUTH, "update_memo", {
        memoId: encMemo.id,
        resourceIds: ["res_pending_1"],
      }),
    ).rejects.toMatchObject({ code: "encrypted_memo_resources_forbidden", status: 409 });

    // 8. Active multipart resource_uploads blocks plaintext -> encrypted conversion.
    const memoWithPendingUpload = await createMemoRecord(
      f.db,
      WORKSPACE_ID,
      { notebookId: NOTEBOOK_ID, title: "Uploading", contentMarkdown: "Pending upload" },
      actor,
      "user:usr_owner",
    );
    await initiateResourceUpload(f.contextFor(), {
      memoId: memoWithPendingUpload.id,
      filename: "video.bin",
      mimeType: "application/octet-stream",
      byteSize: 2048,
    });
    const encForUploading = await makeValidEnvelope(memoWithPendingUpload.id, "Encrypt while uploading");
    const blockedByUpload = await updateMemoRecord(
      f.db,
      WORKSPACE_ID,
      memoWithPendingUpload.id,
      { contentMarkdown: encForUploading.markdown },
      actor,
      "user:usr_owner",
    );
    expect(blockedByUpload.error).toBe("encrypted_memo_resources_forbidden");
    expect(blockedByUpload.status).toBe(409);
  });
});

describe("E2EE public notebook site, Companion, and MCP isolation", () => {
  test("public notebook site excludes encrypted notes from listings, search, detail, preview, and SSR", async () => {
    const f = setupFixture();
    const actor = { actorType: "user", actorId: "usr_owner" };

    const publicMemo = await createMemoRecord(
      f.db,
      WORKSPACE_ID,
      { notebookId: NOTEBOOK_ID, title: "Public Guide", contentMarkdown: "Visible documentation" },
      actor,
      "user:usr_owner",
    );
    const encMemo = await createMemoRecord(
      f.db,
      WORKSPACE_ID,
      { notebookId: NOTEBOOK_ID, title: "Secret Journal", contentMarkdown: "temp" },
      actor,
      "user:usr_owner",
    );
    const envelope = await makeValidEnvelope(encMemo.id, "Super private journal");
    await updateMemoRecord(
      f.db,
      WORKSPACE_ID,
      encMemo.id,
      { contentMarkdown: envelope.markdown },
      actor,
      "user:usr_owner",
    );

    const nbShareRes = await f.req(`/api/v1/notebooks/${NOTEBOOK_ID}/share`, { method: "POST" });
    expect(nbShareRes.status).toBe(200);
    const { share } = await nbShareRes.json();

    // Public notebook list excludes encrypted memo.
    const siteRes = await f.req(`/api/public/notebook-shares/${share.token}`);
    expect(siteRes.status).toBe(200);
    const siteJson = await siteRes.json();
    expect(siteJson.share.memos.map((m) => m.id)).toEqual([publicMemo.id]);

    // Public detail and preview return 404 for encrypted memo.
    expect((await f.req(`/api/public/notebook-shares/${share.token}/memos/${encMemo.id}`)).status).toBe(404);
    expect((await f.req(`/api/public/notebook-shares/${share.token}/memos/${encMemo.id}/preview`)).status).toBe(404);

    // Public search does not return encrypted memo even by title.
    const searchRes = await f.req(`/api/public/notebook-shares/${share.token}/search?q=Secret`);
    expect(searchRes.status).toBe(200);
    expect((await searchRes.json()).memos).toEqual([]);

    // Owner site homepage cannot be set to an encrypted memo.
    const homeRes = await f.req(`/api/v1/notebooks/${NOTEBOOK_ID}/share/site`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ settings: { homeMemoId: encMemo.id } }),
    });
    expect(homeRes.status).toBe(400);

    // SSR notebook site page returns 404 for encrypted memo.
    const ssrPage = await renderNotebookSitePage(
      new Request(`http://edgeever.test/share/notebook/${share.token}/${encMemo.id}`),
      f.db,
      async () => new Response("<html><head><title>App</title></head><body><div id=\"root\"></div></body></html>"),
    );
    expect(ssrPage.status).toBe(404);

    // Defense-in-depth: even if a stale memo_shares row existed, renderPublicMemoSharePage refuses encrypted content.
    const staleToken = "z".repeat(43);
    f.sqlite
      .prepare("INSERT INTO memo_shares (id, memo_id, workspace_id, token) VALUES ('sh_stale', ?, ?, ?)")
      .run(encMemo.id, WORKSPACE_ID, staleToken);
    const shareMdRes = await renderPublicMemoSharePage(
      new Request(`http://edgeever.test/share/${staleToken}.md`),
      f.db,
      async () => new Response("<html></html>"),
    );
    expect(shareMdRes.status).toBe(404);
    expect((await f.req(`/api/public/shares/${staleToken}`)).status).toBe(404);
  });

  test("Companion discovery, prompt context, agent tools, and MCP isolate encrypted note bodies", async () => {
    const f = setupFixture();
    const actor = { actorType: "user", actorId: "usr_owner" };
    const scope = { workspaceId: WORKSPACE_ID, ownerId: "usr_owner" };

    const plainMemo = await createMemoRecord(
      f.db,
      WORKSPACE_ID,
      {
        notebookId: NOTEBOOK_ID,
        title: "Project Roadmap",
        contentMarkdown: "Milestone 1 and Milestone 2 details",
        createdAt: "2026-11-26T01:00:00.000Z",
        updatedAt: "2026-11-26T01:00:00.000Z",
      },
      actor,
      "user:usr_owner",
    );

    // Create an encrypted note that is NEWER than the plain note so it would otherwise be the discovery anchor.
    const encMemo = await createMemoRecord(
      f.db,
      WORKSPACE_ID,
      {
        notebookId: NOTEBOOK_ID,
        title: "Project Secrets",
        contentMarkdown: "temp",
        createdAt: "2026-11-26T02:00:00.000Z",
        updatedAt: "2026-11-26T02:00:00.000Z",
      },
      actor,
      "user:usr_owner",
    );
    const envelope = await makeValidEnvelope(encMemo.id, "Super confidential roadmap");
    await updateMemoRecord(
      f.db,
      WORKSPACE_ID,
      encMemo.id,
      { contentMarkdown: envelope.markdown, updatedAt: "2026-11-26T03:00:00.000Z" },
      actor,
      "user:usr_owner",
    );

    // 1. Companion discovery skips encrypted notes completely.
    const settings = await getDiscoverySettings(f.db, scope);
    await saveDiscoverySettings(f.db, scope, { enabled: true, version: settings.version });
    const seenCandidateIds = [];
    await checkDiscoveries(f.db, scope, {
      locale: "en-US",
      signal: new AbortController().signal,
      loadModel: async () => ({ modelId: "test-model" }),
      generate: async ({ candidates }) => {
        seenCandidateIds.push(...candidates.map((c) => c.id));
        return { suggestion: null };
      },
    });
    expect(seenCandidateIds).toEqual([plainMemo.id]);
    expect(seenCandidateIds).not.toContain(encMemo.id);

    // 2. Companion user content strips encrypted focus body and selection.
    const promptText = companionUserContent({
      id: "turn_1",
      threadId: "thread_1",
      message: "Summarize this note",
      useMemory: false,
      allowNotes: true,
      focus: {
        memoId: encMemo.id,
        title: "Project Secrets",
        contentMarkdown: envelope.markdown,
        selectionMarkdown: envelope.markdown,
      },
    });
    expect(promptText).not.toContain(envelope.envelope.ciphertext);
    expect(promptText).toContain("end-to-end encrypted");

    // 3. Companion get_memo returns redacted metadata and update_memo refuses modifying encrypted memo.
    const sources = [];
    const run = { tools: [], todos: [], questions: [], pause: { ask: false } };
    const session = emptyCompanionAgentSession();
    const companionRead = await executeCompanionTurnTool({
      db: f.db,
      scope,
      context: f.contextFor(USER_AUTH),
      input: { id: "turn_2", threadId: "thread_2", message: "Read note", useMemory: false, allowNotes: true },
      signal: new AbortController().signal,
      assertActive: async () => {},
      sources,
      run,
      session,
      name: "get_memo",
      toolInput: { memoId: encMemo.id },
    });
    expect(companionRead.encrypted).toBe(true);
    expect(companionRead.content).toBe("");
    expect(JSON.stringify(companionRead)).not.toContain(envelope.envelope.ciphertext);

    await expect(
      executeCompanionTurnTool({
        db: f.db,
        scope,
        context: f.contextFor(USER_AUTH),
        input: { id: "turn_2", threadId: "thread_2", message: "Overwrite note", useMemory: false, allowNotes: true },
        signal: new AbortController().signal,
        assertActive: async () => {},
        sources,
        run,
        session,
        name: "update_memo",
        toolInput: { memoId: encMemo.id, contentMarkdown: "Corrupted plaintext" },
      }),
    ).rejects.toMatchObject({ code: "encrypted_memo_forbidden", status: 409 });

    // 4. MCP tools reject reading/modifying encrypted note content and redact list_memos(includeContent: true).
    await expect(
      executeWorkspaceTool(f.contextFor(AGENT_AUTH), AGENT_AUTH, "get_memo", { memoId: encMemo.id }),
    ).rejects.toMatchObject({ code: "encrypted_memo_forbidden", status: 403 });

    await expect(
      executeWorkspaceTool(f.contextFor(AGENT_AUTH), AGENT_AUTH, "update_memo", {
        memoId: encMemo.id,
        contentMarkdown: "Agent overwrite attempt",
      }),
    ).rejects.toMatchObject({ code: "encrypted_memo_forbidden", status: 409 });

    await expect(
      executeWorkspaceTool(f.contextFor(AGENT_AUTH), AGENT_AUTH, "create_memo", {
        notebookId: NOTEBOOK_ID,
        title: "MCP Encrypted",
        contentMarkdown: envelope.markdown,
      }),
    ).rejects.toMatchObject({ code: "encrypted_memo_forbidden", status: 409 });

    const mcpListed = await executeWorkspaceTool(f.contextFor(AGENT_AUTH), AGENT_AUTH, "list_memos", {
      includeContent: true,
    });
    const encEntry = mcpListed.memos.find((m) => m.id === encMemo.id);
    expect(encEntry.encrypted).toBe(true);
    expect(encEntry.contentMarkdown).toBe("");
    expect(encEntry.excerpt).toBe("");
  });
});

describe("E2EE revision restore plaintext cleanup & cross-instance ZIP backup/restore", () => {
  test("restoring a decrypted note back to an older encrypted revision wipes intermediate plaintext snapshots and shares", async () => {
    const f = setupFixture();
    const actor = { actorType: "user", actorId: "usr_owner" };

    // 1. Start with an encrypted note.
    const memo = await createMemoRecord(
      f.db,
      WORKSPACE_ID,
      { notebookId: NOTEBOOK_ID, title: "Toggle Note", contentMarkdown: "initial" },
      actor,
      "user:usr_owner",
    );
    const encV1 = await makeValidEnvelope(memo.id, "Version 1 encrypted secret");
    await updateMemoRecord(
      f.db,
      WORKSPACE_ID,
      memo.id,
      { contentMarkdown: encV1.markdown, updatedAt: "2026-11-26T01:00:00.000Z" },
      actor,
      "user:usr_owner",
    );

    // Silent downgrade (encrypted -> plaintext without explicit e2eeTransition) MUST be rejected with 409.
    const silentDecrypt = await updateMemoRecord(
      f.db,
      WORKSPACE_ID,
      memo.id,
      { contentMarkdown: "Unintentional overwrite from legacy client", updatedAt: "2026-11-26T01:30:00.000Z" },
      actor,
      "user:usr_owner",
    );
    expect(silentDecrypt.error).toBe("encrypted_memo_decrypt_requires_intent");
    expect(silentDecrypt.status).toBe(409);

    // 2. Explicit decrypt to plaintext (snapshots encV1 into memo_revisions).
    const decryptedOk = await updateMemoRecord(
      f.db,
      WORKSPACE_ID,
      memo.id,
      {
        contentMarkdown: "Plaintext edit 1 with PlainSecretA\n```edgeever-encrypted-note\nexample\n```",
        e2eeTransition: "decrypt",
        updatedAt: "2026-11-26T02:00:00.000Z",
      },
      actor,
      "user:usr_owner",
    );
    expect("memo" in decryptedOk).toBe(true);
    expect(decryptedOk.memo.encrypted).toBeFalsy();

    // 3. Edit plaintext again >= 5 min later (snapshots Plaintext edit 1 into memo_revisions).
    await updateMemoRecord(
      f.db,
      WORKSPACE_ID,
      memo.id,
      { contentMarkdown: "Plaintext edit 2 with PlainSecretB", updatedAt: "2026-11-26T03:00:00.000Z" },
      actor,
      "user:usr_owner",
    );

    // Create a share while plaintext.
    const shareRes = await f.req(`/api/v1/memos/${memo.id}/share`, { method: "POST" });
    expect(shareRes.status).toBe(201);
    await f.req(`/api/v1/memos/${memo.id}/share`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ slug: "temp-plain-slug" }),
    });

    const revsBeforeRestore = await listMemoRevisions(f.db, WORKSPACE_ID, memo.id, 50, getMemoDetail);
    expect(revsBeforeRestore.length).toBe(2);
    const encryptedRevision = revsBeforeRestore.find((r) => hasEncryptedNoteMarker(r.contentMarkdown));
    expect(encryptedRevision).toBeDefined();

    // 4. Restore back to the encrypted revision.
    const restored = await restoreMemoRevision(
      f.db,
      WORKSPACE_ID,
      memo.id,
      encryptedRevision.id,
      actor,
      "user:usr_owner",
      { getMemoDetail, getMemoDetailRow },
    );
    expect(restored.encrypted).toBe(true);
    expect(restored.excerpt).toBe("");
    expect(restored.contentText).toBe("");

    // All plaintext snapshots must be physically removed; only the encrypted snapshot remains.
    const remainingRevs = f.sqlite
      .prepare("SELECT content_markdown FROM memo_revisions WHERE memo_id = ?")
      .all(memo.id);
    expect(remainingRevs.length).toBe(1);
    expect(remainingRevs[0].content_markdown).toContain("```edgeever-encrypted-note");
    expect(remainingRevs.some((r) => r.content_markdown.includes("PlainSecret"))).toBe(false);

    // Shares and slug claims must be removed as well.
    expect(f.sqlite.prepare("SELECT COUNT(*) AS count FROM memo_shares WHERE memo_id = ?").get(memo.id).count).toBe(0);
    expect(f.sqlite.prepare("SELECT COUNT(*) AS count FROM memo_share_slug_claims WHERE slug = 'temp-plain-slug'").get().count).toBe(0);

    // 5. Restoring a plaintext revision onto an encrypted note requires explicit e2eeTransition: "decrypt".
    f.sqlite
      .prepare(
        `INSERT INTO memo_revisions (id, memo_id, revision, title, content_json, content_markdown, content_hash, created_by, created_at, tags_json, content_text)
         VALUES ('rev_legacy_plain', ?, 0, 'Toggle Note', '{"type":"doc","content":[{"type":"paragraph"}]}', 'Legacy plaintext revision', 'hash_legacy', 'user:usr_owner', '2026-11-26T00:00:00.000Z', '[]', 'Legacy plaintext revision')`,
      )
      .run(memo.id);
    await expect(
      restoreMemoRevision(
        f.db,
        WORKSPACE_ID,
        memo.id,
        "rev_legacy_plain",
        actor,
        "user:usr_owner",
        { getMemoDetail, getMemoDetailRow },
      ),
    ).rejects.toMatchObject({ code: "encrypted_memo_decrypt_requires_intent", status: 409 });

    const explicitRestoredPlain = await restoreMemoRevision(
      f.db,
      WORKSPACE_ID,
      memo.id,
      "rev_legacy_plain",
      actor,
      "user:usr_owner",
      { getMemoDetail, getMemoDetailRow },
      { e2eeTransition: "decrypt" },
    );
    expect(explicitRestoredPlain.encrypted).toBeFalsy();
    expect(explicitRestoredPlain.contentMarkdown).toBe("Legacy plaintext revision");
  });

  test("exports from ws_source to ZIP and restores into a brand-new ws_target instance with full passphrase unlock and note decryption", async () => {
    const passphrase = "portable-cross-instance-passphrase";
    const secretText = "# Cross-Instance E2EE Note\n\nStill decrypts cleanly on a brand-new instance!";
    const actor = { actorType: "user", actorId: "usr_owner" };

    // --- Instance A (ws_source) ---
    const source = setupFixture({ workspaceId: "ws_source", notebookId: "nb_source" });
    const revBeforeKeyring = source.sqlite
      .prepare("SELECT backup_revision FROM workspaces WHERE id = 'ws_source'")
      .get().backup_revision;

    const initialized = await initializeWorkspaceKeyring({ passphrase });
    const putKeyringRes = await source.req("/api/v1/e2ee/keyring", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(initialized.keyring),
    });
    expect(putKeyringRes.status).toBe(201);
    const revAfterInsert = source.sqlite
      .prepare("SELECT backup_revision FROM workspaces WHERE id = 'ws_source'")
      .get().backup_revision;
    expect(revAfterInsert).toBe(revBeforeKeyring + 1);

    // Create an encrypted note and a plaintext note in ws_source.
    const secretMemoDraft = await createMemoRecord(
      source.db,
      "ws_source",
      { notebookId: "nb_source", title: "Portable Secret", contentMarkdown: "temp", tags: ["backup", "e2ee"] },
      actor,
      "user:usr_owner",
    );
    const encryptedNote = await encryptNoteContent({
      memoId: secretMemoDraft.id,
      keyId: initialized.keyring.keyId,
      masterKey: initialized.masterKey,
      plaintextMarkdown: secretText,
    });
    await updateMemoRecord(
      source.db,
      "ws_source",
      secretMemoDraft.id,
      { contentMarkdown: encryptedNote.markdown },
      actor,
      "user:usr_owner",
    );

    const plainMemo = await createMemoRecord(
      source.db,
      "ws_source",
      { notebookId: "nb_source", title: "Portable Plain", contentMarkdown: "Regular markdown content", tags: ["backup"] },
      actor,
      "user:usr_owner",
    );

    // Check /api/v1/backups/state includes hasE2eeKeyring: true.
    const stateRes = await source.req("/api/v1/backups/state");
    expect(stateRes.status).toBe(200);
    const state = await stateRes.json();
    expect(state.hasE2eeKeyring).toBe(true);

    // API token is rejected for kind=e2ee-keyring backup export.
    source.setAuth({ ...AGENT_AUTH, workspaceId: "ws_source" });
    const tokenKeyringExport = await source.req(
      `/api/v1/backups/data?${new URLSearchParams({
        kind: "e2ee-keyring",
        identity: state.identity,
        revision: state.backupRevision,
      })}`,
    );
    expect(tokenKeyringExport.status).toBe(403);
    source.setAuth({ ...USER_AUTH, workspaceId: "ws_source" });

    // Build real ZIP archive from ws_source backup endpoints.
    const zipBlob = await createEdgeEverZip(
      {
        listNotebooks: async () => {
          const res = await source.req(
            `/api/v1/backups/data?${new URLSearchParams({
              kind: "notebooks",
              identity: state.identity,
              revision: state.backupRevision,
            })}`,
          );
          expect(res.status).toBe(200);
          return res.json();
        },
        listPrompts: async () => ({ prompts: [] }),
        getE2eeKeyring: async () => {
          const res = await source.req(
            `/api/v1/backups/data?${new URLSearchParams({
              kind: "e2ee-keyring",
              identity: state.identity,
              revision: state.backupRevision,
            })}`,
          );
          expect(res.status).toBe(200);
          return res.json();
        },
        getPage: async () => {
          const res = await source.req(
            `/api/v1/backups/data?${new URLSearchParams({
              kind: "memos",
              identity: state.identity,
              revision: state.backupRevision,
            })}`,
          );
          expect(res.status).toBe(200);
          const data = await res.json();
          return { ...data, totalCount: state.counts.memos, nextOffset: null };
        },
      },
      { edgeeverVersion: "2.0.0", buildId: "phase1-test" },
    );

    const parsedZip = await parseEdgeEverZip(zipBlob);
    expect(parsedZip.e2eeKeyring?.keyId).toBe(initialized.keyring.keyId);
    expect(() => validateBackupRelationships(parsedZip)).not.toThrow();

    // --- Instance B (brand-new DB with completely different workspaceId: ws_target) ---
    const target = setupFixture({ workspaceId: "ws_target", notebookId: "nb_target_default" });

    // Demo mode rejects keyring restore; API token rejects keyring restore.
    const demoTarget = setupFixture({ workspaceId: "ws_demo", demoMode: true });
    const demoRestoreRes = await demoTarget.req("/api/v1/restores/json/e2ee-keyring", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ e2eeKeyring: parsedZip.e2eeKeyring }),
    });
    expect(demoRestoreRes.status).toBe(403);
    expect((await demoRestoreRes.json()).error.code).toBe("e2ee_keyring_demo_disabled");

    target.setAuth({ ...AGENT_AUTH, workspaceId: "ws_target" });
    const agentRestoreRes = await target.req("/api/v1/restores/json/e2ee-keyring", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ e2eeKeyring: parsedZip.e2eeKeyring }),
    });
    expect(agentRestoreRes.status).toBe(403);
    target.setAuth({ ...USER_AUTH, workspaceId: "ws_target" });

    // Restore full ZIP into ws_target via HTTP endpoints (keyring restored before memos).
    const restoreOrder = [];
    await restoreEdgeEverZip(parsedZip, {
      restorePrompts: async () => {},
      restoreNotebooks: async (notebooks) => {
        restoreOrder.push("notebooks");
        const res = await target.req("/api/v1/restores/json/notebooks", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ notebooks }),
        });
        expect(res.status).toBe(200);
      },
      restoreE2eeKeyring: async (e2eeKeyring) => {
        restoreOrder.push("e2ee-keyring");
        const res = await target.req("/api/v1/restores/json/e2ee-keyring", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ e2eeKeyring }),
        });
        expect(res.status).toBe(200);
      },
      restoreMemos: async (memos) => {
        restoreOrder.push("memos");
        const res = await target.req("/api/v1/restores/json/memos", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ memos }),
        });
        expect(res.status).toBe(200);
      },
      createResourceRestoreSink: async () => {
        throw new Error("No resources expected");
      },
    });
    expect(restoreOrder).toEqual(["notebooks", "e2ee-keyring", "memos"]);

    // Unlock WMK on ws_target with the original passphrase and decrypt the restored encrypted note!
    const targetKeyringRes = await target.req("/api/v1/e2ee/keyring");
    expect(targetKeyringRes.status).toBe(200);
    const targetKeyringBody = await targetKeyringRes.json();
    expect(targetKeyringBody.configured).toBe(true);
    expect(targetKeyringBody.keyring.keyId).toBe(initialized.keyring.keyId);

    const unlockedTargetWmk = await unlockWorkspaceMasterKey({
      passphrase,
      keyring: targetKeyringBody.keyring,
    });
    const restoredSecretMemo = await getMemoDetail(target.db, "ws_target", secretMemoDraft.id);
    expect(restoredSecretMemo).not.toBeNull();
    expect(restoredSecretMemo.encrypted).toBe(true);
    expect(restoredSecretMemo.excerpt).toBe("");
    expect(restoredSecretMemo.contentText).toBe("");

    const decryptedOnTarget = await decryptNoteContent({
      memoId: restoredSecretMemo.id,
      masterKey: unlockedTargetWmk,
      envelopeOrMarkdown: restoredSecretMemo.contentMarkdown,
      expectedKeyId: targetKeyringBody.keyring.keyId,
    });
    expect(decryptedOnTarget.plaintextMarkdown).toBe(secretText);

    // Restored plaintext note is intact too.
    const restoredPlainMemo = await getMemoDetail(target.db, "ws_target", plainMemo.id);
    expect(restoredPlainMemo.contentMarkdown).toBe("Regular markdown content");

    // --- Backup/restore conflict & security guards ---
    // 1. Re-restoring same keyId with same revision is idempotent; higher revision upgrades cleanly.
    const idempotentRes = await target.req("/api/v1/restores/json/e2ee-keyring", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ e2eeKeyring: targetKeyringBody.keyring }),
    });
    expect(idempotentRes.status).toBe(200);

    const rotatedForBackup = await rotateWorkspacePassphrase({
      currentPassphrase: passphrase,
      newPassphrase: "newer-backup-passphrase",
      currentKeyring: targetKeyringBody.keyring,
    });
    const { expectedRevision: _expectedRevision, ...rotatedKeyringFields } = rotatedForBackup.keyring;
    const upgradeRes = await target.req("/api/v1/restores/json/e2ee-keyring", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        e2eeKeyring: {
          ...rotatedKeyringFields,
          revision: 2,
          createdAt: targetKeyringBody.keyring.createdAt,
          updatedAt: "2026-11-26T12:00:00.000Z",
        },
      }),
    });
    expect(upgradeRes.status).toBe(200);
    expect((await upgradeRes.json()).e2eeKeyring.revision).toBe(2);

    // 2. Restoring a DIFFERENT keyId onto ws_target returns 409 keyring_key_id_mismatch (never overwrites!).
    const foreignKeyring = await initializeWorkspaceKeyring({ passphrase: "other-instance-passphrase" });
    const conflictKeyringRes = await target.req("/api/v1/restores/json/e2ee-keyring", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        e2eeKeyring: {
          ...foreignKeyring.keyring,
          revision: 5,
          createdAt: "2026-11-26T00:00:00.000Z",
          updatedAt: "2026-11-26T00:00:00.000Z",
        },
      }),
    });
    expect(conflictKeyringRes.status).toBe(409);
    expect((await conflictKeyringRes.json()).error.code).toBe("keyring_key_id_mismatch");

    // 3. Restoring an encrypted memo with a foreign keyId fails with 409 keyring_key_id_mismatch.
    const foreignNote = await encryptNoteContent({
      memoId: "memo_foreign_key",
      keyId: foreignKeyring.keyring.keyId,
      masterKey: foreignKeyring.masterKey,
      plaintextMarkdown: "Wrong key note",
    });
    const badMemoRestore = await target.req("/api/v1/restores/json/memos", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        memos: [
          {
            memo: {
              ...restoredSecretMemo,
              id: "memo_foreign_key",
              contentMarkdown: foreignNote.markdown,
            },
            revisions: [],
            resources: [],
          },
        ],
      }),
    });
    expect(badMemoRestore.status).toBe(409);
    expect((await badMemoRestore.json()).error.code).toBe("keyring_key_id_mismatch");

    // 4. Restoring a resource onto a restored encrypted memo is rejected on both PUT and multipart /uploads.
    const pngBytes = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    const resourceMeta = {
      id: "res_restore_enc_1",
      memoId: restoredSecretMemo.id,
      originalMemoId: null,
      kind: "image",
      mimeType: "image/png",
      filename: "forbidden.png",
      byteSize: pngBytes.byteLength,
      sha256: null,
      width: null,
      height: null,
      createdAt: "2026-11-26T00:00:00.000Z",
      updatedAt: "2026-11-26T00:00:00.000Z",
      archivePath: "notes/Vault/Secret.assets/forbidden.png",
    };
    const putResourceForm = new FormData();
    putResourceForm.set("file", new File([pngBytes], "forbidden.png", { type: "image/png" }));
    putResourceForm.set("metadata", JSON.stringify(resourceMeta));
    const putRes = await target.req("/api/v1/restores/json/resources/res_restore_enc_1", {
      method: "PUT",
      body: putResourceForm,
    });
    expect(putRes.status).toBe(409);
    expect((await putRes.json()).error.code).toBe("encrypted_memo_resources_forbidden");

    const uploadInitRes = await target.req("/api/v1/restores/json/resources/res_restore_enc_1/uploads", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(resourceMeta),
    });
    expect(uploadInitRes.status).toBe(409);
    expect((await uploadInitRes.json()).error.code).toBe("encrypted_memo_resources_forbidden");

    // 5. Trigger check for UPDATE and DELETE on workspace_e2ee_keyrings.
    const revBeforeDelete = target.sqlite
      .prepare("SELECT backup_revision FROM workspaces WHERE id = 'ws_target'")
      .get().backup_revision;
    target.sqlite.prepare("DELETE FROM workspace_e2ee_keyrings WHERE workspace_id = 'ws_target'").run();
    const revAfterDelete = target.sqlite
      .prepare("SELECT backup_revision FROM workspaces WHERE id = 'ws_target'")
      .get().backup_revision;
    expect(revAfterDelete).toBe(revBeforeDelete + 1);
  });

  test("handles D1-style meta.changes that include backup_revision trigger writes", async () => {
    const fixture = setupFixture({ workspaceId: "ws_d1_trigger", notebookId: "nb_d1_trigger" });
    const rawDb = fixture.env.storage.db;
    const countTotalChanges = () => Number(fixture.sqlite.prepare("SELECT total_changes() AS n").get().n);
    const wrapStatement = (stmt) => ({
      bind: (...values) => wrapStatement(stmt.bind(...values)),
      first: (...args) => stmt.first(...args),
      all: (...args) => stmt.all(...args),
      run: async () => {
        const before = countTotalChanges();
        const result = await stmt.run();
        const after = countTotalChanges();
        return {
          ...result,
          meta: {
            ...result.meta,
            changes: after - before,
          },
        };
      },
    });
    const d1LikeDb = {
      ...rawDb,
      prepare: (sql) => wrapStatement(rawDb.prepare(sql)),
    };
    const d1Env = {
      ...fixture.env,
      storage: { ...fixture.env.storage, db: d1LikeDb },
    };
    const d1App = new Hono();
    d1App.onError((error, c) => {
      if (error instanceof AppError) return apiError(c, error.code, error.message, error.status);
      throw error;
    });
    d1App.use("/api/v1/*", async (c, next) => {
      c.set("auth", { ...USER_AUTH, workspaceId: "ws_d1_trigger" });
      await next();
    });
    registerE2eeKeyringRoutes(d1App, { isDemoMode: () => false });

    // 1. Initial keyring creation succeeds with 201 even when trigger makes meta.changes === 2.
    const init = await initializeWorkspaceKeyring({ passphrase: "d1-trigger-passphrase-1" });
    const createRes = await d1App.request(
      "http://edgeever.test/api/v1/e2ee/keyring",
      {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(init.keyring),
      },
      d1Env,
    );
    expect(createRes.status).toBe(201);
    const createdBody = await createRes.json();
    expect(createdBody.configured).toBe(true);
    expect(createdBody.keyring.revision).toBe(1);

    // 2. Duplicate creation without expectedRevision returns 409 (INSERT OR IGNORE -> 0 changes).
    const duplicateRes = await d1App.request(
      "http://edgeever.test/api/v1/e2ee/keyring",
      {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(init.keyring),
      },
      d1Env,
    );
    expect(duplicateRes.status).toBe(409);
    expect((await duplicateRes.json()).error.code).toBe("keyring_already_exists");

    // 3. Passphrase rotation succeeds with 200 even when UPDATE trigger makes meta.changes === 2.
    const rotated = await rotateWorkspacePassphrase({
      currentPassphrase: "d1-trigger-passphrase-1",
      newPassphrase: "d1-trigger-passphrase-2",
      currentKeyring: createdBody.keyring,
    });
    const rotateRes = await d1App.request(
      "http://edgeever.test/api/v1/e2ee/keyring",
      {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(rotated.keyring),
      },
      d1Env,
    );
    expect(rotateRes.status).toBe(200);
    const rotatedBody = await rotateRes.json();
    expect(rotatedBody.keyring.revision).toBe(2);

    const createAudits = fixture.sqlite
      .prepare("SELECT action FROM audit_events WHERE entity_id = 'ws_d1_trigger' AND action LIKE 'e2ee.%' ORDER BY rowid")
      .all()
      .map((row) => row.action);
    expect(createAudits).toEqual(["e2ee.keyring_create", "e2ee.keyring_rotate"]);

    // 4. Backup restore insert and upgrade also record audit events under D1-style meta.changes === 2.
    fixture.sqlite.prepare("DELETE FROM workspace_e2ee_keyrings WHERE workspace_id = 'ws_d1_trigger'").run();
    const restoredV1 = await restoreJsonE2eeKeyring(d1LikeDb, "ws_d1_trigger", createdBody.keyring);
    expect(restoredV1.revision).toBe(1);
    const restoredV2 = await restoreJsonE2eeKeyring(d1LikeDb, "ws_d1_trigger", rotatedBody.keyring);
    expect(restoredV2.revision).toBe(2);
    const restoreAudits = fixture.sqlite
      .prepare("SELECT metadata_json FROM audit_events WHERE entity_id = 'ws_d1_trigger' AND action = 'backup.restore_e2ee_keyring' ORDER BY rowid")
      .all()
      .map((row) => JSON.parse(row.metadata_json).mode);
    expect(restoreAudits).toEqual(["insert", "upgrade"]);
  });
});
