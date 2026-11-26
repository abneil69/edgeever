import { afterAll, beforeEach, describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { encryptNoteContent, initializeWorkspaceKeyring } from "@edgeever/shared";
import { restoreTestGlobal } from "../restore-test-global.mjs";
import { sidebarCompanionFocus, sidebarLocalContextText } from "../ai-sidebar-context.ts";
import { memoToSummary } from "../workspace-memo-cache.ts";
import { buildPromptContent } from "../../../../../apps/desktop/src/main/acp-host.mjs";

const originalWindow = globalThis.window;
const originalDocument = globalThis.document;
const originalMutationObserver = globalThis.MutationObserver;

const values = new Map();
const styles = new Map();
const eventListeners = new Map();

const stubWindow = {
  location: { href: "https://edgeever.example/" },
  localStorage: {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, String(value)),
    removeItem: (key) => values.delete(key),
    get length() { return values.size; },
    key: (index) => [...values.keys()][index] ?? null,
  },
  addEventListener: (name, listener) => eventListeners.set(name, listener),
  removeEventListener: (name) => eventListeners.delete(name),
};
globalThis.window = stubWindow;

const stubDocument = {
  documentElement: {
    classList: { contains: () => false },
    dataset: {},
    style: {
      setProperty: (key, value) => styles.set(key, value),
      removeProperty: (key) => styles.delete(key),
    },
    removeAttribute: () => {},
  },
};
globalThis.document = stubDocument;

const StubMutationObserver = class {
  observe() {}
  disconnect() {}
};
globalThis.MutationObserver = StubMutationObserver;

const { EdgeEverPluginHost } = await import("../plugins/plugin-host.ts");

afterAll(() => {
  restoreTestGlobal("window", originalWindow, stubWindow);
  restoreTestGlobal("document", originalDocument, stubDocument);
  restoreTestGlobal("MutationObserver", originalMutationObserver, StubMutationObserver);
});

beforeEach(() => {
  values.clear();
  styles.clear();
  eventListeners.clear();
});

const createSampleEncryptedMarkdown = async (memoId, plaintext) => {
  const init = await initializeWorkspaceKeyring({ passphrase: "boundary-test-passphrase" });
  const sealed = await encryptNoteContent({
    memoId,
    keyId: init.keyring.keyId,
    masterKey: init.masterKey,
    plaintextMarkdown: plaintext,
  });
  return sealed.markdown;
};

describe("Phase 2 E2EE security boundaries", () => {
  test("plugin host denies encrypted note body/revisions/editor access and strips excerpts & search navigation", async () => {
    const encryptedMarkdown = await createSampleEncryptedMarkdown("memo-enc-1", "TOP_SECRET_BODY");
    const plainMarkdown = "Plain public body";
    const encryptedMemo = {
      id: "memo-enc-1",
      notebookId: "nb-1",
      title: "Encrypted Title",
      excerpt: "should-never-appear",
      contentMarkdown: encryptedMarkdown,
      contentJson: { type: "doc", content: [{ type: "paragraph" }] },
      contentText: "",
      tags: ["vault"],
      pinned: false,
      isDeleted: false,
      encrypted: true,
      revision: 3,
      contentHash: "hash-enc-1",
      createdAt: "2026-01-01T00:00:00.000Z",
      updatedAt: "2026-01-02T00:00:00.000Z",
      deletedAt: null,
    };
    const plainMemo = {
      ...encryptedMemo,
      id: "memo-plain-1",
      title: "Plain Title",
      excerpt: "Plain excerpt",
      contentMarkdown: plainMarkdown,
      contentText: plainMarkdown,
      encrypted: false,
    };

    const openedNotes = [];
    const repository = {
      getMemo: async (id) => ({ memo: id === encryptedMemo.id ? encryptedMemo : plainMemo }),
      listMemos: async () => ({
        memos: [encryptedMemo, plainMemo].map((memo) => ({
          id: memo.id,
          notebookId: memo.notebookId,
          title: memo.title,
          excerpt: memo.excerpt,
          tags: memo.tags,
          pinned: memo.pinned,
          isDeleted: memo.isDeleted,
          encrypted: memo.encrypted,
          revision: memo.revision,
          contentHash: memo.contentHash,
          createdAt: memo.createdAt,
          updatedAt: memo.updatedAt,
          deletedAt: memo.deletedAt,
        })),
        totalCount: 2,
        nextCursor: null,
      }),
      listMemoRevisions: async () => ({ revisions: [{ id: "rev-1", revision: 1 }] }),
      restoreMemoRevision: async () => ({ memo: encryptedMemo }),
      updateMemo: async (current, input) => ({
        memo: {
          ...current,
          title: input.title ?? current.title,
          tags: input.tags ?? current.tags,
          contentMarkdown: input.contentMarkdown ?? current.contentMarkdown,
          revision: current.revision + 1,
        },
      }),
      createMemo: async (input) => ({ memo: { ...plainMemo, id: "memo-new", ...input } }),
    };

    const host = new EdgeEverPluginHost({
      repository,
      scope: "e2ee-boundary-test",
    });
    host.setNavigationAdapter({
      openNote: (noteId, _notebookId, options) => {
        openedNotes.push({ noteId, options });
      },
    });
    host.setEditorAdapter({
      isEncrypted: () => true,
      getSelection: () => ({ noteId: "memo-enc-1", from: 0, to: 5, empty: false, text: "LEAK", contentMarkdown: "LEAK" }),
      getDocument: () => ({ noteId: "memo-enc-1", contentMarkdown: "LEAK", hasUnsavedChanges: false }),
      replaceDocument: () => {},
      insertEmbed: () => {},
      replaceSelection: () => {},
      insertAtCursor: () => {},
    });

    const fixtureUrl = new URL("./e2ee-plugin-probe.fixture.mjs", import.meta.url).href;
    const probeModule = await import(fixtureUrl);
    host.installManifest({
      type: "plugin",
      id: "org.edgeever.e2ee-probe",
      name: "E2EE Probe",
      version: "1.0.0",
      apiVersion: "2",
      settingsUi: "host",
      entry: fixtureUrl,
      permissions: ["notes:read", "notes:write", "editor:read", "editor:write", "ui:navigation"],
    }, "https://example.org/manifest.json");
    await host.setEnabled("org.edgeever.e2ee-probe", true);
    const api = probeModule.capturedContext;
    expect(api).not.toBeNull();

    // notes.query exposes metadata only and strips excerpt.
    const queried = await api.notes.query({});
    const encSummary = queried.notes.find((n) => n.id === "memo-enc-1");
    expect(encSummary).toMatchObject({ id: "memo-enc-1", title: "Encrypted Title", excerpt: "", encrypted: true });

    // notes.queryContent excludes encrypted notes completely.
    const contentQueried = await api.notes.queryContent({});
    expect(contentQueried.notes.map((n) => n.id)).toEqual(["memo-plain-1"]);

    // notes.get / editMarkdown / revisions / update (even metadata-only) / creating encrypted marker all throw ENCRYPTED_NOTE_FORBIDDEN.
    await expect(api.notes.get("memo-enc-1")).rejects.toMatchObject({ code: "ENCRYPTED_NOTE_FORBIDDEN" });
    await expect(api.notes.editMarkdown("memo-enc-1", {
      expectedRevision: 3,
      expectedContentHash: "hash-enc-1",
      edits: [{ op: "append", content: "x" }],
    })).rejects.toMatchObject({ code: "ENCRYPTED_NOTE_FORBIDDEN" });
    await expect(api.notes.revisions.list("memo-enc-1")).rejects.toMatchObject({ code: "ENCRYPTED_NOTE_FORBIDDEN" });
    await expect(api.notes.revisions.restore("memo-enc-1", "rev-1")).rejects.toMatchObject({ code: "ENCRYPTED_NOTE_FORBIDDEN" });
    await expect(api.notes.update("memo-enc-1", { contentMarkdown: "hijack" })).rejects.toMatchObject({ code: "ENCRYPTED_NOTE_FORBIDDEN" });
    await expect(api.notes.update("memo-enc-1", { title: "Renamed Vault Note" })).rejects.toMatchObject({ code: "ENCRYPTED_NOTE_FORBIDDEN" });
    await expect(api.notes.create({ title: "Spoof", contentMarkdown: encryptedMarkdown })).rejects.toMatchObject({ code: "ENCRYPTED_NOTE_FORBIDDEN" });

    // editor.* rejects all read/write methods while an encrypted note is active.
    await expect(api.editor.getSelection()).rejects.toMatchObject({ code: "ENCRYPTED_NOTE_FORBIDDEN" });
    await expect(api.editor.getDocument()).rejects.toMatchObject({ code: "ENCRYPTED_NOTE_FORBIDDEN" });
    await expect(api.editor.editMarkdown([{ op: "append", content: "x" }])).rejects.toMatchObject({ code: "ENCRYPTED_NOTE_FORBIDDEN" });
    await expect(api.editor.replaceSelection("x")).rejects.toMatchObject({ code: "ENCRYPTED_NOTE_FORBIDDEN" });
    await expect(api.editor.insertAtCursor("x")).rejects.toMatchObject({ code: "ENCRYPTED_NOTE_FORBIDDEN" });

    // ui.openNote strips in-note search parameter for encrypted notes.
    await api.ui.openNote("memo-enc-1", { search: "TOP_SECRET" });
    expect(openedNotes).toEqual([{ noteId: "memo-enc-1", options: undefined }]);

    await host.dispose();
  });

  test("AI sidebar and local ACP context never include plaintext or selection of encrypted notes", async () => {
    const unlockedEncryptedNote = {
      memoId: "memo-enc-2",
      notebookId: "nb-1",
      notebookTitle: "Private",
      noteTitle: "Vault Entry",
      contentMarkdown: "SUPER_SECRET_UNLOCKED_PLAINTEXT",
      selectionMarkdown: "SELECTED_SECRET_SNIPPET",
      encrypted: true,
    };

    const companionFocus = sidebarCompanionFocus(unlockedEncryptedNote, true);
    expect(companionFocus).toEqual({
      memoId: "memo-enc-2",
      notebookId: "nb-1",
      notebookTitle: "Private",
      title: "Vault Entry",
    });
    expect(companionFocus).not.toHaveProperty("contentMarkdown");
    expect(companionFocus).not.toHaveProperty("selectionMarkdown");
    expect(JSON.stringify(companionFocus)).not.toContain("SUPER_SECRET_UNLOCKED_PLAINTEXT");
    expect(JSON.stringify(companionFocus)).not.toContain("SELECTED_SECRET_SNIPPET");

    const localContext = sidebarLocalContextText(unlockedEncryptedNote, true, {
      message: "Summarize this note",
      recentUserMessages: [],
      fallbackLocale: "en-US",
    });
    expect(localContext).not.toContain("SUPER_SECRET_UNLOCKED_PLAINTEXT");
    expect(localContext).not.toContain("SELECTED_SECRET_SNIPPET");
    expect(localContext).toContain("end-to-end encrypted");

    // Even if an encrypted ciphertext block reaches ACP host, buildPromptContent strips it.
    const encryptedMarkdown = await createSampleEncryptedMarkdown("memo-enc-3", "hidden");
    const promptResult = buildPromptContent({ prompt: "Summarize", contextText: encryptedMarkdown });
    expect(promptResult.blocks).toEqual([{ type: "text", text: "Summarize" }]);
    expect(JSON.stringify(promptResult.blocks)).not.toContain("edgeever-encrypted-note");
  });

  test("memoToSummary strips excerpt and marks encrypted=true for encrypted memos", async () => {
    const encryptedMarkdown = await createSampleEncryptedMarkdown("memo-enc-4", "secret");
    const summary = memoToSummary({
      id: "memo-enc-4",
      notebookId: "nb-1",
      title: "Encrypted Summary",
      excerpt: "leaked excerpt",
      contentMarkdown: encryptedMarkdown,
      contentJson: { type: "doc", content: [{ type: "paragraph" }] },
      contentText: "leaked text",
      tags: ["sec"],
      pinned: false,
      isDeleted: false,
      revision: 1,
      contentHash: "h1",
      createdAt: "2026-01-01T00:00:00.000Z",
      updatedAt: "2026-01-01T00:00:00.000Z",
      deletedAt: null,
    });
    expect(summary.encrypted).toBe(true);
    expect(summary.excerpt).toBe("");
  });

  test("in-note search controller and EditorPane guard disable search for encrypted notes", () => {
    const searchControllerSource = readFileSync(
      new URL("../../components/editor/useEditorNoteSearchController.ts", import.meta.url),
      "utf8",
    );
    expect(searchControllerSource).toContain("disabled = false");
    expect(searchControllerSource).toContain("if (disabled)");

    const editorPaneSource = readFileSync(
      new URL("../../components/EditorPane.tsx", import.meta.url),
      "utf8",
    );
    expect(editorPaneSource).toContain("disabled: isEncryptedNote");
    expect(editorPaneSource).toContain("onSearch={isEncryptedNote ? undefined : () => openNoteSearch()}");
    expect(editorPaneSource).toContain("if (isEncryptedNoteRef.current) {\n          event.preventDefault();\n          return true;\n        }");
    expect(editorPaneSource).toContain("cached.cipherMarkdown === target.contentMarkdown");

    const revisionDialogSource = readFileSync(
      new URL("../../components/dialogs/RevisionHistoryDialog.tsx", import.meta.url),
      "utf8",
    );
    expect(revisionDialogSource).toContain("useE2eeSession()");
    expect(revisionDialogSource).toContain("if (!e2ee.unlocked) {\n      setDecryptedRevisionMarkdown(\"\");\n      return;\n    }");

    const repositorySource = readFileSync(
      new URL("../repository.ts", import.meta.url),
      "utf8",
    );
    expect(repositorySource).toContain("hasEncryptedNoteMarker(revision.contentMarkdown)\n      ? emptyDoc()");
  });

  test("encrypted notes gate plaintext export/copy behind confirmation and avoid outline/spellcheck persistence", async () => {
    const { readOutlineSnapshot, removeOutlineSnapshot, writeOutlineSnapshot } = await import("../editor-outline-state.ts");
    const store = new Map();
    const originalWindow = globalThis.window;
    globalThis.window = {
      localStorage: {
        getItem: (k) => store.get(k) ?? null,
        setItem: (k, v) => { store.set(k, String(v)); },
        removeItem: (k) => { store.delete(k); },
      },
    };
    try {
      writeOutlineSnapshot("memo_enc_outline", {
        items: [{ level: 1, pos: 0, text: "Secret Heading" }],
        collapsed: [0],
      });
      expect(readOutlineSnapshot("memo_enc_outline")?.items[0]?.text).toBe("Secret Heading");
      removeOutlineSnapshot("memo_enc_outline");
      expect(readOutlineSnapshot("memo_enc_outline")).toBeNull();
      expect(store.size).toBe(0);
    } finally {
      globalThis.window = originalWindow;
    }

    const editorPaneSource = readFileSync(
      new URL("../../components/EditorPane.tsx", import.meta.url),
      "utf8",
    );
    expect(editorPaneSource).toContain("const effectiveSpellcheckEnabled = !isEncryptedNote && spellcheckEnabled;");
    expect(editorPaneSource).toContain("persist={!isEncryptedNote}");
    expect(editorPaneSource).toContain("removeOutlineSnapshot(target.id);");
    expect(editorPaneSource).toContain("<EncryptedPlaintextExportConfirmDialog");

    const editorOutlineSource = readFileSync(
      new URL("../../components/EditorOutline.tsx", import.meta.url),
      "utf8",
    );
    expect(editorOutlineSource).toContain("if (!persist) return;");
    expect(editorOutlineSource).toContain("removeOutlineSnapshot(memoId);");

    const docActionsSource = readFileSync(
      new URL("../../components/editor/useEditorDocumentActions.ts", import.meta.url),
      "utf8",
    );
    expect(docActionsSource).toContain('setPendingPlaintextExport("export-markdown")');
    expect(docActionsSource).toContain('setPendingPlaintextExport("export-html")');
    expect(docActionsSource).toContain('setPendingPlaintextExport("export-pdf")');
    expect(docActionsSource).toContain('setPendingPlaintextExport("share-image")');
    expect(docActionsSource).toContain('setPendingPlaintextExport("copy-wechat")');

    const mermaidCodeBlockSource = readFileSync(
      new URL("../../components/MermaidCodeBlock.tsx", import.meta.url),
      "utf8",
    );
    expect(mermaidCodeBlockSource).toContain('editor?.view?.dom?.getAttribute("data-encrypted-note") === "true"');
    expect(mermaidCodeBlockSource).toContain("<EncryptedPlaintextExportConfirmDialog");

    const memoListSource = readFileSync(
      new URL("../../components/MemoListPane.tsx", import.meta.url),
      "utf8",
    );
    expect(memoListSource).toContain('action === "export-pdf" && !memo.encrypted ? preopenNotePrintWindow() : undefined');
  });
});
