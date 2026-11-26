import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type RefObject,
} from "react";
import type { Editor } from "@tiptap/react";
import {
  CLOSED_NOTE_SEARCH_STATE,
  createNoteSearchHighlightPlugin,
  formatNoteSearchMatchLabel,
  getNextSearchMatchIndex,
  getSearchMatchesFromDocument,
  getSearchNavigationIdentity,
  NOTE_SEARCH_HIGHLIGHT_PLUGIN_KEY,
  shouldResetNoteSearchForMemoChange,
  type NoteSearchMatch,
} from "./note-search";

import type { MarkdownSourceEditorRef } from "./MarkdownSourceEditor";
import { getMarkdownSearchMatches } from "./markdown-source-search";

type EditorNoteSearchControllerOptions = {
  disabled?: boolean;
  markdownMode: boolean;
  markdownSource: string;
  markdownSourceEditorRef: RefObject<MarkdownSourceEditorRef | null>;
  contentSearchQuery: string;
  dirtyVersion: number;
  editor: Editor | null;
  editorInstanceKey: string | null;
  editorScrollContainerRef: RefObject<HTMLDivElement | null>;
  readOnly: boolean;
  replaceFocusToken: number;
  searchFocusToken: number;
  memoId: string | null;
};

const isEditorReady = (editor: Editor | null | undefined): editor is Editor =>
  Boolean(editor && !editor.isDestroyed && (editor as { extensionManager?: unknown }).extensionManager);

const getEditorSearchMatches = (editor: Editor | null, query: string): NoteSearchMatch[] => {
  if (!isEditorReady(editor)) {
    return [];
  }

  return getSearchMatchesFromDocument(editor.state.doc, query);
};

export const useEditorNoteSearchController = ({
  disabled = false,
  markdownMode,
  markdownSource,
  markdownSourceEditorRef,
  contentSearchQuery,
  dirtyVersion,
  editor,
  editorInstanceKey,
  editorScrollContainerRef,
  memoId,
  readOnly,
  replaceFocusToken,
  searchFocusToken,
}: EditorNoteSearchControllerOptions) => {
  const [noteSearchOpen, setNoteSearchOpen] = useState(false);
  const [noteSearchQuery, setNoteSearchQuery] = useState("");
  const [noteSearchReplaceOpen, setNoteSearchReplaceOpen] = useState(false);
  const [noteSearchReplacement, setNoteSearchReplacement] = useState("");
  const [noteSearchIndex, setNoteSearchIndex] = useState(0);
  const noteSearchInputRef = useRef<HTMLInputElement | null>(null);
  const automaticSelectionRef = useRef<{ editor: Editor; identity: string } | null>(null);
  const previousEditorInstanceKeyRef = useRef(editorInstanceKey);
  const effectiveContentSearchQuery = disabled ? "" : contentSearchQuery;
  // Reset on a real note switch, not when desktop sync remaps a local id.
  // The editor instance key stays stable across that handoff.
  if (
    disabled && (noteSearchOpen || noteSearchQuery || noteSearchReplaceOpen || noteSearchReplacement || noteSearchIndex !== 0)
  ) {
    setNoteSearchOpen(CLOSED_NOTE_SEARCH_STATE.open);
    setNoteSearchQuery(CLOSED_NOTE_SEARCH_STATE.query);
    setNoteSearchReplaceOpen(CLOSED_NOTE_SEARCH_STATE.replaceOpen);
    setNoteSearchReplacement(CLOSED_NOTE_SEARCH_STATE.replacement);
    setNoteSearchIndex(CLOSED_NOTE_SEARCH_STATE.index);
  }
  if (shouldResetNoteSearchForMemoChange(previousEditorInstanceKeyRef.current, editorInstanceKey)) {
    previousEditorInstanceKeyRef.current = editorInstanceKey;
    setNoteSearchOpen(CLOSED_NOTE_SEARCH_STATE.open);
    setNoteSearchQuery(CLOSED_NOTE_SEARCH_STATE.query);
    setNoteSearchReplaceOpen(CLOSED_NOTE_SEARCH_STATE.replaceOpen);
    setNoteSearchReplacement(CLOSED_NOTE_SEARCH_STATE.replacement);
    setNoteSearchIndex(CLOSED_NOTE_SEARCH_STATE.index);
  }

  const noteSearchMatches = useMemo(
    () => disabled
      ? []
      : (markdownMode ? getMarkdownSearchMatches(markdownSource, noteSearchQuery) : getEditorSearchMatches(editor, noteSearchQuery)),
    [dirtyVersion, disabled, editor, markdownMode, markdownSource, memoId, noteSearchQuery],
  );
  const contentSearchMatches = useMemo(
    () => disabled
      ? []
      : (markdownMode ? getMarkdownSearchMatches(markdownSource, effectiveContentSearchQuery) : getEditorSearchMatches(editor, effectiveContentSearchQuery)),
    [disabled, dirtyVersion, editor, effectiveContentSearchQuery, markdownMode, markdownSource, memoId],
  );

  const selectMatch = useCallback(
    (index: number, matches: NoteSearchMatch[]) => {
      const match = matches[index];

      if (markdownMode) {
        if (match) markdownSourceEditorRef.current?.setSelection(match.from, match.to);
        return;
      }
      if (!isEditorReady(editor) || !match) {
        return;
      }

      editor.chain().setTextSelection({ from: match.from, to: match.to }).scrollIntoView().run();

      window.requestAnimationFrame(() => {
        const scrollContainer = editorScrollContainerRef.current;
        const domPosition = editor.view.domAtPos(match.from);
        const node = domPosition.node.nodeType === Node.TEXT_NODE
          ? domPosition.node.parentElement
          : domPosition.node instanceof Element
            ? domPosition.node
            : domPosition.node.parentElement;

        if (!scrollContainer || !node) {
          return;
        }

        const containerRect = scrollContainer.getBoundingClientRect();
        const nodeRect = node.getBoundingClientRect();
        const padding = 24;
        const isAbove = nodeRect.top < containerRect.top + padding;
        const isBelow = nodeRect.bottom > containerRect.bottom - padding;

        if (isAbove || isBelow) {
          const targetTop = scrollContainer.scrollTop + nodeRect.top - containerRect.top
            - (scrollContainer.clientHeight - nodeRect.height) / 2;
          scrollContainer.scrollTo({ top: Math.max(0, targetTop), behavior: "smooth" });
        }
      });
    },
    [editor, editorScrollContainerRef, markdownMode, markdownSourceEditorRef],
  );

  useEffect(() => {
    if (disabled || markdownMode || !isEditorReady(editor)) {
      return;
    }

    const searchHighlightPlugin = createNoteSearchHighlightPlugin({
      getQuery: () => noteSearchOpen ? noteSearchQuery : effectiveContentSearchQuery,
      getActiveIndex: () => noteSearchOpen ? noteSearchIndex : 0,
    });

    editor.registerPlugin(searchHighlightPlugin);

    return () => {
      if (isEditorReady(editor)) {
        editor.unregisterPlugin(NOTE_SEARCH_HIGHLIGHT_PLUGIN_KEY);
      }
    };
  }, [disabled, editor, effectiveContentSearchQuery, markdownMode, noteSearchIndex, noteSearchOpen, noteSearchQuery]);

  const focusSearchInput = useCallback(() => {
    window.requestAnimationFrame(() => {
      noteSearchInputRef.current?.focus();
      noteSearchInputRef.current?.select();
    });
  }, [noteSearchInputRef]);

  const openSearch = useCallback((showReplace = false) => {
    if (disabled) return;
    setNoteSearchOpen(true);
    setNoteSearchReplaceOpen(showReplace);
    focusSearchInput();
  }, [disabled, focusSearchInput]);

  const openFromSelection = useCallback((text: string, showReplace = false) => {
    if (disabled) return;
    setNoteSearchQuery(text);
    setNoteSearchOpen(true);
    setNoteSearchReplaceOpen(showReplace);
    focusSearchInput();
  }, [disabled, focusSearchInput]);

  const openWithQuery = useCallback((query: string) => {
    if (disabled) return;
    setNoteSearchQuery(query);
    setNoteSearchIndex(0);
    setNoteSearchReplaceOpen(false);
    setNoteSearchOpen(true);
    window.requestAnimationFrame(() => noteSearchInputRef.current?.focus());
  }, [disabled]);

  const closeReplace = useCallback(() => {
    setNoteSearchReplaceOpen(false);
  }, []);

  const openReplace = useCallback(() => {
    if (disabled || readOnly) return;
    openSearch(true);
  }, [disabled, openSearch, readOnly]);

  const closeSearch = useCallback(() => {
    setNoteSearchOpen(false);
    if (markdownMode) {
      markdownSourceEditorRef.current?.focus();
    } else if (isEditorReady(editor)) {
      editor.commands.focus();
    }
  }, [editor, markdownMode, markdownSourceEditorRef, setNoteSearchOpen]);

  useEffect(() => {
    if (!noteSearchOpen) {
      return;
    }

    const handleEscape = (event: KeyboardEvent) => {
      if (event.key !== "Escape" || event.defaultPrevented) {
        return;
      }

      event.preventDefault();
      event.stopPropagation();
      closeSearch();
    };

    window.addEventListener("keydown", handleEscape, true);
    return () => window.removeEventListener("keydown", handleEscape, true);
  }, [closeSearch, noteSearchOpen]);

  const moveMatch = useCallback((direction: 1 | -1) => {
    if (noteSearchMatches.length === 0) {
      return;
    }

    setNoteSearchIndex((current) => {
      const next = getNextSearchMatchIndex(current, direction, noteSearchMatches.length);
      selectMatch(next, noteSearchMatches);
      return next;
    });
  }, [noteSearchMatches, selectMatch, setNoteSearchIndex]);

  useEffect(() => {
    if (searchFocusToken !== 0) {
      openSearch();
    }
  }, [openSearch, searchFocusToken]);

  useEffect(() => {
    if (replaceFocusToken !== 0) {
      openReplace();
    }
  }, [openReplace, replaceFocusToken]);

  useEffect(() => {
    if (!isEditorReady(editor)) {
      return;
    }

    const source = noteSearchOpen ? "note" : "content";
    const query = noteSearchOpen ? noteSearchQuery : contentSearchQuery;
    const matches = noteSearchOpen ? noteSearchMatches : contentSearchMatches;
    const identity = JSON.stringify([markdownMode, getSearchNavigationIdentity(memoId, source, query)]);
    const previousSelection = automaticSelectionRef.current;

    if (previousSelection?.editor === editor && previousSelection.identity === identity) {
      return;
    }

    automaticSelectionRef.current = { editor, identity };
    setNoteSearchIndex(0);

    if (matches[0]) {
      selectMatch(0, matches);
    }
  }, [
    contentSearchMatches,
    contentSearchQuery,
    markdownMode,
    editor,
    memoId,
    noteSearchMatches,
    noteSearchOpen,
    noteSearchQuery,
    selectMatch,
    setNoteSearchIndex,
  ]);

  useEffect(() => {
    setNoteSearchIndex((current) => noteSearchMatches.length === 0
      ? 0
      : Math.min(current, noteSearchMatches.length - 1));
  }, [noteSearchMatches.length, setNoteSearchIndex]);

  const replaceAllMatches = useCallback(() => {
    if (readOnly || noteSearchMatches.length === 0) return;
    if (markdownMode) {
      markdownSourceEditorRef.current?.replaceSearchMatches(noteSearchQuery, noteSearchReplacement);
      setNoteSearchIndex(0);
      return;
    }
    if (!isEditorReady(editor)) {
      return;
    }

    editor
      .chain()
      .command(({ tr, dispatch }) => {
        for (const match of [...noteSearchMatches].reverse()) {
          tr.insertText(noteSearchReplacement, match.from, match.to);
        }

        dispatch?.(tr);
        return true;
      })
      .run();

    setNoteSearchIndex(0);
  }, [
    editor,
    markdownMode,
    markdownSourceEditorRef,
    noteSearchQuery,
    noteSearchMatches,
    noteSearchReplacement,
    readOnly,
    setNoteSearchIndex,
  ]);

  return {
    highlightQuery: disabled ? "" : (noteSearchOpen ? noteSearchQuery : effectiveContentSearchQuery),
    highlightIndex: disabled ? 0 : (noteSearchOpen ? noteSearchIndex : 0),
    closeReplace,
    closeSearch,
    inputRef: noteSearchInputRef,
    matchLabel: disabled
      ? ""
      : formatNoteSearchMatchLabel(
          noteSearchQuery,
          noteSearchIndex,
          noteSearchMatches.length,
        ),
    matches: noteSearchMatches,
    moveMatch,
    openFromSelection,
    openReplace,
    openSearch,
    openWithQuery,
    query: disabled ? "" : noteSearchQuery,
    replaceAllMatches,
    replaceOpen: disabled ? false : noteSearchReplaceOpen,
    replacement: disabled ? "" : noteSearchReplacement,
    searchOpen: disabled ? false : noteSearchOpen,
    setQuery: setNoteSearchQuery,
    setReplacement: setNoteSearchReplacement,
  };
};
