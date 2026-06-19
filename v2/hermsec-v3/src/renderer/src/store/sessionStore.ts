import { create } from "zustand";
import { getHermsecApi, requireHermsecApi } from "@/lib/ipc";
import { useUiStore } from "@/store/uiStore";
import type { ChatItem } from "@/types/chat";
import type { ChatSessionRecord, ChatSessionSummary } from "@/types/sessions";

interface SessionState {
  sessions: ChatSessionSummary[];
  currentSession: ChatSessionRecord | null;
  loading: boolean;
  refreshSessions: () => Promise<ChatSessionSummary[]>;
  startNewSession: () => void;
  openSession: (id: string) => Promise<ChatSessionRecord | null>;
  archiveSession: (id: string) => Promise<void>;
  deleteSession: (id: string) => Promise<void>;
  persistCurrentSession: (
    projectPath: string,
    chatItems: ChatItem[],
    titleSeed?: string,
  ) => Promise<ChatSessionRecord | null>;
}

export const useSessionStore = create<SessionState>((set, get) => ({
  sessions: [],
  currentSession: null,
  loading: false,

  refreshSessions: async () => {
    const api = getHermsecApi();
    if (!api) return [];
    set({ loading: true });
    try {
      const sessions = await api.sessions.list();
      set({ sessions, loading: false });
      return sessions;
    } catch {
      set({ loading: false });
      return get().sessions;
    }
  },

  startNewSession: () => {
    useUiStore.getState().clearChat();
    set({ currentSession: null });
  },

  openSession: async (id) => {
    const session = await requireHermsecApi().sessions.get(id);
    if (!session) return null;
    useUiStore.getState().setCurrentSessionId(session.id);
    useUiStore.getState().setChatItems(session.chatItems);
    set({ currentSession: session });
    return session;
  },

  archiveSession: async (id) => {
    await requireHermsecApi().sessions.archive(id);
    if (useUiStore.getState().currentSessionId === id) {
      useUiStore.getState().clearChat();
      set({ currentSession: null });
    }
    await get().refreshSessions();
  },

  deleteSession: async (id) => {
    await requireHermsecApi().sessions.delete(id);
    if (useUiStore.getState().currentSessionId === id) {
      useUiStore.getState().clearChat();
      set({ currentSession: null });
    }
    await get().refreshSessions();
  },

  persistCurrentSession: async (projectPath, chatItems, titleSeed) => {
    if (!projectPath) return null;

    const api = requireHermsecApi();
    const ui = useUiStore.getState();
    const current = get().currentSession;
    const currentSessionId = ui.currentSessionId;
    const mustCreate =
      !currentSessionId ||
      !current ||
      current.id !== currentSessionId ||
      normalizePath(current.projectPath) !== normalizePath(projectPath);

    const session =
      mustCreate || !currentSessionId
        ? await api.sessions.create({ projectPath, title: titleSeed, chatItems })
        : await api.sessions.update({
            id: currentSessionId,
            projectPath,
            title: titleSeed,
            chatItems,
          });

    useUiStore.getState().setCurrentSessionId(session.id);
    set((state) => ({
      currentSession: session,
      sessions: upsertSummary(state.sessions, session),
    }));
    return session;
  },
}));

function upsertSummary(
  sessions: ChatSessionSummary[],
  session: ChatSessionRecord,
): ChatSessionSummary[] {
  const summary: ChatSessionSummary = {
    id: session.id,
    projectPath: session.projectPath,
    title: session.title,
    createdAt: session.createdAt,
    updatedAt: session.updatedAt,
    messageCount: session.messageCount,
  };
  return [summary, ...sessions.filter((item) => item.id !== summary.id)].sort(
    (a, b) => b.updatedAt - a.updatedAt,
  );
}

function normalizePath(filePath: string): string {
  return filePath.replace(/\\/g, "/").toLowerCase();
}
