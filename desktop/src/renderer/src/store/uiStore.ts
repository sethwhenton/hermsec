import { create } from "zustand";
import type { ChatItem } from "@/types/chat";
import type { ContextChip } from "@/types/chat";

export type AppView = "chat" | "dashboard" | "automations" | "settings";
export type SettingsSection = "general" | "agents" | "providers" | "models" | "scanners";

interface UiState {
  view: AppView;
  settingsSection: SettingsSection;
  sidebarCollapsed: boolean;
  isAgentThinking: boolean;
  agentStatus: string;
  currentSessionId?: string;
  contextChips: ContextChip[];
  chatItems: ChatItem[];
  setView: (view: AppView) => void;
  setSettingsSection: (section: SettingsSection) => void;
  toggleSidebar: () => void;
  setAgentThinking: (thinking: boolean) => void;
  setAgentStatus: (status: string) => void;
  setCurrentSessionId: (sessionId?: string) => void;
  setChatItems: (items: ChatItem[]) => void;
  addContextChip: (chip: ContextChip) => void;
  removeContextChip: (id: string) => void;
  addChatItem: (item: ChatItem) => void;
  updateChatItem: (id: string, updater: (item: ChatItem) => ChatItem) => void;
  clearChat: () => void;
}

const defaultChips: ContextChip[] = [];

export const useUiStore = create<UiState>((set) => ({
  view: "chat",
  settingsSection: "general",
  sidebarCollapsed: false,
  isAgentThinking: false,
  agentStatus: "Thinking...",
  currentSessionId: undefined,
  contextChips: defaultChips,
  chatItems: [],
  setView: (view) => set({ view }),
  setSettingsSection: (settingsSection) => set({ settingsSection }),
  toggleSidebar: () => set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),
  setAgentThinking: (isAgentThinking) => set({ isAgentThinking }),
  setAgentStatus: (agentStatus) => set({ agentStatus }),
  setCurrentSessionId: (currentSessionId) => set({ currentSessionId }),
  setChatItems: (chatItems) => set({ chatItems }),
  addContextChip: (chip) =>
    set((s) => ({
      contextChips: s.contextChips.some((c) => c.id === chip.id)
        ? s.contextChips
        : [...s.contextChips, chip],
    })),
  removeContextChip: (id) =>
    set((s) => ({ contextChips: s.contextChips.filter((c) => c.id !== id) })),
  addChatItem: (item) => set((s) => ({ chatItems: [...s.chatItems, item] })),
  updateChatItem: (id, updater) =>
    set((s) => ({
      chatItems: s.chatItems.map((item) => (item.id === id ? updater(item) : item)),
    })),
  clearChat: () => set({ chatItems: [], currentSessionId: undefined, isAgentThinking: false, agentStatus: "Thinking..." }),
}));
