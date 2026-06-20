import type { ChatItem } from "./chat";

export interface ChatSessionSummary {
  id: string;
  projectPath: string;
  title: string;
  createdAt: number;
  updatedAt: number;
  messageCount: number;
  archivedAt?: number;
}

export interface ChatSessionRecord extends ChatSessionSummary {
  chatItems: ChatItem[];
}

export interface CreateChatSessionRequest {
  projectPath: string;
  title?: string;
  chatItems?: ChatItem[];
}

export interface UpdateChatSessionRequest {
  id: string;
  projectPath?: string;
  title?: string;
  chatItems?: ChatItem[];
}

export interface SessionActionResult {
  ok: boolean;
  message: string;
}
