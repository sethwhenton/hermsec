export type ContextChipKind = "project" | "file" | "folder" | "url" | "selection";

export interface ContextChip {
  id: string;
  kind: ContextChipKind;
  label: string;
  detail?: string;
  removable?: boolean;
}

export interface AgentQuestionOption {
  id: string;
  label: string;
}

export interface AgentQuestion {
  id: string;
  prompt: string;
  options: AgentQuestionOption[];
  allowMultiple?: boolean;
}

export interface ChatMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  createdAt: number;
  reportLink?: {
    label: string;
    path: string;
  };
}

export interface ChatQuestionsItem {
  kind: "questions";
  id: string;
  questions: AgentQuestion[];
  submitted?: boolean;
  answers?: Record<string, string[]>;
}

export interface ChatMessageItem {
  kind: "message";
  id: string;
  message: ChatMessage;
}

export type ChatItem = ChatMessageItem | ChatQuestionsItem;
