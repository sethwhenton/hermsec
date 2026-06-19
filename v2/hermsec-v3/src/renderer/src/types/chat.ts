import type { DoctorProgressEvent, DoctorRunResult } from "./doctor";

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
  copyAction?: {
    label: string;
    text: string;
  };
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

export interface ChatDoctorItem {
  kind: "doctor";
  id: string;
  result?: DoctorRunResult;
  progress?: DoctorProgressEvent[];
  running?: boolean;
  error?: string;
}

export type ChatItem = ChatMessageItem | ChatQuestionsItem | ChatDoctorItem;
