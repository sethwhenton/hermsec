import type { DoctorProgressEvent, DoctorRunResult } from "./doctor";
import type { ScanProgressEvent } from "./scan";

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
  description?: string;
  meta?: string;
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
  scrollBehavior?: "readable";
  copyAction?: {
    label: string;
    text: string;
  };
  reportLink?: {
    label: string;
    path: string;
  };
  reportLinks?: Array<{
    label: string;
    path: string;
  }>;
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

export interface ChatScanProgressItem {
  kind: "scan-progress";
  id: string;
  events: ScanProgressEvent[];
  running?: boolean;
}

export type ChatItem = ChatMessageItem | ChatQuestionsItem | ChatDoctorItem | ChatScanProgressItem;
