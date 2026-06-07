import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import path from "node:path";
import { app } from "electron";
import type { ChatItem } from "../renderer/src/types/chat";
import type {
  ChatSessionRecord,
  ChatSessionSummary,
  CreateChatSessionRequest,
  UpdateChatSessionRequest,
} from "../renderer/src/types/sessions";

const SESSIONS_FILE = "sessions.json";

interface SessionsFile {
  sessions: ChatSessionRecord[];
}

function sessionsPath(): string {
  const dir = app.getPath("userData");
  mkdirSync(dir, { recursive: true });
  return path.join(dir, SESSIONS_FILE);
}

function readSessionsFile(): SessionsFile {
  const filePath = sessionsPath();
  if (!existsSync(filePath)) return { sessions: [] };

  try {
    const parsed = JSON.parse(readFileSync(filePath, "utf8")) as Partial<SessionsFile>;
    const sessions = Array.isArray(parsed.sessions)
      ? parsed.sessions.map(normalizeSession).filter(isSessionRecord)
      : [];
    return {
      sessions,
    };
  } catch {
    return { sessions: [] };
  }
}

function writeSessionsFile(file: SessionsFile): void {
  const filePath = sessionsPath();
  const tmp = `${filePath}.tmp`;
  writeFileSync(tmp, JSON.stringify(file, null, 2), "utf8");
  renameSync(tmp, filePath);
}

export function listChatSessions(projectPath?: string): ChatSessionSummary[] {
  const normalizedProjectPath = projectPath ? normalizePath(projectPath) : null;
  return readSessionsFile()
    .sessions.filter((session) =>
      normalizedProjectPath ? normalizePath(session.projectPath) === normalizedProjectPath : true,
    )
    .map(toSummary)
    .sort((a, b) => b.updatedAt - a.updatedAt);
}

export function getChatSession(id: string): ChatSessionRecord | null {
  return readSessionsFile().sessions.find((session) => session.id === id) ?? null;
}

export function createChatSession(request: CreateChatSessionRequest): ChatSessionRecord {
  const now = Date.now();
  const chatItems = request.chatItems ?? [];
  const session: ChatSessionRecord = {
    id: createId(),
    projectPath: request.projectPath,
    title: cleanTitle(request.title) || titleFromChatItems(chatItems) || "New chat",
    createdAt: now,
    updatedAt: now,
    messageCount: countMessages(chatItems),
    chatItems,
  };
  const file = readSessionsFile();
  file.sessions.unshift(session);
  writeSessionsFile(file);
  return session;
}

export function updateChatSession(request: UpdateChatSessionRequest): ChatSessionRecord {
  const file = readSessionsFile();
  const index = file.sessions.findIndex((session) => session.id === request.id);
  if (index < 0) {
    throw new Error(`Chat session not found: ${request.id}`);
  }

  const current = file.sessions[index];
  const chatItems = request.chatItems ?? current.chatItems;
  const title =
    cleanTitle(request.title) ||
    titleFromChatItems(chatItems) ||
    current.title ||
    "New chat";
  const next: ChatSessionRecord = {
    ...current,
    ...(request.projectPath ? { projectPath: request.projectPath } : {}),
    title,
    chatItems,
    messageCount: countMessages(chatItems),
    updatedAt: Date.now(),
  };

  file.sessions[index] = next;
  file.sessions.sort((a, b) => b.updatedAt - a.updatedAt);
  writeSessionsFile(file);
  return next;
}

function normalizeSession(session: Partial<ChatSessionRecord>): ChatSessionRecord | null {
  if (!session.id || !session.projectPath) return null;
  const chatItems = Array.isArray(session.chatItems) ? session.chatItems : [];
  return {
    id: String(session.id),
    projectPath: String(session.projectPath),
    title: cleanTitle(session.title) || titleFromChatItems(chatItems) || "New chat",
    createdAt: Number(session.createdAt ?? Date.now()),
    updatedAt: Number(session.updatedAt ?? session.createdAt ?? Date.now()),
    messageCount: countMessages(chatItems),
    chatItems,
  };
}

function isSessionRecord(session: ChatSessionRecord | null): session is ChatSessionRecord {
  return session !== null;
}

function toSummary(session: ChatSessionRecord): ChatSessionSummary {
  return {
    id: session.id,
    projectPath: session.projectPath,
    title: session.title,
    createdAt: session.createdAt,
    updatedAt: session.updatedAt,
    messageCount: session.messageCount,
  };
}

function titleFromChatItems(chatItems: ChatItem[]): string {
  const firstUserMessage = chatItems.find(
    (item) => item.kind === "message" && item.message.role === "user",
  );
  if (!firstUserMessage || firstUserMessage.kind !== "message") return "";
  return cleanTitle(firstUserMessage.message.content);
}

function cleanTitle(value?: string): string {
  const normalized = value?.replace(/\s+/g, " ").trim() ?? "";
  if (!normalized) return "";
  return normalized.length > 42 ? `${normalized.slice(0, 39)}...` : normalized;
}

function countMessages(chatItems: ChatItem[]): number {
  return chatItems.filter((item) => item.kind === "message").length;
}

function createId(): string {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

function normalizePath(filePath: string): string {
  return path.resolve(filePath).toLowerCase();
}
