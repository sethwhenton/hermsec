import crypto from "node:crypto";
import path from "node:path";
import fs from "node:fs/promises";
import { ensureHermsecAppData, getAppDataLayout } from "./appData.js";
import {
  JsonStore,
  optionalString,
  requireEnum,
  requireRecord,
  requireString,
  requireStringArray,
} from "./jsonStore.js";

export const sessionRoles = ["system", "user", "assistant", "tool"] as const;
export type SessionRole = (typeof sessionRoles)[number];

export const sessionToolNames = ["scan", "doctor", "report", "workspace", "intel", "schedule"] as const;
export type SessionToolName = (typeof sessionToolNames)[number];

export const toolCallStatuses = ["queued", "running", "succeeded", "failed", "skipped"] as const;
export type ToolCallStatus = (typeof toolCallStatuses)[number];

export type SessionMessage = {
  id: string;
  role: SessionRole;
  content: string;
  createdAt: string;
  redactionApplied: boolean;
};

export type SessionToolCall = {
  id: string;
  toolName: SessionToolName;
  status: ToolCallStatus;
  runId?: string;
};

export type SessionRecord = {
  schemaVersion: 1;
  id: string;
  workspaceId: string;
  title: string;
  createdAt: string;
  updatedAt: string;
  messages: SessionMessage[];
  toolCalls: SessionToolCall[];
  discussedScanIds: string[];
  discussedFindingIds: string[];
  compactSummary?: string;
};

export function createSessionRecord(workspaceId: string, title = "Hermsec session", now = new Date()): SessionRecord {
  const timestamp = now.toISOString();
  return {
    schemaVersion: 1,
    id: `ses-${crypto.randomUUID()}`,
    workspaceId,
    title,
    createdAt: timestamp,
    updatedAt: timestamp,
    messages: [],
    toolCalls: [],
    discussedScanIds: [],
    discussedFindingIds: [],
  };
}

function validateSessionMessage(value: unknown): SessionMessage {
  const record = requireRecord(value, "session.messages[]");
  return {
    id: requireString(record.id, "session.messages[].id"),
    role: requireEnum(record.role, "session.messages[].role", sessionRoles),
    content: requireString(record.content, "session.messages[].content"),
    createdAt: requireString(record.createdAt, "session.messages[].createdAt"),
    redactionApplied: record.redactionApplied === true,
  };
}

function validateSessionToolCall(value: unknown): SessionToolCall {
  const record = requireRecord(value, "session.toolCalls[]");
  const runId = optionalString(record.runId, "session.toolCalls[].runId");
  return {
    id: requireString(record.id, "session.toolCalls[].id"),
    toolName: requireEnum(record.toolName, "session.toolCalls[].toolName", sessionToolNames),
    status: requireEnum(record.status, "session.toolCalls[].status", toolCallStatuses),
    ...(runId ? { runId } : {}),
  };
}

export function validateSessionRecord(value: unknown): SessionRecord {
  const record = requireRecord(value, "session");
  if (record.schemaVersion !== 1) {
    throw new Error("session.schemaVersion must be 1");
  }
  if (!Array.isArray(record.messages) || !Array.isArray(record.toolCalls)) {
    throw new Error("session.messages and session.toolCalls must be arrays");
  }
  const compactSummary = optionalString(record.compactSummary, "session.compactSummary");
  return {
    schemaVersion: 1,
    id: requireString(record.id, "session.id"),
    workspaceId: requireString(record.workspaceId, "session.workspaceId"),
    title: requireString(record.title, "session.title"),
    createdAt: requireString(record.createdAt, "session.createdAt"),
    updatedAt: requireString(record.updatedAt, "session.updatedAt"),
    messages: record.messages.map(validateSessionMessage),
    toolCalls: record.toolCalls.map(validateSessionToolCall),
    discussedScanIds: requireStringArray(record.discussedScanIds ?? [], "session.discussedScanIds"),
    discussedFindingIds: requireStringArray(record.discussedFindingIds ?? [], "session.discussedFindingIds"),
    ...(compactSummary ? { compactSummary } : {}),
  };
}

function sessionPath(workspaceId: string, sessionId: string): string {
  return path.join(getAppDataLayout().sessionsDir, workspaceId, `${sessionId}.json`);
}

export async function saveSession(session: SessionRecord): Promise<SessionRecord> {
  await ensureHermsecAppData();
  return new JsonStore(sessionPath(session.workspaceId, session.id), session, validateSessionRecord).save(session);
}

export async function loadSession(workspaceId: string, sessionId: string): Promise<SessionRecord> {
  await ensureHermsecAppData();
  return new JsonStore(sessionPath(workspaceId, sessionId), createSessionRecord(workspaceId), validateSessionRecord).load();
}

export async function listSessions(workspaceId: string): Promise<SessionRecord[]> {
  const layout = await ensureHermsecAppData();
  const directory = path.join(layout.sessionsDir, workspaceId);
  try {
    const entries = await fs.readdir(directory, { withFileTypes: true });
    const sessions = await Promise.all(
      entries
        .filter((entry) => entry.isFile() && entry.name.endsWith(".json"))
        .map((entry) =>
          new JsonStore(
            path.join(directory, entry.name),
            createSessionRecord(workspaceId),
            validateSessionRecord,
          ).load(),
        ),
    );
    return sessions.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
  } catch (error) {
    const code = error && typeof error === "object" && "code" in error ? String(error.code) : "";
    if (code === "ENOENT") {
      return [];
    }
    throw error;
  }
}

export async function appendSessionMessage(
  workspaceId: string,
  sessionId: string,
  message: Omit<SessionMessage, "id" | "createdAt"> & { id?: string; createdAt?: string },
): Promise<SessionRecord> {
  const session = await loadSession(workspaceId, sessionId);
  const now = new Date().toISOString();
  const nextMessage: SessionMessage = {
    id: message.id ?? `msg-${crypto.randomUUID()}`,
    role: message.role,
    content: message.content,
    createdAt: message.createdAt ?? now,
    redactionApplied: message.redactionApplied,
  };
  return saveSession({
    ...session,
    updatedAt: now,
    messages: [...session.messages, nextMessage],
  });
}
