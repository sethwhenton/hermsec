import fs from "node:fs/promises";
import path from "node:path";

export type ToolPermission = {
  readWorkspace: boolean;
  readOutsideWorkspace: false;
  writeWorkspace: false;
  writeAppData: false;
  network: "none";
  requiresUserApproval: boolean;
  allowedInOfflineMode: boolean;
};

export type ToolContext = {
  workspaceRoot: string;
  offlineMode: boolean;
  userApproved: boolean;
  signal?: AbortSignal;
};

export function inspectionReadOnlyPermission(): ToolPermission {
  return {
    readWorkspace: true,
    readOutsideWorkspace: false,
    writeWorkspace: false,
    writeAppData: false,
    network: "none",
    requiresUserApproval: false,
    allowedInOfflineMode: true,
  };
}

export function assertToolPermission(permission: ToolPermission, context: ToolContext): void {
  throwIfAborted(context.signal);
  if (!permission.readWorkspace) {
    throw new Error("Inspection tools require read-only workspace access.");
  }
  if (permission.readOutsideWorkspace) {
    throw new Error("Hermsec tools may not read outside the active workspace.");
  }
  if (permission.writeWorkspace || permission.writeAppData) {
    throw new Error("Inspection tools may not write files.");
  }
  if (permission.network !== "none") {
    throw new Error("Inspection tools may not access the network.");
  }
  if (context.offlineMode && !permission.allowedInOfflineMode) {
    throw new Error("Tool is not allowed in offline mode.");
  }
  if (permission.requiresUserApproval && !context.userApproved) {
    throw new Error("Tool requires explicit user approval.");
  }
}

export async function assertToolWorkspace(
  context: ToolContext,
  expectedWorkspaceRoot: string,
): Promise<void> {
  throwIfAborted(context.signal);
  if (!context.workspaceRoot?.trim()) {
    throw new Error("Inspection tool context requires a workspace root.");
  }

  const [actualRoot, expectedRoot] = await Promise.all([
    canonicalDirectory(context.workspaceRoot),
    canonicalDirectory(expectedWorkspaceRoot),
  ]);
  if (!samePath(actualRoot, expectedRoot)) {
    throw new Error("Inspection tool workspace does not match the active repository.");
  }
}

async function canonicalDirectory(input: string): Promise<string> {
  const resolved = path.resolve(input);
  const stats = await fs.stat(resolved);
  if (!stats.isDirectory()) {
    throw new Error("Inspection workspace root must be a directory.");
  }
  return fs.realpath(resolved);
}

function samePath(left: string, right: string): boolean {
  return process.platform === "win32"
    ? left.toLowerCase() === right.toLowerCase()
    : left === right;
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) {
    throw signal.reason instanceof Error ? signal.reason : new Error("Tool call was aborted.");
  }
}
