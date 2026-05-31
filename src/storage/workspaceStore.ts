import crypto from "node:crypto";
import path from "node:path";
import { ensureHermsecAppData, getAppDataLayout } from "./appData.js";
import {
  JsonStore,
  optionalString,
  requireEnum,
  requireRecord,
  requireString,
} from "./jsonStore.js";
import { updateRecentWorkspaces, type PrivacyMode } from "./userConfig.js";

export const sourceKinds = ["local", "github-temp", "github-local-clone"] as const;
export type WorkspaceSourceKind = (typeof sourceKinds)[number];

export const scanModes = ["offline", "online", "auto"] as const;
export type WorkspaceScanMode = (typeof scanModes)[number];

export const projectConfigModes = ["none", "read-only", "write-project-local"] as const;
export type ProjectConfigMode = (typeof projectConfigModes)[number];

export type WorkspaceProfile = {
  schemaVersion: 1;
  id: string;
  displayName: string;
  rootPath: string;
  sourceKind: WorkspaceSourceKind;
  remoteUrl?: string;
  reportDir: string;
  privacyMode: PrivacyMode;
  scanMode: WorkspaceScanMode;
  projectConfigMode: ProjectConfigMode;
  lastScanId?: string;
  lastScannedCommit?: string;
  createdAt: string;
  updatedAt: string;
};

export type WorkspacesFile = {
  schemaVersion: 1;
  activeWorkspaceId?: string;
  workspaces: WorkspaceProfile[];
};

export type AddWorkspaceInput = {
  rootPath: string;
  displayName?: string;
  sourceKind?: WorkspaceSourceKind;
  remoteUrl?: string;
  reportDir?: string;
  privacyMode?: PrivacyMode;
  scanMode?: WorkspaceScanMode;
  projectConfigMode?: ProjectConfigMode;
  now?: Date;
};

export function workspaceIdForRoot(rootPath: string): string {
  const normalized = path.resolve(rootPath).toLowerCase();
  const digest = crypto.createHash("sha256").update(normalized).digest("hex").slice(0, 16);
  return `ws-${digest}`;
}

export function workspaceSlug(displayName: string, workspaceId: string): string {
  const slug = displayName
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48);
  return `${slug || "workspace"}-${workspaceId.slice(-8)}`;
}

export function defaultWorkspacesFile(): WorkspacesFile {
  return {
    schemaVersion: 1,
    workspaces: [],
  };
}

export function validateWorkspaceProfile(value: unknown): WorkspaceProfile {
  const record = requireRecord(value, "workspace");
  if (record.schemaVersion !== 1) {
    throw new Error("workspace.schemaVersion must be 1");
  }
  const id = requireString(record.id, "workspace.id");
  const displayName = requireString(record.displayName, "workspace.displayName");
  const rootPath = path.resolve(requireString(record.rootPath, "workspace.rootPath"));
  const sourceKind = requireEnum(record.sourceKind, "workspace.sourceKind", sourceKinds);
  const remoteUrl = optionalString(record.remoteUrl, "workspace.remoteUrl");
  const reportDir = path.resolve(requireString(record.reportDir, "workspace.reportDir"));
  const privacyMode = requireEnum(record.privacyMode, "workspace.privacyMode", [
    "local-only",
    "balanced",
    "cloud-assisted",
  ] as const);
  const scanMode = requireEnum(record.scanMode, "workspace.scanMode", scanModes);
  const projectConfigMode = requireEnum(
    record.projectConfigMode,
    "workspace.projectConfigMode",
    projectConfigModes,
  );
  const lastScanId = optionalString(record.lastScanId, "workspace.lastScanId");
  const lastScannedCommit = optionalString(record.lastScannedCommit, "workspace.lastScannedCommit");
  const createdAt = requireString(record.createdAt, "workspace.createdAt");
  const updatedAt = requireString(record.updatedAt, "workspace.updatedAt");

  return {
    schemaVersion: 1,
    id,
    displayName,
    rootPath,
    sourceKind,
    ...(remoteUrl ? { remoteUrl } : {}),
    reportDir,
    privacyMode,
    scanMode,
    projectConfigMode,
    ...(lastScanId ? { lastScanId } : {}),
    ...(lastScannedCommit ? { lastScannedCommit } : {}),
    createdAt,
    updatedAt,
  };
}

export function validateWorkspacesFile(value: unknown): WorkspacesFile {
  const record = requireRecord(value, "workspaces");
  if (record.schemaVersion !== 1) {
    throw new Error("workspaces.schemaVersion must be 1");
  }
  if (!Array.isArray(record.workspaces)) {
    throw new Error("workspaces.workspaces must be an array");
  }
  const activeWorkspaceId = optionalString(record.activeWorkspaceId, "workspaces.activeWorkspaceId");
  const file: WorkspacesFile = {
    schemaVersion: 1,
    workspaces: record.workspaces.map(validateWorkspaceProfile),
  };
  if (activeWorkspaceId) {
    file.activeWorkspaceId = activeWorkspaceId;
  }
  return file;
}

function workspaceStore(): JsonStore<WorkspacesFile> {
  const layout = getAppDataLayout();
  return new JsonStore(layout.workspacesFile, defaultWorkspacesFile(), validateWorkspacesFile);
}

export async function loadWorkspacesFile(): Promise<WorkspacesFile> {
  await ensureHermsecAppData();
  return workspaceStore().load();
}

export async function saveWorkspacesFile(value: WorkspacesFile): Promise<WorkspacesFile> {
  await ensureHermsecAppData();
  return workspaceStore().save(value);
}

export async function listWorkspaces(): Promise<WorkspaceProfile[]> {
  return (await loadWorkspacesFile()).workspaces;
}

export async function getWorkspace(workspaceId: string): Promise<WorkspaceProfile | undefined> {
  return (await listWorkspaces()).find((workspace) => workspace.id === workspaceId);
}

export async function getActiveWorkspace(): Promise<WorkspaceProfile | undefined> {
  const file = await loadWorkspacesFile();
  if (!file.activeWorkspaceId) {
    return undefined;
  }
  return file.workspaces.find((workspace) => workspace.id === file.activeWorkspaceId);
}

export async function addOrUpdateWorkspace(input: AddWorkspaceInput): Promise<WorkspaceProfile> {
  const layout = await ensureHermsecAppData();
  const now = (input.now ?? new Date()).toISOString();
  const rootPath = path.resolve(input.rootPath);
  const id = workspaceIdForRoot(rootPath);
  const displayName = input.displayName ?? path.basename(rootPath) ?? id;
  const reportDir = path.resolve(input.reportDir ?? path.join(layout.reportsDir, workspaceSlug(displayName, id)));
  const workspace: WorkspaceProfile = {
    schemaVersion: 1,
    id,
    displayName,
    rootPath,
    sourceKind: input.sourceKind ?? "local",
    ...(input.remoteUrl ? { remoteUrl: input.remoteUrl } : {}),
    reportDir,
    privacyMode: input.privacyMode ?? "local-only",
    scanMode: input.scanMode ?? "auto",
    projectConfigMode: input.projectConfigMode ?? "read-only",
    createdAt: now,
    updatedAt: now,
  };

  const saved = await workspaceStore().update((file) => {
    const existing = file.workspaces.find((item) => item.id === id);
    const nextWorkspace = existing
      ? { ...existing, ...workspace, createdAt: existing.createdAt, updatedAt: now }
      : workspace;
    const workspaces = [
      nextWorkspace,
      ...file.workspaces.filter((item) => item.id !== id),
    ];
    return {
      schemaVersion: 1,
      activeWorkspaceId: id,
      workspaces,
    };
  });

  await updateRecentWorkspaces(id);
  const result = saved.workspaces.find((item) => item.id === id);
  if (!result) {
    throw new Error(`Workspace ${id} was not saved`);
  }
  return result;
}

export async function setActiveWorkspace(workspaceId: string): Promise<WorkspaceProfile> {
  const saved = await workspaceStore().update((file) => {
    if (!file.workspaces.some((workspace) => workspace.id === workspaceId)) {
      throw new Error(`Unknown workspace: ${workspaceId}`);
    }
    return { ...file, activeWorkspaceId: workspaceId };
  });
  await updateRecentWorkspaces(workspaceId);
  const workspace = saved.workspaces.find((item) => item.id === workspaceId);
  if (!workspace) {
    throw new Error(`Unknown workspace: ${workspaceId}`);
  }
  return workspace;
}

export async function updateWorkspace(
  workspaceId: string,
  mutator: (workspace: WorkspaceProfile) => WorkspaceProfile,
): Promise<WorkspaceProfile> {
  const saved = await workspaceStore().update((file) => {
    const index = file.workspaces.findIndex((workspace) => workspace.id === workspaceId);
    if (index === -1) {
      throw new Error(`Unknown workspace: ${workspaceId}`);
    }
    const current = file.workspaces[index];
    if (!current) {
      throw new Error(`Unknown workspace: ${workspaceId}`);
    }
    const next = [...file.workspaces];
    next[index] = validateWorkspaceProfile({
      ...mutator(current),
      updatedAt: new Date().toISOString(),
    });
    return { ...file, workspaces: next };
  });
  const workspace = saved.workspaces.find((item) => item.id === workspaceId);
  if (!workspace) {
    throw new Error(`Unknown workspace: ${workspaceId}`);
  }
  return workspace;
}
