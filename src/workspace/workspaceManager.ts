import fs from "node:fs/promises";
import {
  addOrUpdateWorkspace,
  getActiveWorkspace,
  getWorkspace,
  listWorkspaces,
  readProjectConfig,
  setActiveWorkspace,
  type AddWorkspaceInput,
  type ProjectConfig,
  type WorkspaceProfile,
} from "../storage/index.js";
import { resolveReportDestination, type ResolvedReportDestination } from "./reportDestinations.js";
import type { UserConfig } from "../storage/userConfig.js";

export type WorkspaceSummary = {
  id: string;
  displayName: string;
  rootPath: string;
  reportDir: string;
  privacyMode: WorkspaceProfile["privacyMode"];
  scanMode: WorkspaceProfile["scanMode"];
  exists: boolean;
  lastScanId?: string;
  lastScannedCommit?: string;
};

export type WorkspaceContext = {
  workspace: WorkspaceProfile;
  projectConfig?: ProjectConfig;
  reportDestination: ResolvedReportDestination;
};

async function exists(pathName: string): Promise<boolean> {
  try {
    await fs.access(pathName);
    return true;
  } catch {
    return false;
  }
}

export async function addWorkspace(input: AddWorkspaceInput): Promise<WorkspaceProfile> {
  return addOrUpdateWorkspace(input);
}

export async function useWorkspace(workspaceId: string): Promise<WorkspaceProfile> {
  return setActiveWorkspace(workspaceId);
}

export async function findWorkspace(workspaceId: string): Promise<WorkspaceProfile | undefined> {
  return getWorkspace(workspaceId);
}

export async function listWorkspaceSummaries(): Promise<WorkspaceSummary[]> {
  const workspaces = await listWorkspaces();
  return Promise.all(
    workspaces.map(async (workspace) => ({
      id: workspace.id,
      displayName: workspace.displayName,
      rootPath: workspace.rootPath,
      reportDir: workspace.reportDir,
      privacyMode: workspace.privacyMode,
      scanMode: workspace.scanMode,
      exists: await exists(workspace.rootPath),
      ...(workspace.lastScanId ? { lastScanId: workspace.lastScanId } : {}),
      ...(workspace.lastScannedCommit ? { lastScannedCommit: workspace.lastScannedCommit } : {}),
    })),
  );
}

export async function loadWorkspaceContext(
  workspaceId?: string,
  config?: UserConfig,
  callerProvidedReportDir?: string,
): Promise<WorkspaceContext | undefined> {
  const workspace = workspaceId ? await getWorkspace(workspaceId) : await getActiveWorkspace();
  if (!workspace) {
    return undefined;
  }

  const projectConfig = workspace.projectConfigMode === "none"
    ? undefined
    : await readProjectConfig(workspace.rootPath);

  return {
    workspace,
    ...(projectConfig ? { projectConfig } : {}),
    reportDestination: resolveReportDestination(
      workspace,
      config,
      projectConfig,
      callerProvidedReportDir,
    ),
  };
}

export function summarizeWorkspace(workspace: WorkspaceProfile): WorkspaceSummary {
  return {
    id: workspace.id,
    displayName: workspace.displayName,
    rootPath: workspace.rootPath,
    reportDir: workspace.reportDir,
    privacyMode: workspace.privacyMode,
    scanMode: workspace.scanMode,
    exists: true,
    ...(workspace.lastScanId ? { lastScanId: workspace.lastScanId } : {}),
    ...(workspace.lastScannedCommit ? { lastScannedCommit: workspace.lastScannedCommit } : {}),
  };
}
