import path from "node:path";
import type { CommandResult } from "../shared/types.js";
import {
  addWorkspace as addWorkspaceProfile,
  listWorkspaceSummaries,
  useWorkspace as setWorkspace,
} from "./workspaceManager.js";
import { listWorkspaces } from "../storage/workspaceStore.js";

export async function listWorkspacesCommand(): Promise<CommandResult> {
  const workspaces = await listWorkspaceSummaries();
  return {
    ok: true,
    message: workspaces.length
      ? workspaces.map((workspace) => `${workspace.id}\t${workspace.displayName}\t${workspace.rootPath}`).join("\n")
      : "No workspaces configured.",
    data: { workspaces },
  };
}

export { listWorkspacesCommand as listWorkspaces };

export async function addWorkspace(options: {
  cwd: string;
  target: string;
  name?: string;
}): Promise<CommandResult> {
  const workspace = await addWorkspaceProfile({
    rootPath: path.resolve(options.cwd, options.target),
    ...(options.name ? { displayName: options.name } : {}),
  });
  return {
    ok: true,
    message: `Added workspace ${workspace.displayName}: ${workspace.id}`,
    data: { workspace },
  };
}

export async function useWorkspace(options: {
  cwd: string;
  selector: string;
}): Promise<CommandResult> {
  const workspaces = await listWorkspaces();
  const resolved = path.resolve(options.cwd, options.selector);
  const workspace =
    workspaces.find((item) => item.id === options.selector) ??
    workspaces.find((item) => item.displayName.toLowerCase() === options.selector.toLowerCase()) ??
    workspaces.find((item) => item.rootPath === resolved);
  if (!workspace) {
    return {
      ok: false,
      errorCode: "WORKSPACE_NOT_FOUND",
      message: `Workspace not found: ${options.selector}`,
      remediation: "Run `hermsec workspace list` or `hermsec workspace add <path>`.",
    };
  }
  const active = await setWorkspace(workspace.id);
  return {
    ok: true,
    message: `Using workspace ${active.displayName}: ${active.rootPath}`,
    data: { workspace: active },
  };
}
