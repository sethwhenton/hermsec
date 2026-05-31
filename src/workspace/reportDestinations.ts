import path from "node:path";
import { appDataReportRootForWorkspace } from "../storage/reportStore.js";
import type { ProjectConfig } from "../storage/projectConfig.js";
import type { UserConfig } from "../storage/userConfig.js";
import type { WorkspaceProfile } from "../storage/workspaceStore.js";

export type ResolvedReportDestination = {
  kind: "app-data" | "project-local" | "custom" | "workspace-default" | "ask";
  directory: string;
  requiresPrompt: boolean;
};

export function resolveReportDestination(
  workspace: WorkspaceProfile,
  config?: UserConfig,
  projectConfig?: ProjectConfig,
  callerProvidedDir?: string,
): ResolvedReportDestination {
  if (callerProvidedDir) {
    return {
      kind: "custom",
      directory: path.resolve(callerProvidedDir),
      requiresPrompt: false,
    };
  }

  if (projectConfig?.reports?.location === "custom" && projectConfig.reports.customDir) {
    return {
      kind: "custom",
      directory: path.resolve(projectConfig.reports.customDir),
      requiresPrompt: false,
    };
  }

  if (projectConfig?.reports?.location === "project-local") {
    return {
      kind: "project-local",
      directory: path.join(workspace.rootPath, ".hermsec", "reports"),
      requiresPrompt: false,
    };
  }

  if (projectConfig?.reports?.location === "app-data") {
    return {
      kind: "app-data",
      directory: appDataReportRootForWorkspace(workspace),
      requiresPrompt: false,
    };
  }

  if (config?.defaultReportLocation === "custom" && config.customReportDir) {
    return {
      kind: "custom",
      directory: path.resolve(config.customReportDir),
      requiresPrompt: false,
    };
  }

  if (config?.defaultReportLocation === "project-local") {
    return {
      kind: "project-local",
      directory: path.join(workspace.rootPath, ".hermsec", "reports"),
      requiresPrompt: false,
    };
  }

  if (config?.defaultReportLocation === "ask") {
    return {
      kind: "ask",
      directory: workspace.reportDir,
      requiresPrompt: true,
    };
  }

  return {
    kind: workspace.reportDir ? "workspace-default" : "app-data",
    directory: workspace.reportDir || appDataReportRootForWorkspace(workspace),
    requiresPrompt: false,
  };
}
