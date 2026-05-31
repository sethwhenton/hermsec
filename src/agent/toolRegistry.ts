import type { ToolContext, ToolPermission } from "./permissions.js";
import { readOnlyPermission } from "./permissions.js";

export type JsonSchema = Record<string, unknown>;

export type HermsecTool<I = unknown, O = unknown> = {
  name: string;
  description: string;
  inputSchema: JsonSchema;
  outputSchema: JsonSchema;
  permission: ToolPermission;
  run(input: I, context: ToolContext): Promise<O>;
};

export type ToolRegistry = ReadonlyMap<string, HermsecTool>;

export const allowedToolNames = [
  "workspace.select",
  "workspace.describe",
  "workspace.listFilesSafe",
  "workspace.readSnippetSafe",
  "scan.plan",
  "scan.run",
  "scan.status",
  "scan.getFindings",
  "report.render",
  "report.openLocation",
  "intel.update",
  "intel.matchWorkspace",
  "schedule.create",
  "schedule.list",
  "schedule.disable",
  "provider.list",
  "provider.healthCheck",
  "provider.setPreference"
] as const;

export const forbiddenToolNames = [
  "shell.run",
  "file.write",
  "file.edit",
  "package.install",
  "dependency.execute",
  "web.fetch.any",
  "repo.modify",
  "git.push",
  "secret.readRaw",
  "subagent.spawn",
  "javascript.eval"
] as const;

export type AllowedToolName = (typeof allowedToolNames)[number];

export function createToolRegistry(tools: readonly HermsecTool[] = []): ToolRegistry {
  const registry = new Map<string, HermsecTool>();
  for (const tool of tools) {
    registerTool(registry, tool);
  }
  return registry;
}

export function registerTool(registry: Map<string, HermsecTool>, tool: HermsecTool): void {
  if (!isAllowedToolName(tool.name)) {
    throw new Error(`Tool is not allowed in Hermsec runtime: ${tool.name}`);
  }
  if (isForbiddenToolName(tool.name)) {
    throw new Error(`Forbidden tool cannot be registered: ${tool.name}`);
  }
  registry.set(tool.name, tool);
}

export function defaultToolPermission(name: AllowedToolName): ToolPermission {
  if (name.startsWith("report.") || name.startsWith("provider.setPreference")) {
    return readOnlyPermission({ writeAppData: true, requiresUserApproval: true });
  }
  if (name.startsWith("scan.run")) {
    return readOnlyPermission({ requiresUserApproval: true });
  }
  if (name.startsWith("intel.")) {
    return readOnlyPermission({ network: "trusted-intel", allowedInOfflineMode: false });
  }
  if (name.startsWith("provider.healthCheck")) {
    return readOnlyPermission({ network: "model-provider", allowedInOfflineMode: false });
  }
  return readOnlyPermission();
}

function isAllowedToolName(name: string): name is AllowedToolName {
  return (allowedToolNames as readonly string[]).includes(name);
}

function isForbiddenToolName(name: string): boolean {
  return (forbiddenToolNames as readonly string[]).includes(name);
}
