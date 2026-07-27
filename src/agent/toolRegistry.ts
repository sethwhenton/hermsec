import type { ModelToolDefinition } from "../model/provider.js";
import type { ToolContext, ToolPermission } from "./permissions.js";
import { isInspectionToolName, type InspectionToolName } from "./toolProtocol.js";

export type JsonSchema = Record<string, unknown>;

export type HermsecTool<I = unknown, O = unknown> = {
  name: InspectionToolName;
  description: string;
  inputSchema: JsonSchema;
  outputSchema: JsonSchema;
  permission: ToolPermission;
  validateInput(input: unknown): I;
  validateOutput(output: unknown): O;
  run(input: I, context: ToolContext): Promise<O>;
  qualifiesFinalEvidence?(input: I, output: O): boolean;
};

export type ToolRegistry = {
  workspaceRoot: string;
  tools: ReadonlyMap<InspectionToolName, HermsecTool>;
};

export function createToolRegistry(
  workspaceRoot: string,
  tools: readonly HermsecTool[] = [],
): ToolRegistry {
  if (!workspaceRoot.trim()) {
    throw new Error("Tool registry requires an active workspace root.");
  }
  const registry = new Map<InspectionToolName, HermsecTool>();
  for (const tool of tools) {
    registerTool(registry, tool);
  }
  return {
    workspaceRoot,
    tools: registry,
  };
}

export function registerTool(
  registry: Map<InspectionToolName, HermsecTool>,
  tool: HermsecTool,
): void {
  if (!isInspectionToolName(tool.name)) {
    throw new Error(`Tool is not allowed in the inspection runtime: ${tool.name}`);
  }
  if (registry.has(tool.name)) {
    throw new Error(`Duplicate inspection tool registration: ${tool.name}`);
  }
  registry.set(tool.name, tool);
}

export function toolDefinitions(registry: ToolRegistry): ModelToolDefinition[] {
  return [...registry.tools.values()].map((tool) => ({
    type: "function",
    function: {
      name: tool.name,
      description: tool.description,
      parameters: tool.inputSchema,
    },
  }));
}
