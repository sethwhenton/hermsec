import { assertToolPermission, type ToolContext } from "./permissions.js";
import type { ToolRegistry } from "./toolRegistry.js";

export async function dispatchTool<I = unknown, O = unknown>(
  registry: ToolRegistry,
  name: string,
  input: I,
  context: ToolContext
): Promise<O> {
  const tool = registry.get(name);
  if (!tool) {
    throw new Error(`Unregistered Hermsec tool: ${name}`);
  }
  assertToolPermission(tool.permission, context);
  return tool.run(input, context) as Promise<O>;
}
