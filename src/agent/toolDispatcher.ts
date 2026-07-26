import { redactForModel } from "./redaction.js";
import { assertToolPermission, assertToolWorkspace, type ToolContext } from "./permissions.js";
import type { ToolRegistry } from "./toolRegistry.js";
import { isInspectionToolName, type InspectionToolName } from "./toolProtocol.js";

export type DispatchedToolResult = {
  name: InspectionToolName;
  output: unknown;
  redactionMarkers: string[];
  qualifiesFinalEvidence: boolean;
};

export async function dispatchTool(
  registry: ToolRegistry,
  name: string,
  input: unknown,
  context: ToolContext,
): Promise<DispatchedToolResult> {
  if (!isInspectionToolName(name)) {
    throw new Error(`Unregistered Hermsec inspection tool: ${name}`);
  }
  const tool = registry.tools.get(name);
  if (!tool) {
    throw new Error(`Unregistered Hermsec inspection tool: ${name}`);
  }
  assertToolPermission(tool.permission, context);
  await assertToolWorkspace(context, registry.workspaceRoot);

  const validatedInput = tool.validateInput(input);
  const rawOutput = await tool.run(validatedInput, context);
  const validatedOutput = tool.validateOutput(rawOutput);
  let qualifiesFinalEvidence = false;
  try {
    qualifiesFinalEvidence =
      tool.qualifiesFinalEvidence?.(validatedInput, validatedOutput) === true;
  } catch {
    // Final-evidence qualification is a fail-closed local policy check.
  }
  const redacted = redactForModel(validatedOutput);
  return {
    name,
    output: redacted.value,
    redactionMarkers: redacted.markers,
    qualifiesFinalEvidence,
  };
}
