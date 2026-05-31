import { runScan } from "../core/harness.js";
import type { CommandResult, ScanMode } from "../shared/types.js";

export async function watchTarget(options: {
  cwd: string;
  target: string;
  afterIdle: string;
  mode: ScanMode;
}): Promise<CommandResult> {
  const result = await runScan({
    cwd: options.cwd,
    target: options.target,
    mode: options.mode,
    formats: ["json", "md", "html"],
    useModel: false,
  });
  if (!result.ok) {
    return result;
  }
  return {
    ok: true,
    message: `Watch scan completed after ${options.afterIdle}: ${result.message}`,
    data: result.data,
  };
}
