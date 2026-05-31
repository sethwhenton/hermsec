import { ensureHermsecAppData } from "../storage/appData.js";
import type { CommandResult } from "../shared/types.js";

export async function runSync(options: { cwd: string; offline?: boolean }): Promise<CommandResult> {
  const layout = await ensureHermsecAppData();
  return {
    ok: true,
    message: options.offline
      ? "Offline state is ready; remote sync is disabled."
      : "Local state is ready. Remote queue sync is reserved for online enrichment.",
    data: {
      appDataDir: layout.appDataDir,
      queueDir: layout.queueDir,
    },
  };
}
