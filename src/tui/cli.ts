import { ensureHermsecAppData } from "../storage/appData.js";
import { loadUserConfig } from "../storage/userConfig.js";
import type { CommandResult } from "../shared/types.js";
import { runTui } from "./index.js";

export async function launchChat(options: {
  cwd: string;
  args: string[];
  firstRun: boolean;
}): Promise<CommandResult> {
  const summary = await runTui({
    cwd: options.cwd,
    skipOnboarding: !options.firstRun,
  });
  return {
    ok: true,
    message:
      summary.exitReason === "non-interactive"
        ? "Hermsec chat needs an interactive terminal. Use `hermsec --help` for commands."
        : "Chat session finished.",
    data: summary,
  };
}

export async function runOnboarding(options: { cwd: string; args: string[] }): Promise<CommandResult> {
  const layout = await ensureHermsecAppData();
  const config = await loadUserConfig();
  return {
    ok: true,
    message: `Onboarding ready. Config: ${layout.configFile}. Reports: ${config.customReportDir ?? layout.reportsDir}`,
    data: {
      appDataDir: layout.appDataDir,
      configPath: layout.configFile,
      reportDirectory: config.customReportDir ?? layout.reportsDir,
      privacyMode: config.privacyMode,
    },
  };
}
