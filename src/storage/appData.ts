import { ensureDirectory } from "./jsonStore.js";
import { getHermsecAppDataLayout, type HermsecAppDataLayout } from "./platformPaths.js";

const appDataDirectories = (layout: HermsecAppDataLayout): string[] => [
  layout.appDataDir,
  layout.cacheDir,
  layout.tempDir,
  layout.sessionsDir,
  layout.reportsDir,
  layout.runsDir,
  layout.queueDir,
  layout.logsDir,
  layout.baselinesDir,
  layout.intelDir,
];

export async function ensureHermsecAppData(
  layout: HermsecAppDataLayout = getHermsecAppDataLayout(),
): Promise<HermsecAppDataLayout> {
  await Promise.all(appDataDirectories(layout).map((directory) => ensureDirectory(directory)));
  return layout;
}

export function getAppDataLayout(): HermsecAppDataLayout {
  return getHermsecAppDataLayout();
}
