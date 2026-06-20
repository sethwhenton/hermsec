import os from "node:os";
import path from "node:path";
import process from "node:process";

export type HermsecPlatformPaths = {
  appDataDir: string;
  cacheDir: string;
  tempDir: string;
};

function homeDir(): string {
  return process.env.HOME ?? os.homedir() ?? process.cwd();
}

export function getHermsecPlatformPaths(env: NodeJS.ProcessEnv = process.env): HermsecPlatformPaths {
  if (env.HERMSEC_HOME) {
    return {
      appDataDir: path.resolve(env.HERMSEC_HOME),
      cacheDir: path.join(path.resolve(env.HERMSEC_HOME), "Cache"),
      tempDir: path.join(env.TEMP ?? env.TMP ?? os.tmpdir(), "Hermsec"),
    };
  }

  if (process.platform === "win32") {
    const appDataBase = env.APPDATA ?? env.LOCALAPPDATA ?? homeDir();
    const cacheBase = env.LOCALAPPDATA ?? appDataBase;
    return {
      appDataDir: path.join(appDataBase, "Hermsec"),
      cacheDir: path.join(cacheBase, "Hermsec", "Cache"),
      tempDir: path.join(env.TEMP ?? env.TMP ?? os.tmpdir(), "Hermsec"),
    };
  }

  if (process.platform === "darwin") {
    const home = homeDir();
    return {
      appDataDir: path.join(home, "Library", "Application Support", "Hermsec"),
      cacheDir: path.join(home, "Library", "Caches", "Hermsec"),
      tempDir: path.join(env.TMPDIR ?? os.tmpdir(), "Hermsec"),
    };
  }

  const home = homeDir();
  return {
    appDataDir: path.join(env.XDG_STATE_HOME ?? path.join(home, ".local", "state"), "hermsec"),
    cacheDir: path.join(env.XDG_CACHE_HOME ?? path.join(home, ".cache"), "hermsec"),
    tempDir: path.join(env.TMPDIR ?? os.tmpdir(), "hermsec"),
  };
}

export type HermsecAppDataLayout = HermsecPlatformPaths & {
  configFile: string;
  workspacesFile: string;
  schedulesFile: string;
  sessionsDir: string;
  reportsDir: string;
  reportIndexFile: string;
  runsDir: string;
  queueDir: string;
  logsDir: string;
  migrationsFile: string;
  baselinesDir: string;
  intelDir: string;
};

export function getHermsecAppDataLayout(env: NodeJS.ProcessEnv = process.env): HermsecAppDataLayout {
  const roots = getHermsecPlatformPaths(env);
  return {
    ...roots,
    configFile: path.join(roots.appDataDir, "config.json"),
    workspacesFile: path.join(roots.appDataDir, "workspaces.json"),
    schedulesFile: path.join(roots.appDataDir, "schedules.json"),
    sessionsDir: path.join(roots.appDataDir, "sessions"),
    reportsDir: path.join(roots.appDataDir, "reports"),
    reportIndexFile: path.join(roots.appDataDir, "reports", "index.json"),
    runsDir: path.join(roots.appDataDir, "runs"),
    queueDir: path.join(roots.appDataDir, "queue"),
    logsDir: path.join(roots.appDataDir, "logs"),
    migrationsFile: path.join(roots.appDataDir, "migrations.json"),
    baselinesDir: path.join(roots.appDataDir, "baselines"),
    intelDir: path.join(roots.appDataDir, "intel"),
  };
}
