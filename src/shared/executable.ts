import fs from "node:fs";
import path from "node:path";
import process from "node:process";

export function findExecutableOnPath(command: string, env: NodeJS.ProcessEnv = process.env): string | undefined {
  const override = env[commandOverrideEnvName(command)];
  if (override && isFile(override)) {
    return override;
  }

  for (const directory of toolSearchDirectories(env)) {
    const candidate = findExecutableInDirectory(command, directory, env);
    if (candidate) {
      return candidate;
    }
  }

  for (const directory of pathDirectories(env)) {
    if (!directory) {
      continue;
    }
    const candidate = findExecutableInDirectory(command, directory, env, { directOnly: true });
    if (candidate) {
      return candidate;
    }
  }

  return undefined;
}

export function commandOverrideEnvName(command: string): string {
  return `HERMSEC_${command.replace(/[^a-zA-Z0-9]/g, "_").toUpperCase()}_BIN`;
}

export function toolSearchDirectories(env: NodeJS.ProcessEnv = process.env): string[] {
  return unique([
    ...splitPathList(env.HERMSEC_TOOLS_DIR),
    ...splitPathList(env.HERMSEC_BUNDLED_TOOLS_DIR),
  ]);
}

export function findExecutableInDirectory(
  command: string,
  directory: string,
  env: NodeJS.ProcessEnv = process.env,
  options: { directOnly?: boolean } = {},
): string | undefined {
  const base = path.resolve(directory);
  const subdirs = options.directOnly
    ? [base]
    : [
        base,
        path.join(base, "bin"),
        path.join(base, "native"),
        path.join(base, command),
        path.join(base, command, "Scripts"),
        path.join(base, command, "bin"),
        path.join(base, "python", command, "Scripts"),
        path.join(base, "python", command, "bin"),
      ];

  for (const subdir of subdirs) {
    for (const suffix of executableSuffixes(command, env)) {
      const candidate = path.join(subdir, `${command}${suffix}`);
      if (isFile(candidate)) {
        return candidate;
      }
    }
  }

  return undefined;
}

function executableSuffixes(command: string, env: NodeJS.ProcessEnv): string[] {
  if (path.extname(command) || process.platform !== "win32") {
    return [""];
  }
  const pathExt = env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD";
  return ["", ...pathExt.split(";").filter(Boolean).map((item) => item.toLowerCase())];
}

function pathDirectories(env: NodeJS.ProcessEnv): string[] {
  return splitPathList(env.PATH);
}

function splitPathList(value: string | undefined): string[] {
  return (value ?? "")
    .split(path.delimiter)
    .map((item) => item.trim())
    .filter(Boolean);
}

function unique(values: string[]): string[] {
  return Array.from(new Set(values));
}

function isFile(candidate: string): boolean {
  try {
    return fs.statSync(candidate).isFile();
  } catch {
    return false;
  }
}
