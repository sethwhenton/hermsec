import fs from "node:fs";
import path from "node:path";
import process from "node:process";

export function findExecutableOnPath(command: string, env: NodeJS.ProcessEnv = process.env): string | undefined {
  const pathValue = env.PATH;
  if (!pathValue) {
    return undefined;
  }

  for (const directory of pathValue.split(path.delimiter)) {
    if (!directory) {
      continue;
    }
    for (const suffix of executableSuffixes(command, env)) {
      const candidate = path.join(directory, `${command}${suffix}`);
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

function isFile(candidate: string): boolean {
  try {
    return fs.statSync(candidate).isFile();
  } catch {
    return false;
  }
}
