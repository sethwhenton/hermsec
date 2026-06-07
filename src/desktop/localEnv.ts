import fs from "node:fs";
import path from "node:path";

export function loadLocalEnv(cwd = process.cwd(), fileName = ".env.local"): string | undefined {
  const filePath = path.resolve(cwd, fileName);
  if (!fs.existsSync(filePath)) {
    return undefined;
  }
  const raw = fs.readFileSync(filePath, "utf8");
  for (const rawLine of raw.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) {
      continue;
    }
    const separator = line.indexOf("=");
    if (separator <= 0) {
      continue;
    }
    const key = line.slice(0, separator).trim();
    const value = stripQuotes(line.slice(separator + 1).trim());
    if (/^[A-Z_][A-Z0-9_]*$/i.test(key) && process.env[key] === undefined) {
      process.env[key] = value;
    }
  }
  return filePath;
}

function stripQuotes(value: string): string {
  if ((value.startsWith("\"") && value.endsWith("\"")) || (value.startsWith("'") && value.endsWith("'"))) {
    return value.slice(1, -1);
  }
  return value;
}
