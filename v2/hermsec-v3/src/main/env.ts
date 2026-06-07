import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

function findRepoRoot(startDir: string): string {
  let current = resolve(startDir);
  for (let i = 0; i < 8; i += 1) {
    const envPath = join(current, ".env.local");
    if (existsSync(envPath)) {
      return current;
    }
    const parent = dirname(current);
    if (parent === current) {
      break;
    }
    current = parent;
  }
  return resolve(startDir);
}

export function loadEnvFile(): void {
  const moduleDir = dirname(fileURLToPath(import.meta.url));
  const repoRoot = findRepoRoot(join(moduleDir, "..", "..", ".."));
  const envPath = join(repoRoot, ".env.local");

  if (!existsSync(envPath)) {
    return;
  }

  try {
    process.loadEnvFile(envPath);
  } catch {
    // Safe no-op if loadEnvFile is unavailable or file is malformed.
  }
}

export function getEnvDefaults() {
  return {
    model: process.env.HERMSEC_MODEL ?? "deepseek-v4-flash",
    baseUrl: process.env.HERMSEC_MODEL_BASE_URL ?? "https://api.opencode.ai/v1",
    provider: process.env.HERMSEC_MODEL_PROVIDER ?? "opencode-go",
    apiKeyEnvVar: process.env.HERMSEC_MODEL_API_KEY_ENV ?? "HERMSEC_MODEL_API_KEY",
  };
}
