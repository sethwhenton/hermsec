import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

function findEnvFiles(startDir: string): string[] {
  const envFiles: string[] = [];
  let current = resolve(startDir);
  for (let i = 0; i < 8; i += 1) {
    const envPath = join(current, ".env.local");
    if (existsSync(envPath)) {
      envFiles.push(envPath);
    }
    const parent = dirname(current);
    if (parent === current) {
      break;
    }
    current = parent;
  }
  return envFiles.reverse();
}

export function loadEnvFile(): void {
  const moduleDir = dirname(fileURLToPath(import.meta.url));
  const envFiles = findEnvFiles(join(moduleDir, "..", "..", ".."));

  for (const envPath of envFiles) {
    try {
      process.loadEnvFile(envPath);
    } catch {
      // Safe no-op if loadEnvFile is unavailable or file is malformed.
    }
  }
}

export function getEnvDefaults() {
  const provider = nonEmpty(process.env.HERMSEC_MODEL_PROVIDER) ?? "opencode-go";
  return {
    model: nonEmpty(process.env.HERMSEC_MODEL) ?? "deepseek-v4-flash",
    baseUrl: nonEmpty(process.env.HERMSEC_MODEL_BASE_URL) ?? defaultBaseUrl(provider),
    provider,
    apiKeyEnvVar: nonEmpty(process.env.HERMSEC_MODEL_API_KEY_ENV) ?? defaultApiKeyEnvVar(provider),
  };
}

function nonEmpty(value: string | undefined): string | undefined {
  const trimmed = value?.trim().replace(/^["']|["']$/g, "");
  return trimmed ? trimmed : undefined;
}

function defaultBaseUrl(provider: string): string {
  if (provider === "opencode-go") return "https://opencode.ai/zen/go/v1";
  return "https://api.openai.com/v1";
}

function defaultApiKeyEnvVar(provider: string): string {
  if (provider === "opencode-go") return "OPENCODE_GO_API_KEY";
  return "HERMSEC_MODEL_API_KEY";
}
