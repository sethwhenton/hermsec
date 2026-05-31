import crypto from "node:crypto";
import type { ModelProviderId } from "./provider.js";

export type EnvCredentialStatus = {
  envName: string;
  validEnvName: boolean;
  present: boolean;
  fingerprint?: string;
};

export const providerCredentialEnv: Partial<Record<ModelProviderId, string>> = {
  "opencode-go": "OPENCODE_GO_API_KEY",
  openai: "OPENAI_API_KEY",
  openrouter: "OPENROUTER_API_KEY",
  claude: "ANTHROPIC_API_KEY",
  gemini: "GEMINI_API_KEY"
};

const invalidCredentialEnvName = "<invalid-env-name>";
const envNamePattern = /^[A-Za-z_][A-Za-z0-9_]*$/;
const secretValuePrefixPattern =
  /^(?:sk-|gh[pousr]_|github_pat_|glpat-|xox[baprs]-|AKIA|ASIA|AIza|ya29\.|HERMSEC_FAKE_TEST_TOKEN_DO_NOT_USE)/i;

export function credentialStatusFromEnv(envName: string): EnvCredentialStatus {
  const safeName = normalizeCredentialEnvName(envName);
  if (!safeName) {
    return {
      envName: invalidCredentialEnvName,
      validEnvName: false,
      present: false
    };
  }

  const value = readCredentialValueFromEnv(safeName);
  return {
    envName: safeName,
    validEnvName: true,
    present: Boolean(value),
    ...(value ? { fingerprint: credentialFingerprint(value) } : {})
  };
}

export function readCredentialFromEnv(envName: string): string | undefined {
  const safeName = normalizeCredentialEnvName(envName);
  if (!safeName) {
    return undefined;
  }
  return readCredentialValueFromEnv(safeName);
}

export function requireCredentialFromEnv(envName: string): string {
  const safeName = normalizeCredentialEnvName(envName);
  if (!safeName) {
    throw new Error("Provider credential reference must be an environment variable name, not a key value.");
  }
  const value = readCredentialFromEnv(envName);
  if (!value) {
    throw new Error(`Missing provider credential environment variable: ${safeName}`);
  }
  return value;
}

export function normalizeCredentialEnvName(envName: string | undefined): string | undefined {
  const trimmed = envName?.trim();
  if (!trimmed || !envNamePattern.test(trimmed) || secretValuePrefixPattern.test(trimmed)) {
    return undefined;
  }
  return trimmed;
}

export function credentialFingerprint(value: string): string {
  return `sha256:${crypto.createHash("sha256").update(value).digest("hex").slice(0, 12)}`;
}

function readCredentialValueFromEnv(envName: string): string | undefined {
  const value = process.env[envName];
  return value && value.trim().length > 0 ? value : undefined;
}
