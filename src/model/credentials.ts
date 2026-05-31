import type { ModelProviderId } from "./provider.js";

export type EnvCredentialStatus = {
  envName: string;
  present: boolean;
};

export const providerCredentialEnv: Partial<Record<ModelProviderId, string>> = {
  "opencode-go": "OPENCODE_GO_API_KEY",
  openai: "OPENAI_API_KEY",
  openrouter: "OPENROUTER_API_KEY",
  claude: "ANTHROPIC_API_KEY",
  gemini: "GEMINI_API_KEY"
};

export function credentialStatusFromEnv(envName: string): EnvCredentialStatus {
  return {
    envName,
    present: Boolean(process.env[envName])
  };
}

export function readCredentialFromEnv(envName: string): string | undefined {
  const value = process.env[envName];
  return value && value.trim().length > 0 ? value : undefined;
}

export function requireCredentialFromEnv(envName: string): string {
  const value = readCredentialFromEnv(envName);
  if (!value) {
    throw new Error(`Missing provider credential environment variable: ${envName}`);
  }
  return value;
}
