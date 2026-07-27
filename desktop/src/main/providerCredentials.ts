import type { ProviderConfig } from "../renderer/src/types/settings";

const ENVIRONMENT_VARIABLE_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/u;

type CredentialFields = Pick<ProviderConfig, "apiKey" | "apiKeyEnvVar">;

export function isEnvironmentVariableName(value: string | undefined): value is string {
  const trimmed = value?.trim();
  return Boolean(trimmed && ENVIRONMENT_VARIABLE_NAME.test(trimmed));
}

export function normalizeProviderCredential(
  provider: ProviderConfig,
  fallbackEnvironmentVariable: string | undefined,
): ProviderConfig {
  const apiKey = provider.apiKey?.trim();
  const environmentValue = provider.apiKeyEnvVar?.trim();
  if (!environmentValue || isEnvironmentVariableName(environmentValue)) {
    return provider;
  }

  return {
    ...provider,
    apiKey: apiKey || environmentValue,
    apiKeyEnvVar: fallbackEnvironmentVariable,
  };
}

export function resolveCredentialValue(
  fields: CredentialFields,
  fallbackEnvironmentVariables: Array<string | undefined> = [],
): string | undefined {
  const apiKey = fields.apiKey?.trim();
  if (apiKey) return apiKey;

  const environmentValue = fields.apiKeyEnvVar?.trim();
  if (environmentValue && !isEnvironmentVariableName(environmentValue)) {
    return environmentValue;
  }

  const environmentVariables = [
    environmentValue,
    ...fallbackEnvironmentVariables,
  ].filter(isEnvironmentVariableName);
  for (const environmentVariable of Array.from(new Set(environmentVariables))) {
    const value = process.env[environmentVariable]?.trim();
    if (value) return value;
  }

  return undefined;
}

export function safeEnvironmentVariableName(
  value: string | undefined,
  fallback: string | undefined,
): string | undefined {
  if (isEnvironmentVariableName(value)) return value?.trim();
  if (isEnvironmentVariableName(fallback)) return fallback?.trim();
  return undefined;
}

export function redactExactCredential(
  value: string,
  credential: string | undefined,
): string {
  const exactCredential = credential?.trim();
  if (!exactCredential) return value;
  return value.split(exactCredential).join("[REDACTED]");
}
