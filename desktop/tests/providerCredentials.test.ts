import assert from "node:assert/strict";
import test from "node:test";
import type { ProviderConfig } from "../src/renderer/src/types/settings.ts";
import {
  isEnvironmentVariableName,
  normalizeProviderCredential,
  redactExactCredential,
  resolveCredentialValue,
  safeEnvironmentVariableName,
} from "../src/main/providerCredentials.ts";
import { isLoopbackProviderUrl } from "../src/shared/providerSecurity.ts";

function provider(overrides: Partial<ProviderConfig> = {}): ProviderConfig {
  return {
    id: "openrouter",
    presetId: "openrouter",
    displayName: "OpenRouter",
    baseUrl: "https://openrouter.ai/api/v1",
    apiFormat: "openai-compatible",
    authKind: "api_key",
    apiKeyEnvVar: "OPENROUTER_API_KEY",
    enabled: true,
    supportsModelDiscovery: true,
    models: [{ id: "openrouter/auto", label: "OpenRouter Auto", enabled: true }],
    modelDiscovery: { status: "idle" },
    ...overrides,
  };
}

test("recognizes only valid environment-variable names", () => {
  assert.equal(isEnvironmentVariableName("OPENROUTER_API_KEY"), true);
  assert.equal(isEnvironmentVariableName("_HERMSEC_KEY_2"), true);
  assert.equal(isEnvironmentVariableName("key-with-dashes"), false);
  assert.equal(isEnvironmentVariableName("secret.value"), false);
});

test("migrates a credential misplaced in the environment-variable field", () => {
  const misplacedCredential = ["sk", "or", "test-credential"].join("-");
  const migrated = normalizeProviderCredential(
    provider({ apiKeyEnvVar: misplacedCredential }),
    "OPENROUTER_API_KEY",
  );

  assert.equal(migrated.apiKey, misplacedCredential);
  assert.equal(migrated.apiKeyEnvVar, "OPENROUTER_API_KEY");
  assert.equal(resolveCredentialValue(migrated), misplacedCredential);
});

test("never uses an invalid environment-field value as a display label", () => {
  const misplacedCredential = ["sk", "or", "test-credential"].join("-");
  assert.equal(
    safeEnvironmentVariableName(misplacedCredential, "OPENROUTER_API_KEY"),
    "OPENROUTER_API_KEY",
  );
});

test("redacts every exact occurrence of an opaque submitted credential", () => {
  const credential = "opaqueCredentialValue123";
  assert.equal(
    redactExactCredential(
      `Provider rejected ${credential}; retrying ${credential} is not allowed.`,
      credential,
    ),
    "Provider rejected [REDACTED]; retrying [REDACTED] is not allowed.",
  );
});

test("only exact loopback hostnames are treated as local providers", () => {
  assert.equal(isLoopbackProviderUrl("http://localhost:11434/v1"), true);
  assert.equal(isLoopbackProviderUrl("http://127.0.0.1:11434/v1"), true);
  assert.equal(isLoopbackProviderUrl("http://[::1]:11434/v1"), true);
  assert.equal(isLoopbackProviderUrl("http://localhost.attacker.example/v1"), false);
  assert.equal(isLoopbackProviderUrl("http://127.0.0.1.attacker.example/v1"), false);
  assert.equal(isLoopbackProviderUrl("not a URL"), false);
});
