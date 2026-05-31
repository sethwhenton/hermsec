import { redactForLog } from "../agent/redaction.js";
import { credentialStatusFromEnv, normalizeCredentialEnvName, readCredentialFromEnv } from "./credentials.js";
import type { ModelProviderAdapter, ModelRequest, ModelResponse, ProviderConfig, ProviderHealth } from "./provider.js";

const defaultBaseUrl = "https://api.anthropic.com";
const defaultModel = "claude-sonnet-4-5";
const defaultCredentialEnv = "ANTHROPIC_API_KEY";

export const anthropicProvider: ModelProviderAdapter = {
  id: "claude",
  async listModels() {
    return [{ id: defaultModel, label: "Claude Sonnet", local: false }];
  },
  async healthCheck(config?: ProviderConfig): Promise<ProviderHealth> {
    const envName = config?.apiKeyEnv ?? defaultCredentialEnv;
    const credential = credentialStatusFromEnv(envName);
    if (!credential.validEnvName) {
      return invalidCredentialHealth();
    }
    return {
      ok: credential.present,
      provider: "claude",
      message: credential.present
        ? "Claude provider credential was verified from the environment."
        : `Missing provider credential environment variable: ${credential.envName}`,
      credential: credential.present ? "env-present" : "env-missing",
      credentialEnv: credential.envName,
      ...(credential.fingerprint ? { credentialFingerprint: credential.fingerprint } : {}),
      local: false,
    };
  },
  async complete(request: ModelRequest, config?: ProviderConfig): Promise<ModelResponse> {
    const envName = config?.apiKeyEnv ?? defaultCredentialEnv;
    const safeEnvName = normalizeCredentialEnvName(envName);
    if (!safeEnvName) {
      throw new Error("Provider credential reference must be an environment variable name, not a key value.");
    }
    const apiKey = readCredentialFromEnv(safeEnvName);
    if (!apiKey) {
      throw new Error(`Missing provider credential environment variable: ${safeEnvName}`);
    }

    const system = request.messages.filter((message) => message.role === "system").map((message) => message.content).join("\n\n");
    const messages = request.messages
      .filter((message) => message.role !== "system")
      .map((message) => ({
        role: message.role === "assistant" ? "assistant" : "user",
        content: message.content,
      }));
    const model = request.model ?? config?.model ?? defaultModel;
    const response = await fetch(`${stripTrailingSlash(config?.baseUrl ?? defaultBaseUrl)}/v1/messages`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model,
        max_tokens: request.maxTokens ?? 1000,
        temperature: request.temperature ?? 0,
        ...(system ? { system } : {}),
        messages,
      }),
      signal: AbortSignal.timeout(config?.timeoutMs ?? 30_000),
    });
    if (!response.ok) {
      const rawError = await response.text();
      const redacted = redactForLog(rawError).value;
      throw new Error(`claude provider request failed with ${response.status}: ${String(redacted).slice(0, 500)}`);
    }
    const payload = (await response.json()) as {
      model?: string;
      content?: Array<{ type?: string; text?: string }>;
      usage?: { input_tokens?: number; output_tokens?: number };
    };
    const content = (payload.content ?? []).map((part) => part.text ?? "").join("").trim();
    if (!content) {
      throw new Error("claude provider returned no text content.");
    }
    const promptTokens = payload.usage?.input_tokens;
    const completionTokens = payload.usage?.output_tokens;
    return {
      content,
      model: payload.model ?? model,
      provider: "claude",
      usage: {
        provider: "claude",
        model: payload.model ?? model,
        ...(promptTokens !== undefined ? { promptTokens } : {}),
        ...(completionTokens !== undefined ? { completionTokens } : {}),
        ...(promptTokens !== undefined && completionTokens !== undefined ? { totalTokens: promptTokens + completionTokens } : {}),
        local: false,
      },
    };
  },
  estimateCost() {
    return { local: false };
  },
};

function invalidCredentialHealth(): ProviderHealth {
  return {
    ok: false,
    provider: "claude",
    message: "Provider credential reference must be an environment variable name, not a key value.",
    credential: "env-missing",
    credentialEnv: "<invalid-env-name>",
    local: false,
  };
}

function stripTrailingSlash(value: string): string {
  return value.replace(/\/+$/, "");
}
