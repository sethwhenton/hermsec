import { redactForLog, sanitizeErrorMessage } from "../agent/redaction.js";
import { credentialStatusFromEnv, normalizeCredentialEnvName, readCredentialFromEnv } from "./credentials.js";
import type { ModelProviderAdapter, ModelRequest, ModelResponse, ProviderConfig, ProviderHealth } from "./provider.js";

const defaultBaseUrl = "https://api.anthropic.com";
const defaultModel = "claude-sonnet-4-5";
const defaultCredentialEnv = "ANTHROPIC_API_KEY";
const MAX_PROVIDER_RESPONSE_BYTES = 2_000_000;
const MAX_PROVIDER_ERROR_BYTES = 64_000;
const MAX_MODEL_CONTENT_BYTES = 1_000_000;

export const anthropicProvider: ModelProviderAdapter = {
  id: "claude",
  capabilities: {
    tools: false,
    jsonResponse: false,
    externalAbort: true,
    streaming: false,
  },
  async listModels() {
    return [{ id: defaultModel, label: "Claude Sonnet", local: false, supportsTools: false }];
  },
  async healthCheck(config?: ProviderConfig): Promise<ProviderHealth> {
    try {
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
    } catch (error) {
      return {
        ok: false,
        provider: "claude",
        message: `Claude health check failed: ${sanitizeErrorMessage(error)}`,
        credential: "env-missing",
        local: false,
      };
    }
  },
  async complete(request: ModelRequest, config?: ProviderConfig): Promise<ModelResponse> {
    assertNoToolProtocol(request);
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
    try {
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
        signal: request.signal
          ? AbortSignal.any([request.signal, AbortSignal.timeout(config?.timeoutMs ?? 30_000)])
          : AbortSignal.timeout(config?.timeoutMs ?? 30_000),
      });
      if (!response.ok) {
        const rawError = await readBoundedResponseText(response, MAX_PROVIDER_ERROR_BYTES);
        const redacted = redactForLog(rawError).value;
        throw new Error(`request failed with ${response.status}: ${String(redacted).slice(0, 500)}`);
      }
      const rawPayload = await readBoundedResponseText(response, MAX_PROVIDER_RESPONSE_BYTES);
      let payload: {
        model?: string;
        content?: Array<{ type?: string; text?: string }>;
        usage?: { input_tokens?: number; output_tokens?: number };
      };
      try {
        payload = JSON.parse(rawPayload) as typeof payload;
      } catch {
        throw new Error("provider returned invalid JSON.");
      }
      const contentParts = (payload.content ?? []).map((part) =>
        typeof part.text === "string" ? part.text : ""
      );
      for (const part of contentParts) {
        assertBoundedModelValue(part, MAX_MODEL_CONTENT_BYTES);
      }
      const content = contentParts.join("").trim();
      assertBoundedModelValue(content, MAX_MODEL_CONTENT_BYTES);
      if (!content) {
        throw new Error("provider returned no text content.");
      }
      const promptTokens = payload.usage?.input_tokens;
      const completionTokens = payload.usage?.output_tokens;
      const returnedModel = safeModel(payload.model) ?? model;
      return {
        content,
        model: returnedModel,
        provider: "claude",
        usage: {
          provider: "claude",
          model: returnedModel,
          ...(promptTokens !== undefined ? { promptTokens } : {}),
          ...(completionTokens !== undefined ? { completionTokens } : {}),
          ...(promptTokens !== undefined && completionTokens !== undefined ? { totalTokens: promptTokens + completionTokens } : {}),
          local: false,
        },
      };
    } catch (error) {
      throw new Error(`claude provider request failed: ${sanitizeErrorMessage(error)}`);
    }
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

function assertNoToolProtocol(request: ModelRequest): void {
  if (
    (request.tools?.length ?? 0) > 0 ||
    request.messages.some((message) => message.role === "tool" || (message.role === "assistant" && (message.toolCalls?.length ?? 0) > 0))
  ) {
    throw new Error("claude provider does not support Hermsec's normalized native tool protocol yet.");
  }
}

async function readBoundedResponseText(response: Response, maxBytes: number): Promise<string> {
  const declaredLength = Number(response.headers.get("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
    await response.body?.cancel();
    throw new Error(`Provider response exceeds the ${maxBytes}-byte limit.`);
  }
  if (!response.body) {
    return "";
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      totalBytes += value.byteLength;
      if (totalBytes > maxBytes) {
        await reader.cancel();
        throw new Error(`Provider response exceeds the ${maxBytes}-byte limit.`);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)), totalBytes).toString("utf8");
}

function assertBoundedModelValue(value: string, maxBytes: number): void {
  if (Buffer.byteLength(value, "utf8") > maxBytes) {
    throw new Error(`Provider message content exceeds the ${maxBytes}-byte limit.`);
  }
}

function safeModel(value: string | undefined): string | undefined {
  return typeof value === "string" && value.length > 0 && value.length <= 500 && value === value.trim()
    ? value
    : undefined;
}
