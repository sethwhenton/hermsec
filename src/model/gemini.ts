import { redactForLog, sanitizeErrorMessage } from "../agent/redaction.js";
import { credentialStatusFromEnv, normalizeCredentialEnvName, readCredentialFromEnv } from "./credentials.js";
import type { ModelProviderAdapter, ModelRequest, ModelResponse, ProviderConfig, ProviderHealth } from "./provider.js";

const defaultBaseUrl = "https://generativelanguage.googleapis.com/v1beta";
const defaultModel = "gemini-2.5-flash";
const defaultCredentialEnv = "GEMINI_API_KEY";
const MAX_PROVIDER_RESPONSE_BYTES = 2_000_000;
const MAX_PROVIDER_ERROR_BYTES = 64_000;
const MAX_MODEL_CONTENT_BYTES = 1_000_000;

export const geminiProvider: ModelProviderAdapter = {
  id: "gemini",
  capabilities: {
    tools: false,
    jsonResponse: true,
    externalAbort: true,
    streaming: false,
  },
  async listModels() {
    return [{ id: defaultModel, label: "Gemini Flash", local: false, supportsTools: false }];
  },
  async healthCheck(config?: ProviderConfig): Promise<ProviderHealth> {
    try {
      const envName = config?.apiKeyEnv ?? defaultCredentialEnv;
      const credential = credentialStatusFromEnv(envName);
      if (!credential.validEnvName) {
        return {
          ok: false,
          provider: "gemini",
          message: "Provider credential reference must be an environment variable name, not a key value.",
          credential: "env-missing",
          credentialEnv: "<invalid-env-name>",
          local: false,
        };
      }
      return {
        ok: credential.present,
        provider: "gemini",
        message: credential.present
          ? "Gemini provider credential was verified from the environment."
          : `Missing provider credential environment variable: ${credential.envName}`,
        credential: credential.present ? "env-present" : "env-missing",
        credentialEnv: credential.envName,
        ...(credential.fingerprint ? { credentialFingerprint: credential.fingerprint } : {}),
        local: false,
      };
    } catch (error) {
      return {
        ok: false,
        provider: "gemini",
        message: `Gemini health check failed: ${sanitizeErrorMessage(error)}`,
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

    const model = request.model ?? config?.model ?? defaultModel;
    const systemText = request.messages.filter((message) => message.role === "system").map((message) => message.content).join("\n\n");
    const contents = request.messages
      .filter((message) => message.role !== "system")
      .map((message) => ({
        role: message.role === "assistant" ? "model" : "user",
        parts: [{ text: message.content }],
      }));
    const url = `${stripTrailingSlash(config?.baseUrl ?? defaultBaseUrl)}/models/${encodeURIComponent(model)}:generateContent`;
    try {
      const response = await fetch(url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-goog-api-key": apiKey,
        },
        body: JSON.stringify({
          ...(systemText ? { systemInstruction: { parts: [{ text: systemText }] } } : {}),
          contents,
          generationConfig: {
            temperature: request.temperature ?? 0,
            ...(request.maxTokens ? { maxOutputTokens: request.maxTokens } : {}),
            ...(request.responseFormat === "json" ? { responseMimeType: "application/json" } : {}),
          },
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
        candidates?: Array<{ content?: { parts?: Array<{ text?: string }> } }>;
        usageMetadata?: { promptTokenCount?: number; candidatesTokenCount?: number; totalTokenCount?: number };
      };
      try {
        payload = JSON.parse(rawPayload) as typeof payload;
      } catch {
        throw new Error("provider returned invalid JSON.");
      }
      const contentParts = (payload.candidates?.[0]?.content?.parts ?? []).map((part) =>
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
      const promptTokens = payload.usageMetadata?.promptTokenCount;
      const completionTokens = payload.usageMetadata?.candidatesTokenCount;
      const totalTokens = payload.usageMetadata?.totalTokenCount;
      return {
        content,
        model,
        provider: "gemini",
        usage: {
          provider: "gemini",
          model,
          ...(promptTokens !== undefined ? { promptTokens } : {}),
          ...(completionTokens !== undefined ? { completionTokens } : {}),
          ...(totalTokens !== undefined ? { totalTokens } : {}),
          local: false,
        },
      };
    } catch (error) {
      throw new Error(`gemini provider request failed: ${sanitizeErrorMessage(error)}`);
    }
  },
  estimateCost() {
    return { local: false };
  },
};

function stripTrailingSlash(value: string): string {
  return value.replace(/\/+$/, "");
}

function assertNoToolProtocol(request: ModelRequest): void {
  if (
    (request.tools?.length ?? 0) > 0 ||
    request.messages.some((message) => message.role === "tool" || (message.role === "assistant" && (message.toolCalls?.length ?? 0) > 0))
  ) {
    throw new Error("gemini provider does not support Hermsec's normalized native tool protocol yet.");
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
