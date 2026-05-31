import { redactForLog } from "../agent/redaction.js";
import { credentialStatusFromEnv, normalizeCredentialEnvName, readCredentialFromEnv } from "./credentials.js";
import type { ModelProviderAdapter, ModelRequest, ModelResponse, ProviderConfig, ProviderHealth } from "./provider.js";

const defaultBaseUrl = "https://generativelanguage.googleapis.com/v1beta";
const defaultModel = "gemini-2.5-flash";
const defaultCredentialEnv = "GEMINI_API_KEY";

export const geminiProvider: ModelProviderAdapter = {
  id: "gemini",
  async listModels() {
    return [{ id: defaultModel, label: "Gemini Flash", local: false }];
  },
  async healthCheck(config?: ProviderConfig): Promise<ProviderHealth> {
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

    const model = request.model ?? config?.model ?? defaultModel;
    const systemText = request.messages.filter((message) => message.role === "system").map((message) => message.content).join("\n\n");
    const contents = request.messages
      .filter((message) => message.role !== "system")
      .map((message) => ({
        role: message.role === "assistant" ? "model" : "user",
        parts: [{ text: message.content }],
      }));
    const url = `${stripTrailingSlash(config?.baseUrl ?? defaultBaseUrl)}/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(apiKey)}`;
    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        ...(systemText ? { systemInstruction: { parts: [{ text: systemText }] } } : {}),
        contents,
        generationConfig: {
          temperature: request.temperature ?? 0,
          ...(request.maxTokens ? { maxOutputTokens: request.maxTokens } : {}),
          ...(request.responseFormat === "json" ? { responseMimeType: "application/json" } : {}),
        },
      }),
      signal: AbortSignal.timeout(config?.timeoutMs ?? 30_000),
    });
    if (!response.ok) {
      const rawError = await response.text();
      const redacted = redactForLog(rawError).value;
      throw new Error(`gemini provider request failed with ${response.status}: ${String(redacted).slice(0, 500)}`);
    }
    const payload = (await response.json()) as {
      candidates?: Array<{ content?: { parts?: Array<{ text?: string }> } }>;
      usageMetadata?: { promptTokenCount?: number; candidatesTokenCount?: number; totalTokenCount?: number };
    };
    const content = (payload.candidates?.[0]?.content?.parts ?? []).map((part) => part.text ?? "").join("").trim();
    if (!content) {
      throw new Error("gemini provider returned no text content.");
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
  },
  estimateCost() {
    return { local: false };
  },
};

function stripTrailingSlash(value: string): string {
  return value.replace(/\/+$/, "");
}
