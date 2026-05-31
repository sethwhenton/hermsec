import { redactForLog } from "../agent/redaction.js";
import { credentialStatusFromEnv, readCredentialFromEnv } from "./credentials.js";
import type {
  ModelInfo,
  ModelProviderAdapter,
  ModelProviderId,
  ModelRequest,
  ModelResponse,
  ProviderConfig,
  ProviderHealth
} from "./provider.js";

export type OpenAiCompatibleDefaults = {
  id: Extract<ModelProviderId, "openai-compatible" | "opencode-go" | "openai" | "openrouter">;
  baseUrl: string;
  credentialEnv?: string;
  models: readonly string[];
  local: boolean;
  label?: string;
};

export function createOpenAiCompatibleProvider(defaults: OpenAiCompatibleDefaults): ModelProviderAdapter {
  return {
    id: defaults.id,
    async listModels(config?: ProviderConfig): Promise<ModelInfo[]> {
      const configuredModel = config?.model;
      const models = configuredModel ? [configuredModel, ...defaults.models.filter((model) => model !== configuredModel)] : defaults.models;
      return models.map((model) => ({ id: model, label: model, local: defaults.local }));
    },
    async healthCheck(config?: ProviderConfig): Promise<ProviderHealth> {
      const envName = config?.apiKeyEnv ?? defaults.credentialEnv;
      const credential = envName ? credentialStatusFromEnv(envName) : undefined;
      const missingRequiredCredential = Boolean(envName && !credential?.present && !defaults.local);
      return {
        ok: !missingRequiredCredential,
        provider: defaults.id,
        message: missingRequiredCredential
          ? `Missing provider credential environment variable: ${envName}`
          : `${defaults.label ?? defaults.id} provider is configured.`,
        credential: envName ? (credential?.present ? "env-present" : "env-missing") : "not-required",
        local: defaults.local
      };
    },
    async complete(request: ModelRequest, config?: ProviderConfig): Promise<ModelResponse> {
      const baseUrl = stripTrailingSlash(config?.baseUrl ?? defaults.baseUrl);
      const model = request.model ?? config?.model ?? defaults.models[0];
      if (!model) {
        throw new Error(`${defaults.id} provider has no model configured.`);
      }

      const envName = config?.apiKeyEnv ?? defaults.credentialEnv;
      const apiKey = envName ? readCredentialFromEnv(envName) : undefined;
      if (envName && !apiKey && !defaults.local) {
        throw new Error(`Missing provider credential environment variable: ${envName}`);
      }

      const response = await fetch(`${baseUrl}/chat/completions`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...(apiKey ? { authorization: `Bearer ${apiKey}` } : {})
        },
        body: JSON.stringify({
          model,
          messages: request.messages,
          temperature: request.temperature ?? 0,
          ...(request.maxTokens ? { max_tokens: request.maxTokens } : {}),
          ...(request.responseFormat === "json" ? { response_format: { type: "json_object" } } : {})
        }),
        signal: AbortSignal.timeout(config?.timeoutMs ?? 30_000)
      });

      if (!response.ok) {
        const rawError = await response.text();
        const redacted = redactForLog(rawError).value;
        throw new Error(`${defaults.id} provider request failed with ${response.status}: ${String(redacted).slice(0, 500)}`);
      }

      const payload = (await response.json()) as {
        choices?: Array<{ message?: { content?: string } }>;
        model?: string;
        usage?: { prompt_tokens?: number; completion_tokens?: number; total_tokens?: number };
      };
      const content = payload.choices?.[0]?.message?.content;
      if (!content) {
        throw new Error(`${defaults.id} provider returned no message content.`);
      }
      const promptTokens = payload.usage?.prompt_tokens;
      const completionTokens = payload.usage?.completion_tokens;
      const totalTokens = payload.usage?.total_tokens;
      return {
        content,
        model: payload.model ?? model,
        provider: defaults.id,
        usage: {
          provider: defaults.id,
          model: payload.model ?? model,
          ...(promptTokens !== undefined ? { promptTokens } : {}),
          ...(completionTokens !== undefined ? { completionTokens } : {}),
          ...(totalTokens !== undefined ? { totalTokens } : {}),
          local: defaults.local
        }
      };
    },
    estimateCost() {
      return { local: defaults.local };
    }
  };
}

export const openAiCompatibleProvider = createOpenAiCompatibleProvider({
  id: "openai-compatible",
  baseUrl: "http://localhost:1234/v1",
  models: ["local-model"],
  local: true,
  label: "OpenAI-compatible"
});

function stripTrailingSlash(value: string): string {
  return value.replace(/\/+$/, "");
}
