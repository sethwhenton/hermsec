import { redactForLog } from "../agent/redaction.js";
import { credentialStatusFromEnv, normalizeCredentialEnvName, readCredentialFromEnv } from "./credentials.js";
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
  id: Extract<ModelProviderId, "openai-compatible" | "opencode-go" | "openai" | "openrouter" | "ollama">;
  baseUrl: string;
  credentialEnv?: string;
  models: readonly string[];
  local: boolean;
  label?: string;
};

type OpenAiChatPayload = {
  choices?: Array<{
    message?: {
      content?: string | Array<{ text?: string; content?: string }>;
    };
  }>;
  model?: string;
  usage?: { prompt_tokens?: number; completion_tokens?: number; total_tokens?: number };
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
      if (credential && !credential.validEnvName) {
        return {
          ok: false,
          provider: defaults.id,
          message: "Provider credential reference must be an environment variable name, not a key value.",
          credential: "env-missing",
          credentialEnv: credential.envName,
          local: defaults.local
        };
      }

      const missingRequiredCredential = Boolean(envName && !credential?.present && !defaults.local);
      return {
        ok: !missingRequiredCredential,
        provider: defaults.id,
        message: missingRequiredCredential
          ? `Missing provider credential environment variable: ${credential?.envName}`
          : credential?.present
            ? `${defaults.label ?? defaults.id} provider credential was verified from the environment.`
            : `${defaults.label ?? defaults.id} provider is configured.`,
        credential: envName ? (credential?.present ? "env-present" : "env-missing") : "not-required",
        ...(credential?.envName ? { credentialEnv: credential.envName } : {}),
        ...(credential?.fingerprint ? { credentialFingerprint: credential.fingerprint } : {}),
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
      const safeEnvName = normalizeCredentialEnvName(envName);
      if (envName && !safeEnvName) {
        throw new Error("Provider credential reference must be an environment variable name, not a key value.");
      }
      const apiKey = safeEnvName ? readCredentialFromEnv(safeEnvName) : undefined;
      if (safeEnvName && !apiKey && !defaults.local) {
        throw new Error(`Missing provider credential environment variable: ${safeEnvName}`);
      }

      let payload = await requestChatCompletion({
        baseUrl,
        defaultsId: defaults.id,
        ...(apiKey ? { apiKey } : {}),
        model,
        request,
        ...(config?.timeoutMs ? { timeoutMs: config.timeoutMs } : {}),
        includeResponseFormat: request.responseFormat === "json",
      });
      let content = extractMessageContent(payload);
      if (!content && request.responseFormat === "json") {
        payload = await requestChatCompletion({
          baseUrl,
          defaultsId: defaults.id,
          ...(apiKey ? { apiKey } : {}),
          model,
          request,
          ...(config?.timeoutMs ? { timeoutMs: config.timeoutMs } : {}),
          includeResponseFormat: false,
        });
        content = extractMessageContent(payload);
      }
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

export const openAiProvider = createOpenAiCompatibleProvider({
  id: "openai",
  baseUrl: "https://api.openai.com/v1",
  credentialEnv: "OPENAI_API_KEY",
  models: ["gpt-4.1-mini"],
  local: false,
  label: "OpenAI"
});

export const openRouterProvider = createOpenAiCompatibleProvider({
  id: "openrouter",
  baseUrl: "https://openrouter.ai/api/v1",
  credentialEnv: "OPENROUTER_API_KEY",
  models: ["openai/gpt-4.1-mini"],
  local: false,
  label: "OpenRouter"
});

export const ollamaProvider = createOpenAiCompatibleProvider({
  id: "ollama",
  baseUrl: "http://localhost:11434/v1",
  models: ["llama3.1"],
  local: true,
  label: "Ollama"
});

async function requestChatCompletion(input: {
  baseUrl: string;
  defaultsId: ModelProviderId;
  apiKey?: string;
  model: string;
  request: ModelRequest;
  timeoutMs?: number;
  includeResponseFormat: boolean;
}): Promise<OpenAiChatPayload> {
  const response = await fetch(`${input.baseUrl}/chat/completions`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(input.apiKey ? { authorization: `Bearer ${input.apiKey}` } : {})
    },
    body: JSON.stringify({
      model: input.model,
      messages: input.request.messages,
      temperature: input.request.temperature ?? 0,
      ...(input.request.maxTokens ? { max_tokens: input.request.maxTokens } : {}),
      ...(input.includeResponseFormat ? { response_format: { type: "json_object" } } : {})
    }),
    signal: AbortSignal.timeout(input.timeoutMs ?? 30_000)
  });

  if (!response.ok) {
    const rawError = await response.text();
    const redacted = redactForLog(rawError).value;
    throw new Error(`${input.defaultsId} provider request failed with ${response.status}: ${String(redacted).slice(0, 500)}`);
  }

  return (await response.json()) as OpenAiChatPayload;
}

function extractMessageContent(payload: OpenAiChatPayload): string | undefined {
  const content = payload.choices?.[0]?.message?.content;
  if (typeof content === "string") {
    const trimmed = content.trim();
    return trimmed ? trimmed : undefined;
  }
  if (Array.isArray(content)) {
    const joined = content
      .map((part) => part.text ?? part.content ?? "")
      .join("\n")
      .trim();
    return joined ? joined : undefined;
  }
  return undefined;
}

function stripTrailingSlash(value: string): string {
  return value.replace(/\/+$/, "");
}
