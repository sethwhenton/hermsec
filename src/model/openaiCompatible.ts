import {
  redactForLog,
  sanitizeErrorMessage,
} from "../agent/redaction.js";
import { credentialStatusFromEnv, normalizeCredentialEnvName, readCredentialFromEnv } from "./credentials.js";
import {
  ModelProviderRequestError,
  type OpenRouterMaxPrice,
  type ModelInfo,
  type ModelProviderAdapter,
  type ModelProviderId,
  type ModelMessage,
  type ModelRequest,
  type ModelResponse,
  type ModelRouteMetadata,
  type ModelToolCall,
  type ProviderConfig,
  type ProviderHealth,
} from "./provider.js";

const MAX_PROVIDER_RESPONSE_BYTES = 2_000_000;
const MAX_PROVIDER_ERROR_BYTES = 64_000;
const MAX_MODEL_CONTENT_BYTES = 1_000_000;
const MAX_TOOL_ARGUMENT_BYTES = 64_000;

export type OpenAiCompatibleDefaults = {
  id: Extract<ModelProviderId, "openai-compatible" | "opencode-go" | "openai" | "openrouter" | "ollama">;
  baseUrl: string;
  credentialEnv?: string;
  models: readonly string[];
  local: boolean;
  label?: string;
};

type OpenAiChatPayload = {
  id?: string;
  error?: OpenAiProviderError;
  choices?: Array<{
    finish_reason?: string;
    error?: OpenAiProviderError;
    message?: {
      content?: string | null | Array<{ text?: string; content?: string }>;
      tool_calls?: Array<{
        id?: string;
        type?: string;
        function?: {
          name?: string;
          arguments?: string | Record<string, unknown>;
        };
      }>;
    };
  }>;
  model?: string;
  provider?: string;
  usage?: {
    prompt_tokens?: number;
    completion_tokens?: number;
    total_tokens?: number;
    cost?: number;
    cost_details?: {
      upstream_inference_cost?: number;
    };
    prompt_tokens_details?: {
      cached_tokens?: number;
      cache_write_tokens?: number;
    };
    completion_tokens_details?: {
      reasoning_tokens?: number;
    };
  };
  openrouter_metadata?: {
    requested?: string;
    strategy?: string;
    region?: string | null;
    attempt?: number;
    is_byok?: boolean;
    endpoints?: {
      available?: Array<{
        provider?: string;
        model?: string;
        selected?: boolean;
      }>;
    };
    attempts?: Array<{
      provider?: string;
      model?: string;
      status?: number;
    }>;
  };
};

type OpenAiProviderError = {
  code?: unknown;
  message?: unknown;
  metadata?: {
    error_type?: unknown;
    provider_code?: unknown;
  };
};

type OpenAiChatResult = {
  payload: OpenAiChatPayload;
  generationId?: string;
  requestId?: string;
};

export function createOpenAiCompatibleProvider(defaults: OpenAiCompatibleDefaults): ModelProviderAdapter {
  return {
    id: defaults.id,
    capabilities: {
      tools: true,
      jsonResponse: true,
      externalAbort: true,
      streaming: false,
    },
    async listModels(config?: ProviderConfig): Promise<ModelInfo[]> {
      const configuredModel = config?.model;
      const models = configuredModel ? [configuredModel, ...defaults.models.filter((model) => model !== configuredModel)] : defaults.models;
      return models.map((model) => ({ id: model, label: model, local: defaults.local, supportsTools: true }));
    },
    async healthCheck(config?: ProviderConfig): Promise<ProviderHealth> {
      try {
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
      } catch (error) {
        return {
          ok: false,
          provider: defaults.id,
          message: `${defaults.label ?? defaults.id} health check failed: ${sanitizeErrorMessage(error)}`,
          credential: "env-missing",
          local: defaults.local,
        };
      }
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

      let result: OpenAiChatResult;
      try {
        result = await requestChatCompletion({
          baseUrl,
          defaultsId: defaults.id,
          ...(apiKey ? { apiKey } : {}),
          model,
          request,
          ...(config?.timeoutMs ? { timeoutMs: config.timeoutMs } : {}),
          includeResponseFormat: request.responseFormat === "json",
          ...(config ? { providerConfig: config } : {}),
        });
      } catch (error) {
        if (error instanceof ModelProviderRequestError) {
          throw error;
        }
        if (isTimeoutError(error)) {
          throw new ModelProviderRequestError(
            `${defaults.id} provider request timed out.`,
            {
              provider: defaults.id,
              errorType: "timeout",
            },
          );
        }
        throw new ModelProviderRequestError(
          `${defaults.id} provider request failed: ${sanitizeErrorMessage(error)}`,
          {
            provider: defaults.id,
            errorType: providerTransportErrorType(error),
          },
        );
      }
      const { payload } = result;
      const embeddedError =
        payload.error ??
        payload.choices?.find((choice) => choice.error)?.error;
      if (embeddedError) {
        throw providerRequestError(
          defaults.id,
          providerErrorStatus(embeddedError.code),
          embeddedError,
        );
      }
      const content = extractMessageContent(payload);
      const toolCalls = extractToolCalls(payload);
      if (!content && toolCalls.length === 0) {
        if (defaults.id === "openrouter") {
          throw new ModelProviderRequestError(
            "openrouter provider returned no message content.",
            {
              provider: defaults.id,
              errorType: "provider_unavailable",
            },
          );
        }
        throw new Error(`${defaults.id} provider returned no message content.`);
      }
      const returnedModel = safeMetadataString(payload.model, 500) ?? model;
      const promptTokens = safeTokenCount(payload.usage?.prompt_tokens);
      const completionTokens = safeTokenCount(payload.usage?.completion_tokens);
      const totalTokens = safeTokenCount(payload.usage?.total_tokens);
      const authoritativeUsd = finiteNonNegative(payload.usage?.cost);
      const upstreamInferenceUsd = finiteNonNegative(payload.usage?.cost_details?.upstream_inference_cost);
      const cachedPromptTokens = safeTokenCount(payload.usage?.prompt_tokens_details?.cached_tokens);
      const cacheWritePromptTokens = safeTokenCount(payload.usage?.prompt_tokens_details?.cache_write_tokens);
      const reasoningTokens = safeTokenCount(payload.usage?.completion_tokens_details?.reasoning_tokens);
      const responseId = safeOpaqueId(payload.id);
      const generationId = safeOpaqueId(result.generationId);
      const requestId = safeOpaqueId(result.requestId);
      const route = defaults.id === "openrouter"
        ? extractOpenRouterRoute(payload)
        : undefined;
      if (defaults.id === "openrouter" && requiresExactOpenRouterModel(request, config)) {
        const exactReturnedModel = safeMetadataString(payload.model, 500);
        if (
          exactReturnedModel !== model ||
          route?.requestedModel !== model ||
          route.selectedModel === undefined ||
          !isExactOrDatedDeploymentModel(model, route.selectedModel)
        ) {
          throw new Error("openrouter provider did not honor the exact requested model.");
        }
      }
      return {
        content: content ?? "",
        model: returnedModel,
        provider: defaults.id,
        ...(toolCalls.length > 0 ? { toolCalls } : {}),
        ...(payload.choices?.[0]?.finish_reason ? { finishReason: payload.choices[0].finish_reason } : {}),
        ...(responseId ? { responseId } : {}),
        ...(generationId ? { generationId } : {}),
        ...(requestId ? { requestId } : {}),
        ...(route ? { route } : {}),
        usage: {
          provider: defaults.id,
          model: returnedModel,
          ...(promptTokens !== undefined ? { promptTokens } : {}),
          ...(completionTokens !== undefined ? { completionTokens } : {}),
          ...(totalTokens !== undefined ? { totalTokens } : {}),
          ...(defaults.id === "openrouter" && authoritativeUsd !== undefined
            ? { authoritativeUsd }
            : {}),
          ...(defaults.id === "openrouter" && upstreamInferenceUsd !== undefined
            ? { upstreamInferenceUsd }
            : {}),
          ...(defaults.id === "openrouter" && cachedPromptTokens !== undefined
            ? { cachedPromptTokens }
            : {}),
          ...(defaults.id === "openrouter" && cacheWritePromptTokens !== undefined
            ? { cacheWritePromptTokens }
            : {}),
          ...(defaults.id === "openrouter" && reasoningTokens !== undefined
            ? { reasoningTokens }
            : {}),
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
  providerConfig?: ProviderConfig;
}): Promise<OpenAiChatResult> {
  const signal = combineRequestSignal(input.request.signal, input.timeoutMs ?? 30_000);
  const openRouterPolicy = input.defaultsId === "openrouter"
    ? openRouterRequestPolicy(input.request, input.providerConfig)
    : undefined;
  const response = await fetch(`${input.baseUrl}/chat/completions`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(input.apiKey ? { authorization: `Bearer ${input.apiKey}` } : {}),
      ...(openRouterPolicy?.captureRouteMetadata
        ? { "x-openrouter-metadata": "enabled" }
        : {}),
    },
    body: JSON.stringify({
      model: input.model,
      messages: input.request.messages.map(toOpenAiMessage),
      temperature: input.request.temperature ?? 0,
      ...(input.request.maxTokens ? { max_tokens: input.request.maxTokens } : {}),
      ...(input.includeResponseFormat ? { response_format: { type: "json_object" } } : {}),
      ...(input.request.tools && input.request.tools.length > 0
        ? {
            tools: input.request.tools,
            tool_choice: input.request.toolChoice ?? "auto",
            ...(input.defaultsId === "openrouter" &&
            openRouterPolicy?.provider?.require_parameters === true
              ? {}
              : { parallel_tool_calls: false }),
          }
        : {}),
      ...(openRouterPolicy?.provider ? { provider: openRouterPolicy.provider } : {}),
    }),
    signal,
  });

  if (!response.ok) {
    const rawError = await readBoundedResponseText(response, MAX_PROVIDER_ERROR_BYTES);
    throw providerRequestError(
      input.defaultsId,
      response.status,
      parseProviderError(rawError),
    );
  }

  const rawPayload = await readBoundedResponseText(response, MAX_PROVIDER_RESPONSE_BYTES);
  try {
    const generationId = response.headers.get("x-generation-id") ?? undefined;
    const requestId = response.headers.get("x-request-id") ?? undefined;
    return {
      payload: JSON.parse(rawPayload) as OpenAiChatPayload,
      ...(generationId ? { generationId } : {}),
      ...(requestId ? { requestId } : {}),
    };
  } catch {
    throw new Error(`${input.defaultsId} provider returned invalid JSON.`);
  }
}

function parseProviderError(raw: string): OpenAiProviderError | undefined {
  try {
    const parsed = JSON.parse(raw) as {
      error?: OpenAiProviderError;
    };
    return parsed?.error &&
      typeof parsed.error === "object" &&
      !Array.isArray(parsed.error)
      ? parsed.error
      : undefined;
  } catch {
    return undefined;
  }
}

function providerErrorMessage(
  provider: string,
  status: number | undefined,
  errorType: string | undefined,
  providerCode: string | undefined,
  message: string,
): string {
  return [
    `${provider} provider request failed${status === undefined ? "" : ` with ${status}`}`,
    errorType ? `error_type=${errorType}` : "",
    providerCode ? `provider_code=${providerCode}` : "",
    message,
  ].filter(Boolean).join(": ");
}

function providerRequestError(
  provider: ModelProviderId,
  status: number | undefined,
  error: OpenAiProviderError | undefined,
): ModelProviderRequestError {
  const message =
    typeof error?.message === "string"
      ? sanitizeErrorMessage(error.message)
      : "Provider returned an error.";
  const errorType =
    safeErrorToken(error?.metadata?.error_type) ??
    inferredProviderErrorType(status);
  const providerCode = safeErrorToken(error?.metadata?.provider_code);
  return new ModelProviderRequestError(
    providerErrorMessage(
      provider,
      status,
      errorType,
      providerCode,
      message,
    ),
    {
      provider,
      ...(status !== undefined ? { status } : {}),
      ...(errorType ? { errorType } : {}),
      ...(providerCode ? { providerCode } : {}),
    },
  );
}

function inferredProviderErrorType(
  status: number | undefined,
): string | undefined {
  if (status === 429) {
    return "rate_limit_exceeded";
  }
  if (status === 529) {
    return "provider_overloaded";
  }
  if (status === 502 || status === 503) {
    return "provider_unavailable";
  }
  if (status === 408 || status === 504) {
    return "timeout";
  }
  return undefined;
}

function providerErrorStatus(value: unknown): number | undefined {
  const parsed =
    typeof value === "number"
      ? value
      : typeof value === "string" && /^[45]\d{2}$/u.test(value)
        ? Number(value)
        : undefined;
  return Number.isSafeInteger(parsed) && (parsed ?? 0) >= 400 && (parsed ?? 0) <= 599
    ? parsed
    : undefined;
}

function safeErrorToken(value: unknown): string | undefined {
  if (
    typeof value !== "string" ||
    !/^[a-z0-9][a-z0-9._-]{0,99}$/iu.test(value)
  ) {
    return undefined;
  }
  const originalRedaction = redactForLog(value);
  const normalized = value.toLowerCase();
  const normalizedRedaction = redactForLog(normalized);
  return !originalRedaction.redacted &&
    originalRedaction.value === value &&
    !normalizedRedaction.redacted &&
    normalizedRedaction.value === normalized
    ? normalized
    : undefined;
}

function isTimeoutError(error: unknown): boolean {
  return (
    error instanceof Error &&
    error.name === "TimeoutError"
  );
}

function providerTransportErrorType(
  error: unknown,
): "invalid_response" | "transport_error" {
  return error instanceof Error &&
      /invalid json|response exceeds/iu.test(error.message)
    ? "invalid_response"
    : "transport_error";
}

function openRouterRequestPolicy(
  request: ModelRequest,
  config: ProviderConfig | undefined,
): {
  provider?: {
    require_parameters: boolean;
    allow_fallbacks: boolean;
    data_collection: "allow" | "deny";
    max_price?: OpenRouterMaxPrice;
  };
  captureRouteMetadata: boolean;
} {
  const configured = config?.openRouter;
  const boundedResearchRequest = requiresExactOpenRouterModel(request, config);
  const hasExplicitRouting = configured !== undefined;
  if (!boundedResearchRequest && !hasExplicitRouting) {
    return { captureRouteMetadata: false };
  }
  const maxPrice = normalizeOpenRouterMaxPrice(configured?.maxPrice);
  return {
    provider: {
      require_parameters: boundedResearchRequest ? true : configured?.requireParameters ?? false,
      // Exact-model enforcement rejects model-family substitution locally.
      // OpenRouter provider fallbacks only fail over between endpoints serving
      // that same requested model, which improves availability without
      // weakening the exact-model contract.
      allow_fallbacks: configured?.allowFallbacks ?? true,
      data_collection: boundedResearchRequest ? "deny" : configured?.dataCollection ?? "deny",
      ...(maxPrice ? { max_price: maxPrice } : {}),
    },
    captureRouteMetadata: boundedResearchRequest ? true : configured?.captureRouteMetadata ?? false,
  };
}

function normalizeOpenRouterMaxPrice(
  value: OpenRouterMaxPrice | undefined,
): OpenRouterMaxPrice | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("OpenRouter max price must be a pricing object.");
  }
  const allowed = new Set([
    "prompt",
    "completion",
    "request",
    "image",
    "audio",
  ]);
  const keys = Object.keys(value);
  if (keys.length === 0 || keys.some((key) => !allowed.has(key))) {
    throw new Error(
      "OpenRouter max price must contain only prompt, completion, request, image, or audio ceilings.",
    );
  }
  const normalized: OpenRouterMaxPrice = {};
  for (const key of keys as Array<keyof OpenRouterMaxPrice>) {
    const candidate = value[key];
    if (
      typeof candidate !== "string" ||
      !/^(?:0|[1-9]\d*)(?:\.\d+)?$/u.test(candidate) ||
      !Number.isFinite(Number(candidate))
    ) {
      throw new Error(
        `OpenRouter max price ${key} must be a canonical non-negative decimal string.`,
      );
    }
    normalized[key] = candidate;
  }
  return normalized;
}

function requiresExactOpenRouterModel(
  request: ModelRequest,
  config: ProviderConfig | undefined,
): boolean {
  return (
    request.requireExactModel === true ||
    config?.openRouter?.scored === true ||
    (request.tools?.length ?? 0) > 0
  );
}

function isExactOrDatedDeploymentModel(requested: string, selected: string): boolean {
  return selected === requested || new RegExp(`^${escapeRegExp(requested)}-\\d{8}$`, "u").test(selected);
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

function extractMessageContent(payload: OpenAiChatPayload): string | undefined {
  const content = payload.choices?.[0]?.message?.content;
  if (typeof content === "string") {
    assertBoundedModelValue(content, MAX_MODEL_CONTENT_BYTES, "message content");
    const trimmed = content.trim();
    return trimmed ? trimmed : undefined;
  }
  if (Array.isArray(content)) {
    for (const part of content) {
      assertBoundedModelValue(part.text ?? part.content ?? "", MAX_MODEL_CONTENT_BYTES, "message content");
    }
    const joined = content
      .map((part) => part.text ?? part.content ?? "")
      .join("\n")
      .trim();
    assertBoundedModelValue(joined, MAX_MODEL_CONTENT_BYTES, "message content");
    return joined ? joined : undefined;
  }
  return undefined;
}

function extractToolCalls(payload: OpenAiChatPayload): ModelToolCall[] {
  return (payload.choices?.[0]?.message?.tool_calls ?? [])
    .map((call): ModelToolCall | undefined => {
      const name = call.function?.name?.trim();
      if (!name) {
        return undefined;
      }
      const id = call.id?.trim();
      if (!id || !/^[A-Za-z0-9_.:-]{1,160}$/u.test(id)) {
        throw new Error("Provider returned a tool call without a valid ID.");
      }
      const rawArguments = call.function?.arguments;
      const args = typeof rawArguments === "string"
        ? rawArguments
        : JSON.stringify(rawArguments ?? {});
      assertBoundedModelValue(args, MAX_TOOL_ARGUMENT_BYTES, "tool arguments");
      return {
        id,
        type: "function",
        function: {
          name,
          arguments: args,
        },
      };
    })
    .filter((call): call is ModelToolCall => call !== undefined);
}

function toOpenAiMessage(message: ModelMessage): Record<string, unknown> {
  if (message.role === "assistant") {
    return {
      role: "assistant",
      content: message.content || null,
      ...(message.toolCalls && message.toolCalls.length > 0
        ? {
            tool_calls: message.toolCalls.map((call) => ({
              id: call.id,
              type: "function",
              function: {
                name: call.function.name,
                arguments: call.function.arguments,
              },
            })),
          }
        : {}),
    };
  }
  if (message.role === "tool") {
    return {
      role: "tool",
      tool_call_id: message.toolCallId,
      content: message.content,
    };
  }
  return {
    role: message.role,
    content: message.content,
  };
}

function combineRequestSignal(external: AbortSignal | undefined, timeoutMs: number): AbortSignal {
  const timeout = AbortSignal.timeout(timeoutMs);
  return external ? AbortSignal.any([external, timeout]) : timeout;
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

function assertBoundedModelValue(value: string, maxBytes: number, label: string): void {
  if (Buffer.byteLength(value, "utf8") > maxBytes) {
    throw new Error(`Provider ${label} exceeds the ${maxBytes}-byte limit.`);
  }
}

function extractOpenRouterRoute(payload: OpenAiChatPayload): ModelRouteMetadata | undefined {
  const metadata = payload.openrouter_metadata;
  const selected = metadata?.endpoints?.available
    ?.slice(0, 64)
    .find((endpoint) => endpoint.selected === true);
  const attempts = metadata?.attempts
    ?.slice(0, 32)
    .map((attempt) => {
      const sanitized: NonNullable<ModelRouteMetadata["attempts"]>[number] = {};
      const provider = safeMetadataString(attempt.provider, 160);
      const model = safeMetadataString(attempt.model, 500);
      const status = attempt.status;
      if (provider) {
        sanitized.provider = provider;
      }
      if (model) {
        sanitized.model = model;
      }
      if (
        Number.isSafeInteger(status) &&
        (status ?? 0) >= 100 &&
        (status ?? 0) <= 599
      ) {
        sanitized.status = status as number;
      }
      return sanitized;
    })
    .filter((attempt) => Object.keys(attempt).length > 0);
  const route: ModelRouteMetadata = {};
  const requestedModel = safeMetadataString(metadata?.requested, 500);
  const strategy = safeMetadataString(metadata?.strategy, 80);
  const region = safeMetadataString(metadata?.region ?? undefined, 80);
  const selectedProvider = safeMetadataString(selected?.provider ?? payload.provider, 160);
  const selectedModel = safeMetadataString(selected?.model, 500);
  const routeAttempt = metadata?.attempt;
  if (requestedModel) {
    route.requestedModel = requestedModel;
  }
  if (strategy) {
    route.strategy = strategy;
  }
  if (region) {
    route.region = region;
  }
  if (Number.isSafeInteger(routeAttempt) && (routeAttempt ?? -1) >= 0) {
    route.attempt = routeAttempt as number;
  }
  if (typeof metadata?.is_byok === "boolean") {
    route.isByok = metadata.is_byok;
  }
  if (selectedProvider) {
    route.selectedProvider = selectedProvider;
  }
  if (selectedModel) {
    route.selectedModel = selectedModel;
  }
  if (attempts && attempts.length > 0) {
    route.attempts = attempts;
  }
  return Object.keys(route).length > 0 ? route : undefined;
}

function safeTokenCount(value: number | undefined): number | undefined {
  return Number.isSafeInteger(value) && (value ?? -1) >= 0 ? value : undefined;
}

function finiteNonNegative(value: number | undefined): number | undefined {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : undefined;
}

function safeOpaqueId(value: string | undefined): string | undefined {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 256 ||
    value !== value.trim() ||
    !/^[A-Za-z0-9_.:/-]+$/u.test(value)
  ) {
    return undefined;
  }
  return value;
}

function safeMetadataString(value: string | undefined, maxLength: number): string | undefined {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maxLength ||
    value !== value.trim() ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    return undefined;
  }
  return value;
}

function stripTrailingSlash(value: string): string {
  return value.replace(/\/+$/, "");
}
