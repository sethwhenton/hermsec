import type { ModelUsage as CostModelUsage } from "../agent/costTracker.js";

export type ModelProviderId =
  | "openrouter"
  | "openai"
  | "claude"
  | "gemini"
  | "ollama"
  | "opencode-go"
  | "openai-compatible"
  | "none";

export type ModelInfo = {
  id: string;
  label?: string;
  local: boolean;
  contextWindow?: number;
  supportsTools?: boolean;
};

export type OpenRouterMaxPrice = {
  prompt?: string;
  completion?: string;
  request?: string;
  image?: string;
  audio?: string;
};

export type ProviderConfig = {
  provider?: ModelProviderId;
  baseUrl?: string;
  model?: string;
  apiKeyEnv?: string;
  allowRemoteProviders?: boolean;
  timeoutMs?: number;
  openRouter?: {
    scored?: boolean;
    requireParameters?: boolean;
    allowFallbacks?: boolean;
    dataCollection?: "allow" | "deny";
    captureRouteMetadata?: boolean;
    maxPrice?: OpenRouterMaxPrice;
  };
};

export class ModelProviderRequestError extends Error {
  readonly provider: ModelProviderId;
  readonly status?: number;
  readonly errorType?: string;
  readonly providerCode?: string;

  constructor(
    message: string,
    metadata: {
      provider: ModelProviderId;
      status?: number;
      errorType?: string;
      providerCode?: string;
    },
  ) {
    super(message);
    this.name = "ModelProviderRequestError";
    this.provider = metadata.provider;
    if (metadata.status !== undefined) {
      this.status = metadata.status;
    }
    if (metadata.errorType !== undefined) {
      this.errorType = metadata.errorType;
    }
    if (metadata.providerCode !== undefined) {
      this.providerCode = metadata.providerCode;
    }
  }
}

export type ProviderHealth = {
  ok: boolean;
  provider: ModelProviderId;
  message: string;
  credential?: "not-required" | "env-present" | "env-missing";
  credentialEnv?: string;
  credentialFingerprint?: string;
  local: boolean;
};

export type ModelToolDefinition = {
  type: "function";
  function: {
    name: string;
    description: string;
    parameters: Record<string, unknown>;
  };
};

export type ModelToolCall = {
  id: string;
  type: "function";
  function: {
    name: string;
    arguments: string;
  };
};

export type ModelToolChoice =
  | "auto"
  | "none"
  | "required"
  | {
      type: "function";
      function: {
        name: string;
      };
    };

export type ModelMessage =
  | {
      role: "system" | "user";
      content: string;
    }
  | {
      role: "assistant";
      content: string;
      toolCalls?: ModelToolCall[];
    }
  | {
      role: "tool";
      content: string;
      toolCallId: string;
      name?: string;
    };

export type ModelRequest = {
  messages: ModelMessage[];
  model?: string;
  requireExactModel?: boolean;
  temperature?: number;
  maxTokens?: number;
  responseFormat?: "text" | "json";
  tools?: ModelToolDefinition[];
  toolChoice?: ModelToolChoice;
  signal?: AbortSignal;
};

export type ModelUsage = CostModelUsage & {
  authoritativeUsd?: number;
  upstreamInferenceUsd?: number;
  cachedPromptTokens?: number;
  cacheWritePromptTokens?: number;
  reasoningTokens?: number;
};

export type ModelRouteMetadata = {
  requestedModel?: string;
  strategy?: string;
  region?: string;
  attempt?: number;
  isByok?: boolean;
  selectedProvider?: string;
  selectedModel?: string;
  attempts?: Array<{
    provider?: string;
    model?: string;
    status?: number;
  }>;
};

export type ModelResponse = {
  content: string;
  model: string;
  provider: ModelProviderId;
  usage?: ModelUsage;
  toolCalls?: ModelToolCall[];
  finishReason?: string;
  responseId?: string;
  generationId?: string;
  requestId?: string;
  route?: ModelRouteMetadata;
};

export type ModelStreamEvent =
  | { type: "content"; content: string }
  | { type: "done"; usage?: ModelUsage };

export type CostEstimate = {
  estimatedUsd?: number;
  promptTokens?: number;
  completionTokens?: number;
  local: boolean;
};

export type ModelProviderCapabilities = {
  tools: boolean;
  jsonResponse: boolean;
  externalAbort: boolean;
  streaming: boolean;
};

export type ModelProviderAdapter = {
  id: ModelProviderId;
  capabilities?: ModelProviderCapabilities;
  listModels(config?: ProviderConfig): Promise<ModelInfo[]>;
  healthCheck(config?: ProviderConfig): Promise<ProviderHealth>;
  complete(request: ModelRequest, config?: ProviderConfig): Promise<ModelResponse>;
  stream?(request: ModelRequest, config?: ProviderConfig): AsyncIterable<ModelStreamEvent>;
  estimateCost?(request: ModelRequest, config?: ProviderConfig): CostEstimate;
};
