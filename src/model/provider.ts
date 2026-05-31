import type { ModelUsage } from "../agent/costTracker.js";

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
};

export type ProviderConfig = {
  provider?: ModelProviderId;
  baseUrl?: string;
  model?: string;
  apiKeyEnv?: string;
  allowRemoteProviders?: boolean;
  timeoutMs?: number;
};

export type ProviderHealth = {
  ok: boolean;
  provider: ModelProviderId;
  message: string;
  credential?: "not-required" | "env-present" | "env-missing";
  local: boolean;
};

export type ModelMessage = {
  role: "system" | "user" | "assistant";
  content: string;
};

export type ModelRequest = {
  messages: ModelMessage[];
  model?: string;
  temperature?: number;
  maxTokens?: number;
  responseFormat?: "text" | "json";
};

export type ModelResponse = {
  content: string;
  model: string;
  provider: ModelProviderId;
  usage?: ModelUsage;
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

export type ModelProviderAdapter = {
  id: ModelProviderId;
  listModels(config?: ProviderConfig): Promise<ModelInfo[]>;
  healthCheck(config?: ProviderConfig): Promise<ProviderHealth>;
  complete(request: ModelRequest, config?: ProviderConfig): Promise<ModelResponse>;
  stream?(request: ModelRequest, config?: ProviderConfig): AsyncIterable<ModelStreamEvent>;
  estimateCost?(request: ModelRequest, config?: ProviderConfig): CostEstimate;
};
