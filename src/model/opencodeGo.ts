import { createOpenAiCompatibleProvider } from "./openaiCompatible.js";

export const opencodeGoConfig = {
  id: "opencode-go" as const,
  baseUrl: "https://opencode.ai/zen/go/v1",
  credentialEnv: "OPENCODE_GO_API_KEY",
  models: [
    "deepseek-v4-pro",
    "deepseek-v4-flash",
    "glm-5",
    "glm-5.1",
    "glm-5.2",
    "hy3-preview",
    "kimi-k2.5",
    "kimi-k2.6",
    "kimi-k2.7-code",
    "mimo-v2.5-pro",
    "mimo-v2.5",
    "mimo-v2-pro",
    "mimo-v2-omni",
    "minimax-m2.5",
    "minimax-m2.7",
    "minimax-m3",
    "qwen3.5-plus",
    "qwen3.6-plus",
    "qwen3.7-max",
    "qwen3.7-plus",
  ] as const
};

export const opencodeGoProvider = createOpenAiCompatibleProvider({
  id: opencodeGoConfig.id,
  baseUrl: opencodeGoConfig.baseUrl,
  credentialEnv: opencodeGoConfig.credentialEnv,
  models: opencodeGoConfig.models,
  local: false,
  label: "OpenCode Go"
});
