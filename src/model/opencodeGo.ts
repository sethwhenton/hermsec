import { createOpenAiCompatibleProvider } from "./openaiCompatible.js";

export const opencodeGoConfig = {
  id: "opencode-go" as const,
  baseUrl: "https://opencode.ai/zen/go/v1",
  credentialEnv: "OPENCODE_GO_API_KEY",
  models: ["kimi-k2.6", "glm-5.1", "deepseek-v4-pro", "deepseek-v4-flash"] as const
};

export const opencodeGoProvider = createOpenAiCompatibleProvider({
  id: opencodeGoConfig.id,
  baseUrl: opencodeGoConfig.baseUrl,
  credentialEnv: opencodeGoConfig.credentialEnv,
  models: opencodeGoConfig.models,
  local: false,
  label: "OpenCode Go"
});
