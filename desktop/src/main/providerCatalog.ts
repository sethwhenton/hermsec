import type { ModelConfig, ProviderConfig, ProviderPreset } from "../renderer/src/types/settings";

const LOGO_BASE = "https://raw.githubusercontent.com/ln-dev7/logos-apps/master/logos";

const opencodeGoChatModels: ModelConfig[] = [
  model("deepseek-v4-pro", "DeepSeek V4 Pro"),
  model("deepseek-v4-flash", "DeepSeek V4 Flash"),
  model("glm-5", "GLM 5"),
  model("glm-5.1", "GLM 5.1"),
  model("glm-5.2", "GLM 5.2"),
  model("hy3-preview", "HY3 Preview"),
  model("kimi-k2.5", "Kimi K2.5"),
  model("kimi-k2.6", "Kimi K2.6"),
  model("kimi-k2.7-code", "Kimi K2.7 Code"),
  model("mimo-v2.5-pro", "MiMo V2.5 Pro"),
  model("mimo-v2.5", "MiMo V2.5"),
  model("mimo-v2-pro", "MiMo V2 Pro"),
  model("mimo-v2-omni", "MiMo V2 Omni"),
  model("minimax-m2.5", "MiniMax M2.5"),
  model("minimax-m2.7", "MiniMax M2.7"),
  model("minimax-m3", "MiniMax M3"),
  model("qwen3.5-plus", "Qwen3.5 Plus"),
  model("qwen3.6-plus", "Qwen3.6 Plus"),
  model("qwen3.7-max", "Qwen3.7 Max"),
  model("qwen3.7-plus", "Qwen3.7 Plus"),
];

export function providerPresets(): ProviderPreset[] {
  return [
    {
      id: "opencode-go",
      displayName: "OpenCode Go",
      description: "Curated coding models through an OpenAI-compatible endpoint.",
      baseUrl: "https://opencode.ai/zen/go/v1",
      apiFormat: "openai-compatible",
      apiKeyEnvVar: "OPENCODE_GO_API_KEY",
      logoUrl: `${LOGO_BASE}/opencode.svg`,
      websiteUrl: "https://opencode.ai/go",
      enabled: true,
      supportsModelDiscovery: true,
      status: "available",
      models: opencodeGoChatModels,
    },
    {
      id: "openrouter",
      displayName: "OpenRouter",
      description: "OpenAI-compatible access to many hosted models through one API key.",
      baseUrl: "https://openrouter.ai/api/v1",
      apiFormat: "openai-compatible",
      apiKeyEnvVar: "OPENROUTER_API_KEY",
      logoUrl: `${LOGO_BASE}/openrouter.svg`,
      websiteUrl: "https://openrouter.ai/pricing",
      enabled: true,
      supportsModelDiscovery: true,
      status: "available",
      models: [
        model("openai/gpt-4.1-mini", "OpenAI GPT-4.1 Mini"),
        model("anthropic/claude-sonnet-4", "Claude Sonnet 4"),
        model("google/gemini-2.5-flash", "Gemini 2.5 Flash"),
        model("deepseek/deepseek-chat-v3.1", "DeepSeek Chat V3.1"),
      ],
    },
    {
      id: "ollama-local",
      displayName: "Ollama Local",
      description: "Local OpenAI-compatible models served from your machine.",
      baseUrl: "http://127.0.0.1:11434/v1",
      apiFormat: "openai-compatible",
      logoUrl: `${LOGO_BASE}/ollama.svg`,
      websiteUrl: "https://ollama.com/download",
      enabled: true,
      supportsModelDiscovery: true,
      status: "available",
      models: [
        model("llama3.1", "Llama 3.1"),
        model("qwen2.5-coder", "Qwen2.5 Coder"),
        model("deepseek-coder-v2", "DeepSeek Coder V2"),
      ],
    },
    {
      id: "ollama-cloud",
      displayName: "Ollama Cloud",
      description: "Hosted Ollama cloud models through the OpenAI-compatible API.",
      baseUrl: "https://ollama.com/v1",
      apiFormat: "openai-compatible",
      apiKeyEnvVar: "OLLAMA_API_KEY",
      logoUrl: `${LOGO_BASE}/ollama.svg`,
      websiteUrl: "https://ollama.com/pricing",
      enabled: true,
      supportsModelDiscovery: true,
      status: "available",
      models: [
        model("gpt-oss:120b", "GPT OSS 120B"),
        model("gpt-oss:20b", "GPT OSS 20B"),
        model("deepseek-v3.1:671b", "DeepSeek V3.1 671B"),
        model("qwen3-coder:480b", "Qwen3 Coder 480B"),
      ],
    },
    {
      id: "openai",
      displayName: "OpenAI",
      description: "OpenAI-compatible API for GPT and reasoning-capable models.",
      baseUrl: "https://api.openai.com/v1",
      apiFormat: "openai-compatible",
      apiKeyEnvVar: "OPENAI_API_KEY",
      logoUrl: `${LOGO_BASE}/openai.svg`,
      websiteUrl: "https://openai.com/api/pricing/",
      enabled: true,
      supportsModelDiscovery: true,
      status: "available",
      models: [
        model("gpt-4.1", "GPT-4.1"),
        model("gpt-4.1-mini", "GPT-4.1 Mini"),
        model("gpt-4o", "GPT-4o"),
        model("gpt-4o-mini", "GPT-4o Mini"),
      ],
    },
    {
      id: "anthropic",
      displayName: "Anthropic",
      description: "Claude models through Anthropic's OpenAI compatibility layer.",
      baseUrl: "https://api.anthropic.com/v1",
      apiFormat: "anthropic",
      apiKeyEnvVar: "ANTHROPIC_API_KEY",
      logoUrl: `${LOGO_BASE}/anthropic.svg`,
      websiteUrl: "https://www.anthropic.com/pricing",
      enabled: true,
      supportsModelDiscovery: true,
      status: "available",
      models: [
        model("claude-opus-4-8", "Claude Opus 4.8"),
        model("claude-sonnet-4-6", "Claude Sonnet 4.6"),
        model("claude-haiku-4-5", "Claude Haiku 4.5"),
      ],
    },
    {
      id: "google-gemini",
      displayName: "Google Gemini",
      description: "Gemini models through Google's OpenAI-compatible endpoint.",
      baseUrl: "https://generativelanguage.googleapis.com/v1beta/openai",
      apiFormat: "gemini",
      apiKeyEnvVar: "GEMINI_API_KEY",
      logoUrl: `${LOGO_BASE}/google-gemini.svg`,
      websiteUrl: "https://ai.google.dev/gemini-api/docs/pricing",
      enabled: true,
      supportsModelDiscovery: true,
      status: "available",
      models: [
        model("gemini-3.5-flash", "Gemini 3.5 Flash"),
        model("gemini-3.1-pro", "Gemini 3.1 Pro"),
        model("gemini-3-flash", "Gemini 3 Flash"),
      ],
    },
    {
      id: "cursor",
      displayName: "Cursor Cloud Agents",
      description: "One-key Cursor Cloud Agents integration for future agent handoff workflows.",
      baseUrl: "https://api.cursor.com",
      apiFormat: "cursor",
      apiKeyEnvVar: "CURSOR_API_KEY",
      logoUrl: `${LOGO_BASE}/cursor.svg`,
      websiteUrl: "https://cursor.com/pricing",
      enabled: true,
      supportsModelDiscovery: true,
      status: "available",
      models: [
        model("default", "Default Cursor agent model"),
        model("composer-1.5", "Composer 1.5"),
      ],
    },
  ];
}

export function providerFromPreset(preset: ProviderPreset, existing?: ProviderConfig): ProviderConfig {
  return {
    id: preset.id,
    displayName: preset.displayName,
    description: preset.description,
    baseUrl: preset.baseUrl,
    apiFormat: preset.apiFormat,
    presetId: preset.id,
    logoUrl: preset.logoUrl,
    websiteUrl: preset.websiteUrl,
    supportsModelDiscovery: preset.supportsModelDiscovery,
    authKind: existing?.authKind ?? (preset.id === "ollama-local" ? "custom" : "api_key"),
    apiKeyEnvVar: existing?.apiKeyEnvVar ?? preset.apiKeyEnvVar,
    ...(existing?.apiKey ? { apiKey: existing.apiKey } : {}),
    enabled: existing?.enabled ?? preset.enabled,
    models: mergeModels(existing?.models ?? [], preset.models),
    modelDiscovery: existing?.modelDiscovery ?? { status: "idle" },
  };
}

export function normalizeProviderConfig(provider: ProviderConfig): ProviderConfig {
  const preset = providerPresets().find((item) => item.id === provider.presetId || item.id === provider.id);
  const base = preset ? providerFromPreset(preset, provider) : provider;
  return {
    ...base,
    id: cleanProviderId(base.id),
    displayName: base.displayName?.trim() || base.id,
    baseUrl: base.baseUrl?.trim() ?? "",
    apiFormat: base.apiFormat ?? "openai-compatible",
    authKind: base.authKind ?? "api_key",
    enabled: Boolean(base.enabled),
    supportsModelDiscovery: base.supportsModelDiscovery ?? true,
    models: mergeModels([], base.models ?? []),
    modelDiscovery: base.modelDiscovery ?? { status: "idle" },
  };
}

export function mergeModels(existing: ModelConfig[], incoming: ModelConfig[]): ModelConfig[] {
  const byId = new Map<string, ModelConfig>();
  for (const item of existing) {
    if (!item.id?.trim()) continue;
    byId.set(item.id, {
      id: item.id,
      label: item.label?.trim() || labelFromModelId(item.id),
      enabled: item.enabled !== false,
    });
  }
  for (const item of incoming) {
    if (!item.id?.trim()) continue;
    const current = byId.get(item.id);
    byId.set(item.id, {
      id: item.id,
      label: item.label?.trim() || current?.label || labelFromModelId(item.id),
      enabled: current?.enabled ?? item.enabled !== false,
    });
  }
  return [...byId.values()].sort((left, right) => left.label.localeCompare(right.label));
}

export function labelFromModelId(id: string): string {
  return id
    .replace(/^models\//u, "")
    .split(/[-_/]/u)
    .filter(Boolean)
    .map((part) => {
      if (/^(gpt|glm|mimo|api|ai|v\d+)$/iu.test(part)) return part.toUpperCase();
      if (/^\d+(?:\.\d+)*$/u.test(part)) return part;
      return `${part.slice(0, 1).toUpperCase()}${part.slice(1)}`;
    })
    .join(" ");
}

function model(id: string, label: string, enabled = true): ModelConfig {
  return { id, label, enabled };
}

function cleanProviderId(id: string): string {
  const cleaned = id.trim().toLowerCase().replace(/[^a-z0-9_-]+/gu, "-").replace(/^-+|-+$/gu, "");
  return cleaned || "custom-provider";
}
