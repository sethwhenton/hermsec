import fs from "node:fs/promises";
import path from "node:path";
import { providerCredentialEnv } from "../model/credentials.js";
import { listConfiguredProviders, selectModelProvider } from "../model/providerRouter.js";
import type { ModelProviderId, ProviderConfig, ProviderHealth } from "../model/provider.js";
import { latestReportForWorkspace } from "../reports/reportIndex.js";
import type { ReportDocument } from "../reports/schema.js";
import { redactSecrets, stableId } from "../shared/text.js";
import type { CommandResult, ScanMode } from "../shared/types.js";
import { loadUserConfig, modelProviders, type UserConfig } from "../storage/userConfig.js";

const DEFAULT_MODEL = "deepseek-v4-flash";
const MAX_MANIFEST_BYTES = 16_000;
const MAX_PROJECT_ENTRIES = 80;
const MAX_REPORT_FINDINGS = 8;

const PROJECT_MANIFESTS = [
  "package.json",
  "pnpm-lock.yaml",
  "package-lock.json",
  "yarn.lock",
  "bun.lockb",
  "pyproject.toml",
  "requirements.txt",
  "poetry.lock",
  "Pipfile",
  "go.mod",
  "Cargo.toml",
  "composer.json",
  "Gemfile",
  "Dockerfile",
  "docker-compose.yml",
] as const;

export type AgentAskOptions = {
  cwd: string;
  content: string;
  target?: string;
  mode?: ScanMode;
  useModel?: boolean;
};

export type AgentAskData = {
  message: string;
  provider: ModelProviderId;
  model: string;
  health: ProviderHealth;
  fallbackReason?: string;
  target?: string;
  mode: ScanMode;
};

export type AgentProviderOption = {
  id: ModelProviderId;
  label: string;
  local: boolean;
  credentialEnv?: string;
  credential?: ProviderHealth["credential"];
  credentialFingerprint?: string;
  ok: boolean;
  message: string;
  models: string[];
};

export type AgentProviderStatusData = {
  configuredProvider: ModelProviderId;
  configuredModel: string;
  privacyMode: UserConfig["privacyMode"];
  selected: ProviderHealth;
  fallbackReason?: string;
  providers: AgentProviderOption[];
};

export async function askSecurityAgent(options: AgentAskOptions): Promise<CommandResult<AgentAskData>> {
  const content = options.content.trim();
  if (!content) {
    return {
      ok: false,
      errorCode: "EMPTY_AGENT_MESSAGE",
      message: "Agent message cannot be empty.",
      remediation: "Ask Hermsec a defensive security question or choose an action from the chat.",
    };
  }

  const config = await loadUserConfig();
  const providerConfig = buildProviderConfig(config);
  const selection = await selectModelProvider(providerConfig, config.privacyMode);
  const mode = options.mode ?? "auto";
  const target = options.target ? path.resolve(options.cwd, options.target) : undefined;

  if (options.useModel === false || selection.provider.id === "none" || selection.fallbackReason) {
    const message = [
      "Hermsec can answer with scanner-backed context once a model provider is configured and allowed.",
      "Available local actions: scan repo, set an automation, list reports, refresh security intel, and run doctor checks.",
      selection.fallbackReason ? `Provider note: ${selection.fallbackReason}` : selection.health.message,
    ].join("\n");
    return {
      ok: true,
      message,
      data: {
        message,
        provider: selection.provider.id,
        model: providerConfig.model ?? DEFAULT_MODEL,
        health: selection.health,
        ...(selection.fallbackReason ? { fallbackReason: selection.fallbackReason } : {}),
        ...(target ? { target } : {}),
        mode,
      },
    };
  }

  const prompt = await buildAgentPrompt({
    content,
    cwd: options.cwd,
    mode,
    ...(target ? { target } : {}),
  });
  const response = await selection.provider.complete(
    {
      temperature: 0,
      maxTokens: 4_000,
      ...(providerConfig.model ? { model: providerConfig.model } : {}),
      messages: [
        {
          role: "system",
          content: [
            "You are Hermsec, a defensive security assistant for local repositories.",
            "Use a formal, concise, direct tone.",
            "Avoid casual greetings, playful language, excessive encouragement, and ultra-friendly chat.",
            "Answer with the minimum context needed to be useful.",
            "HermSec product context: HermSec is a local-first desktop security assistant for code projects. It inspects project folders, detects languages/manifests/lockfiles/config files, chooses matching scanner tools, runs defensive checks, validates evidence, and writes dashboard, JSON, Markdown, HTML, and PDF reports.",
            "HermSec features include Doctor readiness checks, live chat progress, provider/model setup, report links, and in-app scan automations.",
            "HermSec scan modes: Deep assisted scan runs scanners first and uses the model to explain scanner-backed findings. Single agent inspection uses one configured model without scanner tools. MoA inspection means Mixture of Agents: specialist agents, a false-positive judge, and an aggregator review focused candidates without scanner tools. Scanner + MoA runs scanners and MoA independently, then validates, deduplicates, and merges both evidence sources.",
            "You may explain project structure, scanner-backed findings, secure defaults, and next defensive steps.",
            "Never claim you scanned files unless scanner evidence or a supplied report says so.",
            "Never invent CVEs, package versions, file paths, or line numbers.",
            "Do not provide exploit payloads, secret exfiltration steps, destructive shell commands, or dependency-install instructions.",
            "If the user asks to scan or automate, tell them to use the Hermsec scan or automation action.",
          ].join(" "),
        },
        { role: "user", content: prompt },
      ],
    },
    providerConfig,
  );

  const message = response.content.trim();
  return {
    ok: true,
    message,
    data: {
      message,
      provider: response.provider,
      model: response.model,
      health: selection.health,
      ...(target ? { target } : {}),
      mode,
    },
  };
}

export async function getAgentProviderStatus(options: {
  cwd: string;
}): Promise<CommandResult<AgentProviderStatusData>> {
  void options;
  const config = await loadUserConfig();
  const providerConfig = buildProviderConfig(config);
  const selection = await selectModelProvider(providerConfig, config.privacyMode);
  const providers = await Promise.all(
    listConfiguredProviders().map(async (provider) => {
      const configuredEnvName =
        provider.id === providerConfig.provider ? providerConfig.apiKeyEnv : undefined;
      const envName = configuredEnvName ?? providerCredentialEnv[provider.id];
      const configForProvider: ProviderConfig = {
        provider: provider.id,
        ...(providerConfig.model ? { model: providerConfig.model } : {}),
        ...(providerConfig.allowRemoteProviders !== undefined
          ? { allowRemoteProviders: providerConfig.allowRemoteProviders }
          : {}),
        ...(providerConfig.timeoutMs !== undefined ? { timeoutMs: providerConfig.timeoutMs } : {}),
        ...(envName ? { apiKeyEnv: envName } : {}),
        ...(provider.id === providerConfig.provider && providerConfig.baseUrl
          ? { baseUrl: providerConfig.baseUrl }
          : {}),
      };
      const [health, models] = await Promise.all([
        provider.healthCheck(configForProvider),
        provider.listModels(configForProvider),
      ]);
      const providerLabel = health.provider === "none"
        ? "Scanner-only"
        : health.provider === "opencode-go"
          ? "OpenCode Go"
          : health.provider === "openai-compatible"
            ? "OpenAI-compatible"
            : health.provider === "openrouter"
              ? "OpenRouter"
              : health.provider === "openai"
                ? "OpenAI"
                : health.provider === "claude"
                  ? "Claude"
                  : health.provider === "gemini"
                    ? "Google Gemini"
                    : health.provider === "ollama"
                      ? "Ollama"
                      : health.provider;
      const option: AgentProviderOption = {
        id: provider.id,
        label: providerLabel,
        local: health.local,
        ok: health.ok,
        message: health.message,
        models: models.map((model) => model.id),
      };
      if (health.credentialEnv) option.credentialEnv = health.credentialEnv;
      if (health.credential) option.credential = health.credential;
      if (health.credentialFingerprint) option.credentialFingerprint = health.credentialFingerprint;
      return option;
    }),
  );

  return {
    ok: true,
    message: selection.fallbackReason
      ? `Provider fallback: ${selection.fallbackReason}`
      : selection.health.message,
    data: {
      configuredProvider: providerConfig.provider ?? "none",
      configuredModel: providerConfig.model ?? DEFAULT_MODEL,
      privacyMode: config.privacyMode,
      selected: selection.health,
      ...(selection.fallbackReason ? { fallbackReason: selection.fallbackReason } : {}),
      providers,
    },
  };
}

function buildProviderConfig(config: UserConfig): ProviderConfig {
  const provider = effectiveProvider(config);
  const apiKeyEnv = config.providerCredentialRef?.kind === "env"
    ? config.providerCredentialRef.name
    : providerCredentialEnv[provider];
  const result: ProviderConfig = {
    provider,
    model: process.env.HERMSEC_MODEL?.trim() || DEFAULT_MODEL,
    allowRemoteProviders: config.privacyMode !== "local-only",
    timeoutMs: 45_000,
  };
  if (apiKeyEnv) result.apiKeyEnv = apiKeyEnv;
  if (process.env.HERMSEC_MODEL_BASE_URL?.trim()) {
    result.baseUrl = process.env.HERMSEC_MODEL_BASE_URL.trim();
  }
  return result;
}

function effectiveProvider(config: UserConfig): ModelProviderId {
  const envProvider = process.env.HERMSEC_MODEL_PROVIDER?.trim();
  if (envProvider && (modelProviders as readonly string[]).includes(envProvider)) {
    return envProvider as ModelProviderId;
  }
  return config.preferredModelProvider ?? "none";
}

async function buildAgentPrompt(input: {
  content: string;
  cwd: string;
  target?: string;
  mode: ScanMode;
}): Promise<string> {
  const target = input.target ? path.resolve(input.cwd, input.target) : undefined;
  const [project, report] = await Promise.all([
    target ? projectSnapshot(target) : Promise.resolve("No project folder selected."),
    target ? latestReportSnapshot(target) : Promise.resolve("No saved scan report for a selected project."),
  ]);

  return redactSecrets(
    [
      `User request: ${input.content}`,
      `Scan mode preference: ${input.mode}`,
      "",
      "Project context:",
      project,
      "",
      "Latest scanner-backed report context:",
      report,
    ].join("\n"),
  );
}

async function projectSnapshot(target: string): Promise<string> {
  try {
    const stats = await fs.stat(target);
    if (!stats.isDirectory()) {
      return `Selected target is a file: ${target}`;
    }
    const entries = await fs.readdir(target, { withFileTypes: true });
    const visibleEntries = entries
      .filter((entry) => !entry.name.startsWith(".") && entry.name !== "node_modules" && entry.name !== "dist")
      .slice(0, MAX_PROJECT_ENTRIES)
      .map((entry) => `${entry.isDirectory() ? "dir " : "file"} ${entry.name}`);
    const manifests = await Promise.all(PROJECT_MANIFESTS.map((name) => readManifest(target, name)));
    return [
      `Target: ${target}`,
      `Top-level entries:\n${visibleEntries.length ? visibleEntries.join("\n") : "No visible entries."}`,
      manifests.filter(Boolean).join("\n\n") || "No recognized dependency/build manifests found at project root.",
    ].join("\n\n");
  } catch (error) {
    return `Could not read selected project folder: ${error instanceof Error ? error.message : String(error)}`;
  }
}

async function readManifest(target: string, name: string): Promise<string> {
  const filePath = path.join(target, name);
  try {
    const stats = await fs.stat(filePath);
    if (!stats.isFile() || stats.size > MAX_MANIFEST_BYTES) {
      return "";
    }
    const raw = await fs.readFile(filePath, "utf8");
    return `--- ${name} ---\n${raw.slice(0, MAX_MANIFEST_BYTES)}`;
  } catch {
    return "";
  }
}

async function latestReportSnapshot(target: string): Promise<string> {
  try {
    const workspaceId = stableId(target, "ws");
    const latest = await latestReportForWorkspace(workspaceId);
    if (!latest) {
      return "No saved Hermsec report was found for this project. Ask Hermsec to scan first for scanner-backed findings.";
    }
    const documentPath = path.join(latest.reportDir, "report-document.json");
    const document = JSON.parse(await fs.readFile(documentPath, "utf8")) as ReportDocument;
    const findings = document.findings.slice(0, MAX_REPORT_FINDINGS).map((finding) => {
      const location = finding.location
        ? `${finding.location.file}${finding.location.startLine ? `:${finding.location.startLine}` : ""}`
        : "no location";
      return [
        `${finding.id}: ${finding.severity.toUpperCase()} ${finding.title}`,
        `category=${finding.category}; confidence=${finding.confidence}; tool=${finding.tool}; location=${location}`,
        `evidence=${finding.evidence}`,
        `remediation=${finding.remediation}`,
      ].join("\n");
    });
    return [
      `Report: ${document.scanId} generated ${document.generatedAt}`,
      `Summary: total=${document.summary.total}, critical=${document.summary.critical}, high=${document.summary.high}, medium=${document.summary.medium}, low=${document.summary.low}, info=${document.summary.info}`,
      findings.length ? findings.join("\n\n") : "No findings in latest report.",
    ].join("\n\n");
  } catch (error) {
    return `Could not read latest report context: ${error instanceof Error ? error.message : String(error)}`;
  }
}
