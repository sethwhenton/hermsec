import fs from "node:fs/promises";
import path from "node:path";
import { explainFinding, summarizeRun } from "../agent/explainer.js";
import { runScan, targetDisplayName } from "../core/scan.js";
import { runDoctor as runDoctorChecks } from "../doctor/checks.js";
import { getIntelFeed } from "../intel/feed.js";
import { updateIntel as updateIntelCommand } from "../intel/update.js";
import { listConfiguredProviders, selectModelProvider } from "../model/providerRouter.js";
import type { ModelProviderId, ProviderConfig } from "../model/provider.js";
import { renderReport } from "../reports/reportRenderer.js";
import { listReportIndexEntries, latestReportForWorkspace } from "../reports/reportIndex.js";
import type { ReportDocument } from "../reports/schema.js";
import type { CommandResult, ScanMode } from "../shared/types.js";
import {
  appendSessionMessage,
  createSessionRecord,
  listSessions,
  saveSession,
  type SessionRecord,
} from "../storage/sessionStore.js";
import {
  loadUserConfig,
  modelProviders,
  privacyModes,
  reportLocations,
  saveUserConfig,
  type PreferredModelProvider,
  type UserConfig,
} from "../storage/userConfig.js";
import {
  addOrUpdateWorkspace,
  getActiveWorkspace,
  getWorkspace,
  listWorkspaces,
  setActiveWorkspace,
  updateWorkspace,
  type WorkspaceProfile,
} from "../storage/workspaceStore.js";
import type {
  ChatTurnInput,
  ChatTurnResult,
  DesktopIntelItem,
  DesktopProviderOption,
  DesktopSettings,
  DesktopState,
  DoctorDesktopResult,
  SaveSettingsInput,
  ScanWorkspaceInput,
  ScanWorkspaceResult,
  UpdateIntelResult,
} from "./types.js";

const DEFAULT_MODEL = "deepseek-v4-flash";

export async function getDesktopState(cwd: string, envFile?: string): Promise<DesktopState> {
  const config = await loadUserConfig();
  const workspaces = await listWorkspaces();
  const activeWorkspace = await getActiveWorkspace();
  const sessions = activeWorkspace ? await listSessions(activeWorkspace.id) : [];
  const reports = await listReportIndexEntries(activeWorkspace ? { workspaceId: activeWorkspace.id } : {});
  const intel = await getDesktopIntelFeed();
  const providerSelection = await currentProviderSelection(config);
  const state: DesktopState = {
    cwd,
    config,
    settings: settingsFromConfig(config),
    workspaces,
    sessions,
    reports,
    intel,
    providerHealth: providerSelection.health,
    providerOptions: await providerOptions(),
  };
  if (envFile) {
    state.envFile = envFile;
  }
  if (activeWorkspace) {
    state.activeWorkspace = activeWorkspace;
  }
  if (providerSelection.fallbackReason) {
    state.providerFallbackReason = providerSelection.fallbackReason;
  }
  return state;
}

export async function addWorkspaceFromPath(rootPath: string): Promise<WorkspaceProfile> {
  return addOrUpdateWorkspace({ rootPath });
}

export async function scanWorkspace(input: ScanWorkspaceInput): Promise<ScanWorkspaceResult> {
  const workspace = await resolveWorkspace(input);
  const mode = input.mode ?? workspace.scanMode ?? "offline";
  const run = await runScan({ target: input.target ?? workspace.rootPath, mode });
  const report = await renderReport({
    scanRun: run,
    workspaceId: workspace.id,
    workspaceName: workspace.displayName,
    configuredReportDir: workspace.reportDir,
    target: {
      kind: "local-path",
      value: run.target,
      displayName: workspace.displayName,
    },
    formats: ["html", "markdown", "json"],
    agentSummary: {
      provider: "none",
      fallbackReason: "Desktop scan reports are generated from deterministic scanner evidence by default.",
    },
  });

  const nextWorkspace = await updateWorkspace(workspace.id, (current) => {
    const updated: WorkspaceProfile = {
      ...current,
      lastScanId: run.id,
    };
    if (run.git?.commit) {
      updated.lastScannedCommit = run.git.commit;
    }
    return updated;
  });

  return {
    run,
    workspace: nextWorkspace,
    report: {
      ...("htmlPath" in report.artifacts ? { htmlPath: report.artifacts.htmlPath } : {}),
      ...("markdownPath" in report.artifacts ? { markdownPath: report.artifacts.markdownPath } : {}),
      documentPath: report.artifacts.documentPath,
      reportDir: report.paths.reportDir,
    },
    summaryText: summarizeRun(run),
  };
}

export async function updateSecurityIntel(cwd: string, offline = false): Promise<UpdateIntelResult> {
  const result = await updateIntelCommand({ cwd, offline });
  if (!result.ok) {
    throw commandError(result);
  }
  const data = result.data as { summaryText?: string } | undefined;
  return {
    message: result.message,
    ...(data?.summaryText ? { summaryText: data.summaryText } : {}),
    feed: await getDesktopIntelFeed(),
  };
}

export async function runDoctor(cwd: string): Promise<DoctorDesktopResult> {
  const result = await runDoctorChecks({ cwd, json: true, env: process.env });
  const data = result.ok ? result.data : undefined;
  return {
    message: result.message,
    ...(data?.summary ? { summary: data.summary } : {}),
  };
}

export async function saveDesktopSettings(cwd: string, input: SaveSettingsInput, envFile?: string): Promise<DesktopState> {
  const current = await loadUserConfig();
  const next: UserConfig = { ...current };
  if (input.privacyMode && isOneOf(input.privacyMode, privacyModes)) {
    next.privacyMode = input.privacyMode;
  }
  if (input.defaultReportLocation && isOneOf(input.defaultReportLocation, reportLocations)) {
    next.defaultReportLocation = input.defaultReportLocation;
  }
  if (input.customReportDir) {
    next.customReportDir = path.resolve(cwd, input.customReportDir);
    next.defaultReportLocation = "custom";
  }
  if (input.preferredModelProvider && isOneOf(input.preferredModelProvider, modelProviders)) {
    next.preferredModelProvider = input.preferredModelProvider;
  }
  if (input.providerCredentialEnv) {
    next.providerCredentialRef = { kind: "env", name: input.providerCredentialEnv };
  }
  if (input.providerCredentialEnv === "") {
    delete next.providerCredentialRef;
  }
  await saveUserConfig(next);
  if (input.model) {
    process.env.HERMSEC_MODEL = input.model;
  }
  if (input.allowRemoteProviders !== undefined) {
    process.env.HERMSEC_ALLOW_REMOTE_PROVIDERS = input.allowRemoteProviders ? "true" : "false";
  }
  return getDesktopState(cwd, envFile);
}

export async function chatTurn(cwd: string, input: ChatTurnInput): Promise<ChatTurnResult> {
  const workspace = input.workspaceId ? await getWorkspace(input.workspaceId) : await getActiveWorkspace();
  const session = workspace ? await ensureSession(workspace.id, input.sessionId) : undefined;
  if (session) {
    await appendSessionMessage(session.workspaceId, session.id, {
      role: "user",
      content: input.content,
      redactionApplied: false,
    });
  }

  const trimmed = input.content.trim();
  const commandResult = await tryRunCommand(cwd, trimmed, workspace);
  if (commandResult) {
    return withStoredAssistantMessage(session, commandResult);
  }

  const message = await answerWithConfiguredModel(trimmed, workspace);
  return withStoredAssistantMessage(session, { message });
}

async function tryRunCommand(
  cwd: string,
  content: string,
  workspace: WorkspaceProfile | undefined,
): Promise<Omit<ChatTurnResult, "session"> | undefined> {
  const [command, ...rest] = content.split(/\s+/);
  switch (command?.toLowerCase()) {
    case "/help":
    case "/commands":
      return {
        message: [
          "Hermsec commands:",
          "/scan [path] - run the local scan harness and save a report",
          "/intel - refresh trusted vulnerability intelligence",
          "/doctor - check local tool readiness",
          "/reports - list saved reports",
          "/settings - open model, privacy, and report settings",
        ].join("\n"),
      };
    case "/scan": {
      const target = rest.length > 0 ? rest.join(" ") : workspace?.rootPath;
      if (!target) {
        return { message: "Choose a workspace first, then run /scan." };
      }
      const scanInput: ScanWorkspaceInput = { target, mode: workspace?.scanMode ?? "offline" };
      if (workspace?.id) {
        scanInput.workspaceId = workspace.id;
      }
      const scan = await scanWorkspace(scanInput);
      return { message: scan.summaryText, scan };
    }
    case "/intel": {
      const intel = await updateSecurityIntel(cwd, false);
      return { message: intel.summaryText ?? intel.message, intel };
    }
    case "/doctor": {
      const doctor = await runDoctor(cwd);
      return { message: doctor.message };
    }
    case "/reports": {
      const reports = await listReportIndexEntries(workspace ? { workspaceId: workspace.id } : {});
      return {
        message: reports.length
          ? reports.slice(0, 8).map((report) => `${report.generatedAt}  ${report.scanId}`).join("\n")
          : "No saved reports yet.",
      };
    }
    case "/settings":
      return { message: "Settings are available in the right panel. Configure privacy mode, provider, model, and report location there." };
    default:
      return undefined;
  }
}

async function answerWithConfiguredModel(content: string, workspace: WorkspaceProfile | undefined): Promise<string> {
  const config = await loadUserConfig();
  const selection = await currentProviderSelection(config);
  if (selection.provider.id === "none" || selection.fallbackReason) {
    return [
      "I can route safe Hermsec actions right now.",
      "Try /scan, /intel, /doctor, /reports, or enable a provider in Settings for model-backed explanations.",
      selection.fallbackReason ? `Provider note: ${selection.fallbackReason}` : "",
    ].filter(Boolean).join("\n");
  }

  const report = workspace ? await latestReportDocument(workspace.id) : undefined;
  const findings = report?.findings.slice(0, 5).map((finding) => explainFinding(finding));
  const prompt = [
    content,
    "",
    `Workspace: ${workspace?.displayName ?? "none selected"}`,
    report ? `Latest summary: total=${report.summary.total}, critical=${report.summary.critical}, high=${report.summary.high}, medium=${report.summary.medium}, low=${report.summary.low}` : "Latest summary: no scan report yet",
    findings?.length
      ? `Scanner-backed findings:\n${findings.map((finding) => `- ${finding.summary} Next: ${finding.nextStep}`).join("\n")}`
      : "Scanner-backed findings: none",
  ].join("\n");

  const response = await selection.provider.complete({
    model: process.env.HERMSEC_MODEL ?? DEFAULT_MODEL,
    temperature: 0,
    maxTokens: 4_000,
    messages: [
      {
        role: "system",
        content:
          "You are Hermsec, a defensive security assistant. Return a concise final answer. Use only scanner-backed evidence; do not invent CVEs, file paths, packages, versions, or line numbers.",
      },
      { role: "user", content: prompt },
    ],
  }, providerConfig(config));
  return response.content;
}

async function withStoredAssistantMessage(
  session: SessionRecord | undefined,
  result: Omit<ChatTurnResult, "session">,
): Promise<ChatTurnResult> {
  if (!session) {
    return result;
  }
  const saved = await appendSessionMessage(session.workspaceId, session.id, {
    role: "assistant",
    content: result.message,
    redactionApplied: false,
  });
  return { ...result, session: saved };
}

async function ensureSession(workspaceId: string, sessionId: string | undefined): Promise<SessionRecord> {
  const existing = await listSessions(workspaceId);
  const selected = sessionId ? existing.find((session) => session.id === sessionId) : existing[0];
  if (selected) {
    return selected;
  }
  return saveSession(createSessionRecord(workspaceId, "Hermsec desktop session"));
}

async function resolveWorkspace(input: ScanWorkspaceInput): Promise<WorkspaceProfile> {
  if (input.workspaceId) {
    const workspace = await getWorkspace(input.workspaceId);
    if (!workspace) {
      throw new Error(`Unknown workspace: ${input.workspaceId}`);
    }
    return workspace;
  }
  const active = await getActiveWorkspace();
  if (active) {
    return active;
  }
  if (input.target) {
    return addOrUpdateWorkspace({ rootPath: input.target, displayName: targetDisplayName(input.target) });
  }
  throw new Error("No workspace selected.");
}

async function currentProviderSelection(config: UserConfig) {
  return selectModelProvider(providerConfig(config), config.privacyMode);
}

function providerConfig(config: UserConfig): ProviderConfig {
  const provider = configuredProvider(config);
  const apiKeyEnv = config.providerCredentialRef?.kind === "env"
    ? config.providerCredentialRef.name
    : process.env.HERMSEC_MODEL_API_KEY_ENV;
  const result: ProviderConfig = {
    provider,
    model: process.env.HERMSEC_MODEL ?? DEFAULT_MODEL,
    allowRemoteProviders: process.env.HERMSEC_ALLOW_REMOTE_PROVIDERS === "true" || config.privacyMode !== "local-only",
    timeoutMs: 45_000,
  };
  if (apiKeyEnv) {
    result.apiKeyEnv = apiKeyEnv;
  }
  if (process.env.HERMSEC_MODEL_BASE_URL) {
    result.baseUrl = process.env.HERMSEC_MODEL_BASE_URL;
  }
  return result;
}

function configuredProvider(config: UserConfig): ModelProviderId {
  const envProvider = process.env.HERMSEC_MODEL_PROVIDER;
  if (envProvider && isOneOf(envProvider, modelProviders)) {
    return envProvider;
  }
  return config.preferredModelProvider ?? "none";
}

function settingsFromConfig(config: UserConfig): DesktopSettings {
  const settings: DesktopSettings = {
    privacyMode: config.privacyMode,
    defaultReportLocation: config.defaultReportLocation,
    preferredModelProvider: configuredProvider(config) as PreferredModelProvider,
    model: process.env.HERMSEC_MODEL ?? DEFAULT_MODEL,
    allowRemoteProviders: process.env.HERMSEC_ALLOW_REMOTE_PROVIDERS === "true" || config.privacyMode !== "local-only",
  };
  if (config.customReportDir) {
    settings.customReportDir = config.customReportDir;
  }
  if (config.providerCredentialRef?.kind === "env" && config.providerCredentialRef.name) {
    settings.providerCredentialEnv = config.providerCredentialRef.name;
  } else if (process.env.HERMSEC_MODEL_API_KEY_ENV) {
    settings.providerCredentialEnv = process.env.HERMSEC_MODEL_API_KEY_ENV;
  }
  return settings;
}

async function providerOptions(): Promise<DesktopProviderOption[]> {
  return Promise.all(listConfiguredProviders().map(async (provider) => ({
    id: provider.id,
    label: provider.id === "none" ? "No model" : provider.id,
    local: (await provider.healthCheck({ provider: provider.id })).local,
    models: (await provider.listModels()).map((model) => model.id),
  })));
}

async function getDesktopIntelFeed(): Promise<DesktopIntelItem[]> {
  const feed = await getIntelFeed({ limit: 8, includeFallback: true });
  return feed.map((item) => {
    const next: DesktopIntelItem = {
      id: item.item.id,
      title: item.item.title,
      source: item.item.source,
      whyShown: item.whyShown,
      cacheStatus: item.cacheStatus,
    };
    if (item.item.severity) {
      next.severity = item.item.severity;
    }
    if (item.item.url) {
      next.url = item.item.url;
    }
    return next;
  });
}

async function latestReportDocument(workspaceId: string): Promise<ReportDocument | undefined> {
  const latest = await latestReportForWorkspace(workspaceId);
  if (!latest) {
    return undefined;
  }
  const documentPath = path.join(latest.reportDir, "report-document.json");
  try {
    return JSON.parse(await fs.readFile(documentPath, "utf8")) as ReportDocument;
  } catch {
    return undefined;
  }
}

function commandError(result: CommandResult): Error {
  return new Error(`${result.message}${result.ok ? "" : result.remediation ? `\n${result.remediation}` : ""}`);
}

function isOneOf<T extends readonly string[]>(value: string, allowed: T): value is T[number] {
  return (allowed as readonly string[]).includes(value);
}
