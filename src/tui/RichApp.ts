import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import process from "node:process";
import blessed from "blessed";

import { setConfigValue, loadUserConfig, modelProviders, type PreferredModelProvider } from "../storage/userConfig.js";
import { defaultReportDir, normalizeTargetPath } from "../shared/paths.js";
import { redactSecrets, stableId } from "../shared/text.js";
import type { CommandResult } from "../shared/types.js";
import {
  activeWorkspace,
  defaultWorkspaceName,
  formatDoctor,
  formatHelp,
  formatHistory,
  formatReports,
  formatSchedules,
  formatSessions,
  formatStatus,
  formatWorkspaces,
  isLikelyUrl,
  normalizedDisplayPath,
  scanPreferenceLabel,
} from "./format.js";
import { createDefaultState } from "./App.js";
import type {
  ChatMessage,
  ModelMode,
  PrivacyMode,
  ReportLocation,
  ScanPreference,
  TuiDoctorReport,
  TuiIntelSummary,
  TuiReportSummary,
  TuiRunOptions,
  TuiRunSummary,
  TuiScanRequest,
  TuiScanResult,
  TuiScheduleSummary,
  TuiSessionSnapshot,
  TuiSessionSummary,
  TuiState,
  TuiStatus,
  TuiToolbox,
  TuiWorkspace,
} from "./types.js";

type BlessedNode = {
  setContent(value: string): void;
  destroy(): void;
  focus?(): void;
  log?(value: string): void;
  add?(value: string): void;
  scrollTo?(value: number): void;
  getScrollHeight?(): number;
  clearValue?(): void;
  setValue?(value: string): void;
  on(eventName: string, listener: (...args: unknown[]) => void): void;
};

type OnboardingStep =
  | "workspace"
  | "privacy"
  | "report"
  | "custom-report"
  | "model"
  | "scan"
  | "done";

type OnboardingDraft = {
  target?: string;
  privacyMode?: PrivacyMode;
  reportLocation?: ReportLocation;
  reportDir?: string;
  modelMode?: ModelMode;
  scanPreference?: ScanPreference;
};

type RichAction = {
  label: string;
  command: string;
  description: string;
};

const LOGO = String.raw`
 __  __ __   __
|  \/  |\ \ / /
| |\/| | \ V /
|_|  |_|  |_|
 _   _ _____ ____  __  __ ____  _____ ____
| | | | ____|  _ \|  \/  / ___|| ____/ ___|
| |_| |  _| | |_) | |\/| \___ \|  _|| |
|  _  | |___|  _ <| |  | |___) | |__| |___
|_| |_|_____|_| \_\_|  |_|____/|_____\____|
`.trim();

const PROVIDER_ENV: Record<PreferredModelProvider, string> = {
  none: "",
  ollama: "",
  openrouter: "OPENROUTER_API_KEY",
  openai: "OPENAI_API_KEY",
  claude: "ANTHROPIC_API_KEY",
  gemini: "GEMINI_API_KEY",
  "opencode-go": "OPENCODE_GO_API_KEY",
  "openai-compatible": "OPENAI_COMPATIBLE_API_KEY",
};

const DEFAULT_ACTIONS: RichAction[] = [
  { label: "Commands", command: "/commands", description: "Show command palette" },
  { label: "Doctor", command: "/doctor", description: "Readiness checks" },
  { label: "Scan", command: "/scan", description: "Scan active workspace" },
  { label: "Intel", command: "/intel", description: "Security updates" },
  { label: "Reports", command: "/reports", description: "Local report list" },
  { label: "Settings", command: "/settings", description: "Privacy/model/report settings" },
  { label: "Model", command: "/model", description: "Choose model provider" },
  { label: "Provider", command: "/provider", description: "Configure provider env var" },
  { label: "Sessions", command: "/sessions", description: "Saved chat history" },
];

export class RichHermsecTui {
  private readonly cwd: string;
  private readonly input: NodeJS.ReadableStream & { isTTY?: boolean };
  private readonly output: NodeJS.WritableStream & { columns?: number; isTTY?: boolean };
  private readonly tools: TuiToolbox;
  private readonly forceInteractive: boolean | undefined;
  private readonly skipOnboarding: boolean;
  private readonly forceOnboarding: boolean;
  private state: TuiState;
  private screen?: blessed.Widgets.Screen;
  private logo?: BlessedNode;
  private modelLine?: BlessedNode;
  private sidebar?: BlessedNode;
  private chat?: BlessedNode;
  private detail?: BlessedNode;
  private inputBox?: BlessedNode;
  private toolbar?: BlessedNode;
  private footer?: BlessedNode;
  private actionButtons: BlessedNode[] = [];
  private exitResolver?: (summary: TuiRunSummary) => void;
  private onboardingStep: OnboardingStep = "done";
  private onboardingDraft: OnboardingDraft = {};

  constructor(options: TuiRunOptions = {}) {
    this.cwd = options.cwd ?? process.cwd();
    this.input = options.input ?? process.stdin;
    this.output = options.output ?? process.stdout;
    this.tools = options.tools ?? {};
    this.forceInteractive = options.forceInteractive;
    this.skipOnboarding = options.skipOnboarding ?? false;
    this.forceOnboarding = options.forceOnboarding ?? false;
    this.state = createDefaultState(this.cwd, options.initialState);
  }

  async run(): Promise<TuiRunSummary> {
    if (!this.isInteractive()) {
      this.output.write(nonInteractiveMessage());
      return { exitReason: "non-interactive", state: this.state };
    }

    await this.loadExternalState();
    this.screen = blessed.screen({
      input: this.input as never,
      output: this.output as never,
      smartCSR: true,
      fullUnicode: true,
      autoPadding: true,
      title: "Hermsec",
    });
    this.screen.enableMouse();

    this.buildLayout();
    this.bindKeys();
    this.addHermsecMessage("Hermsec is ready. Paste paths or commands into the input, then press Enter.");

    if (this.forceOnboarding || (!this.skipOnboarding && this.state.workspaces.length === 0)) {
      this.startOnboarding();
    } else {
      this.showHome();
    }

    this.inputBox?.focus?.();
    this.render();

    return new Promise<TuiRunSummary>((resolve) => {
      this.exitResolver = resolve;
    });
  }

  private async loadExternalState(): Promise<void> {
    if (!this.tools.loadState) {
      return;
    }
    const external = await this.tools.loadState();
    this.state = createDefaultState(this.cwd, { ...this.state, ...external });
  }

  private buildLayout(): void {
    if (!this.screen) {
      return;
    }

    this.logo = blessed.box({
      parent: this.screen,
      top: 1,
      left: 2,
      width: 31,
      height: 11,
      tags: true,
      content: `{cyan-fg}${LOGO}{/cyan-fg}`,
      style: { fg: "cyan", bg: "black" },
    }) as BlessedNode;

    this.modelLine = blessed.box({
      parent: this.screen,
      top: 12,
      left: 2,
      width: 31,
      height: 5,
      tags: true,
      content: "loading settings...",
      style: { fg: "white", bg: "black" },
    }) as BlessedNode;

    this.sidebar = blessed.box({
      parent: this.screen,
      top: 17,
      left: 1,
      width: 33,
      bottom: 6,
      border: "line",
      tags: true,
      label: " actions ",
      style: {
        fg: "white",
        bg: "black",
        border: { fg: "cyan" },
      },
    }) as BlessedNode;

    this.chat = blessed.log({
      parent: this.screen,
      top: 1,
      left: 35,
      right: 39,
      bottom: 13,
      border: "line",
      tags: true,
      mouse: true,
      keys: true,
      scrollable: true,
      alwaysScroll: true,
      scrollbar: { ch: " ", style: { bg: "cyan" } },
      label: " chat ",
      style: {
        fg: "white",
        bg: "black",
        border: { fg: "cyan" },
      },
    }) as BlessedNode;

    this.detail = blessed.box({
      parent: this.screen,
      top: 1,
      right: 1,
      width: 38,
      bottom: 13,
      border: "line",
      tags: true,
      mouse: true,
      keys: true,
      scrollable: true,
      alwaysScroll: true,
      scrollbar: { ch: " ", style: { bg: "cyan" } },
      label: " context ",
      style: {
        fg: "white",
        bg: "black",
        border: { fg: "cyan" },
      },
    }) as BlessedNode;

    this.toolbar = blessed.box({
      parent: this.screen,
      left: 35,
      right: 1,
      bottom: 7,
      height: 6,
      tags: true,
      border: "line",
      label: " buttons ",
      style: { fg: "white", bg: "black", border: { fg: "cyan" } },
    }) as BlessedNode;

    this.inputBox = blessed.textbox({
      parent: this.screen,
      left: 35,
      right: 1,
      bottom: 2,
      height: 4,
      border: "line",
      tags: false,
      keys: true,
      mouse: true,
      inputOnFocus: true,
      label: " paste or type command ",
      style: {
        fg: "white",
        bg: "black",
        border: { fg: "cyan" },
        focus: { border: { fg: "yellow" } },
      },
    }) as BlessedNode;

    this.footer = blessed.box({
      parent: this.screen,
      left: 1,
      right: 1,
      bottom: 0,
      height: 1,
      tags: true,
      content: "Enter submits | Tab focuses input | mouse clicks buttons | Ctrl+C exits | /commands lists everything",
      style: { fg: "gray", bg: "black" },
    }) as BlessedNode;

    this.inputBox.on("submit", (value: unknown) => {
      const text = String(value ?? "").trim();
      this.inputBox?.clearValue?.();
      void this.submit(text);
    });
  }

  private bindKeys(): void {
    if (!this.screen) {
      return;
    }
    this.screen.key(["C-c", "escape"], () => {
      void this.exit("user-exit");
    });
    this.screen.key(["tab"], () => {
      this.inputBox?.focus?.();
      this.render();
    });
    this.screen.key(["f1"], () => {
      void this.submit("/commands");
    });
    this.screen.key(["f2"], () => {
      void this.submit("/settings");
    });
    this.screen.key(["f3"], () => {
      void this.submit("/model");
    });
  }

  private async submit(rawInput: string): Promise<void> {
    const input = rawInput.trim();
    if (input.length === 0) {
      this.inputBox?.focus?.();
      return;
    }

    if (this.onboardingStep !== "done" && !input.startsWith("/")) {
      await this.handleOnboardingInput(input);
      this.inputBox?.focus?.();
      this.render();
      return;
    }

    this.addMessage("user", input);
    this.chat?.log?.(`{yellow-fg}You>{/yellow-fg} ${escapeTag(redactSecrets(input))}`);
    const normalized = input.toLowerCase();
    const [commandToken, ...restParts] = input.split(/\s+/);
    const command = commandToken?.toLowerCase() ?? "";
    const rest = input.slice(commandToken?.length ?? 0).trim();

    if (command === "/exit" || command === "/quit" || normalized === "exit" || normalized === "quit") {
      await this.exit("user-exit");
      return;
    }

    try {
      if (command === "/help" || command === "/commands" || normalized.includes("commands")) {
        this.showCommands();
      } else if (command === "/doctor" || /\bdoctor\b|\bready\b/.test(normalized)) {
        await this.runDoctor();
      } else if (command === "/scan" || /\bscan\b/.test(normalized)) {
        await this.runScan(rest || extractNaturalTarget(input));
      } else if (command === "/intel" || /\bsecurity news\b|\bintel\b/.test(normalized)) {
        await this.runIntel();
      } else if (command === "/reports" || /\breports?\b/.test(normalized)) {
        await this.runReports();
      } else if (command === "/workspace") {
        await this.runWorkspace(rest);
      } else if (command === "/schedule") {
        await this.runSchedules(restParts.join(" "));
      } else if (command === "/history") {
        this.showHistory(rest);
      } else if (command === "/sessions" || command === "/session") {
        await this.runSessions(rest);
      } else if (command === "/settings") {
        await this.handleSettingsCommand(rest);
      } else if (command === "/model") {
        await this.handleModelCommand(rest);
      } else if (command === "/provider") {
        await this.handleProviderCommand(rest);
      } else if (command === "/onboard") {
        this.startOnboarding();
      } else {
        this.addHermsecMessage("I can route safe Hermsec actions only. Use /commands, /scan <path>, /settings, /model, or /provider.");
        this.showCommands();
      }
    } catch (error) {
      this.addHermsecMessage(`Action failed safely: ${errorMessage(error)}`);
    }

    this.inputBox?.focus?.();
    this.render();
  }

  private startOnboarding(): void {
    this.onboardingStep = "workspace";
    this.onboardingDraft = {};
    this.addHermsecMessage("Welcome. Onboarding runs inside this terminal UI. Paste a workspace path, or click Use current folder.");
    this.showOnboarding();
  }

  private async handleOnboardingInput(input: string): Promise<void> {
    switch (this.onboardingStep) {
      case "workspace":
        await this.setOnboardingWorkspace(input);
        return;
      case "custom-report":
        this.onboardingDraft.reportDir = normalizeTargetPath(input);
        this.onboardingStep = "model";
        this.showOnboarding();
        return;
      default:
        this.addHermsecMessage("Use the onboarding buttons for this step, or type /commands.");
    }
  }

  private async setOnboardingWorkspace(value: string): Promise<void> {
    const target = value.trim() || this.cwd;
    if (!isLikelyUrl(target) && !(await localPathExists(target))) {
      this.addHermsecMessage(`That workspace path does not exist: ${target}`);
      this.showOnboarding();
      return;
    }
    this.onboardingDraft.target = isLikelyUrl(target) ? target : normalizeTargetPath(target);
    this.onboardingStep = "privacy";
    this.showOnboarding();
  }

  private showOnboarding(): void {
    const draft = this.onboardingDraft;
    const lines = [
      "{cyan-fg}Hermsec onboarding{/cyan-fg}",
      "",
      "This setup stays local. Keys are not requested here.",
      "",
      `Workspace: ${draft.target ?? "paste a local path or GitHub URL"}`,
      `Privacy: ${draft.privacyMode ?? "choose below"}`,
      `Reports: ${draft.reportDir ?? draft.reportLocation ?? "choose below"}`,
      `Model: ${draft.modelMode ?? "choose below"}`,
      `Scan: ${draft.scanPreference ?? "choose below"}`,
      "",
      onboardingInstruction(this.onboardingStep),
    ];
    this.detail?.setContent(lines.join("\n"));
    this.setActions(onboardingActions(this.onboardingStep, this.cwd), async (action) => {
      await this.handleOnboardingAction(action.command);
    });
  }

  private async handleOnboardingAction(command: string): Promise<void> {
    switch (command) {
      case "use-current":
        await this.setOnboardingWorkspace(this.cwd);
        break;
      case "privacy-local":
      case "privacy-balanced":
      case "privacy-cloud":
        this.onboardingDraft.privacyMode = command === "privacy-local"
          ? "local-only"
          : command === "privacy-balanced"
            ? "balanced"
            : "cloud-assisted";
        this.state.privacyMode = this.onboardingDraft.privacyMode;
        this.onboardingStep = "report";
        this.showOnboarding();
        break;
      case "report-app":
      case "report-project":
        this.onboardingDraft.reportLocation = command === "report-app" ? "app-data" : "project-local";
        this.onboardingDraft.reportDir = this.onboardingDraft.reportLocation === "project-local" && this.onboardingDraft.target && !isLikelyUrl(this.onboardingDraft.target)
          ? path.join(this.onboardingDraft.target, ".hermsec", "reports")
          : defaultReportDir();
        this.onboardingStep = "model";
        this.showOnboarding();
        break;
      case "report-custom":
        this.onboardingDraft.reportLocation = "custom";
        this.onboardingStep = "custom-report";
        this.detail?.setContent("Paste the custom report folder into the input, then press Enter.");
        this.setActions([{ label: "Default Reports", command: "report-app", description: defaultReportDir() }], async (action) => {
          await this.handleOnboardingAction(action.command);
        });
        break;
      case "model-none":
      case "model-local":
      case "model-cloud":
        this.onboardingDraft.modelMode = command === "model-none" ? "none" : command === "model-local" ? "local-provider" : "cloud-provider";
        this.state.modelMode = this.onboardingDraft.modelMode;
        this.onboardingStep = "scan";
        this.showOnboarding();
        break;
      case "scan-full":
      case "scan-changed":
      case "scan-dependency":
      case "scan-secrets":
        this.onboardingDraft.scanPreference = command === "scan-changed"
          ? "changed"
          : command === "scan-dependency"
            ? "dependency-only"
            : command === "scan-secrets"
              ? "secrets-only"
              : "full";
        await this.finishOnboarding();
        break;
      case "skip":
        this.onboardingStep = "done";
        this.showHome();
        break;
    }
  }

  private async finishOnboarding(): Promise<void> {
    const target = this.onboardingDraft.target ?? this.cwd;
    const workspace = this.createWorkspaceFromDraft(target);
    await this.addWorkspace(workspace);
    this.onboardingStep = "done";
    this.addHermsecMessage(`Workspace ${workspace.name} is ready. Use /scan, /doctor, /settings, /model, or /provider.`);
    this.showHome();
  }

  private createWorkspaceFromDraft(target: string): TuiWorkspace {
    const now = new Date().toISOString();
    const reportLocation = this.onboardingDraft.reportLocation ?? "app-data";
    const workspace: TuiWorkspace = {
      id: stableId(target, "workspace"),
      name: defaultWorkspaceName(target),
      target,
      sourceKind: isLikelyUrl(target) ? "github-url" : "local",
      reportLocation,
      privacyMode: this.onboardingDraft.privacyMode ?? this.state.privacyMode,
      modelMode: this.onboardingDraft.modelMode ?? this.state.modelMode,
      scanPreference: this.onboardingDraft.scanPreference ?? this.state.scanPreference,
      createdAt: now,
      lastUsedAt: now,
      scannerReadiness: this.state.lastDoctor?.summary ?? "not checked yet",
    };
    const reportDir = this.onboardingDraft.reportDir ?? defaultReportDir();
    if (reportDir) {
      workspace.reportDir = reportDir;
    }
    return workspace;
  }

  private showHome(): void {
    const workspace = activeWorkspace(this.state);
    this.detail?.setContent([
      "{cyan-fg}Hermsec workspace{/cyan-fg}",
      "",
      `Workspace: ${workspace?.name ?? "none"}`,
      `Target: ${workspace?.target ?? "add one with /workspace add <path>"}`,
      `Privacy: ${this.state.privacyMode}`,
      `Model: ${this.state.modelMode}`,
      `Reports: ${workspace?.reportDir ?? this.state.reportDir ?? defaultReportDir()}`,
      "",
      "Click buttons or paste a slash command below.",
    ].join("\n"));
    this.setActions(DEFAULT_ACTIONS);
    void this.refreshModelLine();
  }

  private showCommands(): void {
    this.detail?.setContent(formatHelp());
    this.setActions([
      { label: "Settings", command: "/settings", description: "Edit settings" },
      { label: "Model", command: "/model", description: "Choose model provider" },
      { label: "Provider", command: "/provider", description: "Set provider env" },
      { label: "History", command: "/history", description: "Current session history" },
      { label: "Sessions", command: "/sessions", description: "Saved sessions" },
      { label: "Onboard", command: "/onboard", description: "Run onboarding" },
    ]);
    this.addHermsecMessage("Commands are shown in the context panel.");
  }

  private async handleModelCommand(rest: string): Promise<void> {
    const requested = rest.trim().toLowerCase();
    if (requested.length === 0) {
      await this.showModelPicker();
      return;
    }

    if (!isPreferredModelProvider(requested)) {
      this.addHermsecMessage(`Unknown model provider: ${requested}.`);
      await this.showModelPicker();
      return;
    }

    await this.setPreferredProvider(requested);
    await this.showModelPicker();
  }

  private async handleSettingsCommand(rest: string): Promise<void> {
    const [subcommandToken, ...remaining] = rest.trim().split(/\s+/).filter(Boolean);
    const subcommand = subcommandToken?.toLowerCase() ?? "";

    if (subcommand === "report") {
      const value = remaining.join(" ").trim();
      if (!value) {
        this.addHermsecMessage("Use /settings report app-data, /settings report project-local, or /settings report <custom folder>.");
        await this.showSettings();
        return;
      }

      if (value === "app-data" || value === "project-local" || value === "ask") {
        await setConfigValue({ cwd: this.cwd, key: "defaultReportLocation", value });
        this.state.reportLocation = value;
        if (value === "app-data") {
          this.state.reportDir = defaultReportDir();
        }
      } else {
        await setConfigValue({ cwd: this.cwd, key: "customReportDir", value });
        const config = await loadUserConfig();
        this.state.reportLocation = "custom";
        this.state.reportDir = config.customReportDir;
      }
      this.addHermsecMessage("Report destination setting updated.");
      await this.showSettings();
      return;
    }

    await this.showSettings();
  }

  private async handleProviderCommand(rest: string): Promise<void> {
    const [subcommand, value] = rest.trim().split(/\s+/).filter(Boolean);
    const normalized = subcommand?.toLowerCase() ?? "";

    if (!normalized) {
      await this.showProviderPicker();
      return;
    }

    if (normalized === "env") {
      if (!value) {
        this.addHermsecMessage("Use /provider env YOUR_ENV_NAME. Hermsec will not store raw provider keys.");
        await this.showProviderPicker();
        return;
      }
      await this.setProviderCredentialEnv(value);
      await this.showProviderPicker();
      return;
    }

    if (isPreferredModelProvider(normalized)) {
      await this.setPreferredProvider(normalized);
      await this.showProviderPicker();
      return;
    }

    this.addHermsecMessage("Provider commands: /provider, /provider <provider>, or /provider env YOUR_ENV_NAME.");
    await this.showProviderPicker();
  }

  private async setPreferredProvider(provider: PreferredModelProvider): Promise<void> {
    await setConfigValue({ cwd: this.cwd, key: "preferredModelProvider", value: provider });
    if (PROVIDER_ENV[provider]) {
      await setConfigValue({ cwd: this.cwd, key: "providerCredentialEnv", value: PROVIDER_ENV[provider] });
    }
    this.addHermsecMessage(`Model provider set to ${provider}.${PROVIDER_ENV[provider] ? ` Credential env: ${PROVIDER_ENV[provider]}.` : ""}`);
    await this.refreshModelLine();
  }

  private async setProviderCredentialEnv(envName: string): Promise<void> {
    await setConfigValue({ cwd: this.cwd, key: "providerCredentialEnv", value: envName });
    this.addHermsecMessage(`Provider credential reference set to environment variable ${envName}. Raw keys remain outside Hermsec config.`);
    await this.refreshModelLine();
  }

  private async showSettings(): Promise<void> {
    const config = await loadUserConfig();
    this.detail?.setContent([
      "{cyan-fg}Settings{/cyan-fg}",
      "",
      `Privacy mode: ${config.privacyMode}`,
      `Report location: ${config.defaultReportLocation}`,
      `Report directory: ${config.customReportDir ?? defaultReportDir()}`,
      `Provider: ${config.preferredModelProvider ?? "none"}`,
      `Credential env: ${config.providerCredentialRef?.name ?? "not set"}`,
      "",
      "Use the buttons to change common settings. Provider keys stay in environment variables.",
    ].join("\n"));
    this.setActions([
      { label: "Local", command: "settings:privacy:local-only", description: "No cloud model calls" },
      { label: "Balanced", command: "settings:privacy:balanced", description: "Local plus online intel" },
      { label: "Cloud", command: "settings:privacy:cloud-assisted", description: "Allow cloud explanations" },
      { label: "Reports App", command: "settings:report:app-data", description: defaultReportDir() },
      { label: "Reports Project", command: "settings:report:project-local", description: ".hermsec/reports in workspace" },
      { label: "Reports Custom", command: "settings:report:custom", description: "Paste /settings report <folder>" },
      { label: "Model", command: "/model", description: "Choose model/provider" },
      { label: "Provider", command: "/provider", description: "Set provider env" },
    ], async (action) => {
      if (action.command.startsWith("settings:privacy:")) {
        const value = action.command.split(":").at(-1);
        if (value) {
          await setConfigValue({ cwd: this.cwd, key: "privacyMode", value });
          this.state.privacyMode = value as PrivacyMode;
          this.addHermsecMessage(`Privacy mode set to ${value}.`);
          await this.showSettings();
        }
        return;
      }
      if (action.command.startsWith("settings:report:")) {
        const value = action.command.split(":").at(-1);
        if (value === "custom") {
          this.addHermsecMessage("Paste /settings report <folder> into the input to set a custom local report folder.");
          return;
        }
        if (value) {
          await setConfigValue({ cwd: this.cwd, key: "defaultReportLocation", value });
          this.state.reportLocation = value as ReportLocation;
          if (value === "app-data") {
            this.state.reportDir = defaultReportDir();
          }
          this.addHermsecMessage(`Report location set to ${value}.`);
          await this.showSettings();
        }
        return;
      }
      await this.submit(action.command);
    });
  }

  private async showModelPicker(): Promise<void> {
    const config = await loadUserConfig();
    this.detail?.setContent([
      "{cyan-fg}Model picker{/cyan-fg}",
      "",
      `Current provider: ${config.preferredModelProvider ?? "none"}`,
      `Credential env: ${config.providerCredentialRef?.name ?? "not set"}`,
      "",
      "Click a provider. Use /provider to set the env var name.",
    ].join("\n"));
    this.setActions(modelProviders.map((provider) => ({
      label: provider,
      command: `model:${provider}`,
      description: PROVIDER_ENV[provider] || "No remote key required",
    })), async (action) => {
      const provider = action.command.replace(/^model:/, "") as PreferredModelProvider;
      await this.setPreferredProvider(provider);
      await this.showModelPicker();
    });
  }

  private async showProviderPicker(): Promise<void> {
    const config = await loadUserConfig();
    this.detail?.setContent([
      "{cyan-fg}Provider setup{/cyan-fg}",
      "",
      "Hermsec stores environment variable names, never raw API keys.",
      "",
      `Current provider: ${config.preferredModelProvider ?? "none"}`,
      `Credential env: ${config.providerCredentialRef?.name ?? "not set"}`,
      "",
      "Click a known provider, or paste: /provider env YOUR_ENV_NAME",
    ].join("\n"));
    this.setActions(modelProviders.filter((provider) => provider !== "none").map((provider) => ({
      label: provider,
      command: `provider:${provider}`,
      description: PROVIDER_ENV[provider],
    })), async (action) => {
      const provider = action.command.replace(/^provider:/, "") as PreferredModelProvider;
      await this.setPreferredProvider(provider);
      await this.showProviderPicker();
    });
  }

  private async runDoctor(): Promise<void> {
    this.addHermsecMessage("Running doctor checks...");
    if (!this.tools.doctor) {
      this.addHermsecMessage("Doctor tool is not connected.");
      return;
    }
    const result = await this.tools.doctor();
    if (!hasData(result)) {
      this.addHermsecMessage(result.ok ? "Doctor returned no data." : result.message);
      return;
    }
    this.state.lastDoctor = result.data;
    const active = activeWorkspace(this.state);
    if (active) {
      active.scannerReadiness = result.data.summary;
    }
    this.detail?.setContent(formatDoctor(result.data));
    this.addHermsecMessage(result.data.summary);
  }

  private async runScan(rawTarget: string): Promise<void> {
    const active = activeWorkspace(this.state);
    const target = rawTarget.trim() || active?.target;
    if (!target) {
      this.addHermsecMessage("No scan target. Add a workspace or paste /scan <path>.");
      return;
    }
    if (!isLikelyUrl(target) && !(await localPathExists(target))) {
      this.addHermsecMessage(`Scan target does not exist: ${target}`);
      return;
    }
    if (!this.tools.scan) {
      this.addHermsecMessage("Scan harness is not connected.");
      return;
    }

    const request: TuiScanRequest = {
      target: isLikelyUrl(target) ? target : normalizeTargetPath(target),
      mode: this.state.scanMode,
      preference: this.state.scanPreference,
    };
    if (active?.id) {
      request.workspaceId = active.id;
    }

    this.addHermsecMessage(`Scanning ${request.target}...`);
    const result = await this.tools.scan(request);
    if (!hasData(result)) {
      this.addHermsecMessage(result.ok ? "Scan completed without TUI data." : result.message);
      return;
    }
    this.state.lastScan = result.data;
    if (active) {
      active.lastScanAt = result.data.finishedAt ?? result.data.startedAt;
      active.lastFindingSummary = summarizeScan(result.data);
    }
    this.recordReportFromScan(result.data);
    const statusLines = result.data.scannerStatuses?.map((status) => `${formatStatus(status.status)} ${status.label}: ${status.message}`) ?? [];
    this.detail?.setContent([
      result.message,
      "",
      `Target: ${result.data.target}`,
      `Mode: ${result.data.mode}`,
      `Findings: ${summarizeScan(result.data)}`,
      result.data.reportPath ? `Report: ${result.data.reportPath}` : "Report: pending",
      "",
      ...statusLines,
    ].join("\n"));
    this.addHermsecMessage(result.message);
  }

  private async runIntel(): Promise<void> {
    if (!this.tools.updateIntel) {
      this.addHermsecMessage("Intel updater is not connected.");
      return;
    }
    this.addHermsecMessage("Refreshing trusted security updates...");
    const result = await this.tools.updateIntel(activeWorkspace(this.state));
    if (!hasData(result)) {
      this.addHermsecMessage(result.ok ? "Intel returned no data." : result.message);
      return;
    }
    this.detail?.setContent(formatIntel(result.data));
    this.addHermsecMessage(result.data.message);
  }

  private async runReports(): Promise<void> {
    const reports = await this.listReports(activeWorkspace(this.state));
    this.state.reports = reports;
    this.detail?.setContent(formatReports(reports));
    this.addHermsecMessage(`${reports.length} report(s) shown.`);
  }

  private async runWorkspace(rest: string): Promise<void> {
    const [subcommandToken, ...remaining] = rest.trim().split(/\s+/).filter(Boolean);
    const subcommand = subcommandToken?.toLowerCase() ?? "list";
    const argument = remaining.join(" ").trim();
    if (subcommand === "list") {
      this.detail?.setContent(formatWorkspaces(this.state.workspaces, this.state.activeWorkspaceId));
      return;
    }
    if (subcommand === "add") {
      const target = argument || this.cwd;
      if (!isLikelyUrl(target) && !(await localPathExists(target))) {
        this.addHermsecMessage(`Workspace path does not exist: ${target}`);
        return;
      }
      const workspace = this.workspaceFromTarget(target);
      await this.addWorkspace(workspace);
      this.addHermsecMessage(`Workspace added: ${workspace.name}`);
      this.showHome();
      return;
    }
    if (subcommand === "use") {
      const workspace = this.findWorkspace(argument);
      if (!workspace) {
        this.addHermsecMessage(`No workspace matched: ${argument}`);
        return;
      }
      await this.useWorkspace(workspace);
      this.addHermsecMessage(`Active workspace: ${workspace.name}`);
      this.showHome();
      return;
    }
    this.addHermsecMessage("Workspace commands: /workspace list, /workspace add <path>, /workspace use <name>.");
  }

  private async runSchedules(rest: string): Promise<void> {
    const subcommand = rest.trim().toLowerCase() || "list";
    if (subcommand !== "list") {
      this.addHermsecMessage("Schedule command available here: /schedule list.");
      return;
    }
    const schedules = await this.listSchedules(activeWorkspace(this.state));
    this.state.schedules = schedules;
    this.detail?.setContent(formatSchedules(schedules));
  }

  private showHistory(rest: string): void {
    const count = Number.parseInt(rest.trim(), 10);
    this.detail?.setContent(formatHistory(this.state.transcript, Number.isFinite(count) ? count : 20));
  }

  private async runSessions(rest: string): Promise<void> {
    const subcommand = rest.trim().toLowerCase() || "list";
    if (subcommand === "new") {
      await this.saveCurrentSession();
      this.state.activeSessionId = `ses-${crypto.randomUUID()}`;
      this.state.transcript = [{ role: "system", text: `TUI cwd: ${normalizedDisplayPath(this.cwd)}`, at: new Date().toISOString() }];
      this.addHermsecMessage("Started a new session.");
      this.detail?.setContent(`Started new session: ${this.state.activeSessionId}`);
      return;
    }
    if (subcommand === "current") {
      this.detail?.setContent([
        `Current session: ${this.state.activeSessionId}`,
        `Workspace: ${this.sessionWorkspaceId()}`,
        `Messages: ${this.state.transcript.length}`,
        `Latest scan: ${this.state.lastScan?.id ?? "none"}`,
      ].join("\n"));
      return;
    }
    const sessions = await this.listSessions(activeWorkspace(this.state));
    this.state.sessions = sessions;
    this.detail?.setContent(formatSessions(sessions, this.state.activeSessionId, this.state.transcript.length));
  }

  private async addWorkspace(workspace: TuiWorkspace): Promise<void> {
    let saved = workspace;
    if (this.tools.addWorkspace) {
      const result = await this.tools.addWorkspace(workspace);
      if (hasData(result)) {
        saved = result.data;
      }
    }
    const existing = this.state.workspaces.findIndex((item) => item.id === saved.id);
    if (existing >= 0) {
      this.state.workspaces[existing] = saved;
    } else {
      this.state.workspaces.push(saved);
    }
    await this.useWorkspace(saved);
  }

  private async useWorkspace(workspace: TuiWorkspace): Promise<void> {
    let selected = workspace;
    if (this.tools.useWorkspace) {
      const result = await this.tools.useWorkspace(workspace);
      if (hasData(result)) {
        selected = result.data;
      }
    }
    selected.lastUsedAt = new Date().toISOString();
    this.state.activeWorkspaceId = selected.id;
    this.state.privacyMode = selected.privacyMode;
    this.state.modelMode = selected.modelMode;
    this.state.scanPreference = selected.scanPreference;
    this.state.reportLocation = selected.reportLocation;
    this.state.reportDir = selected.reportDir;
  }

  private async listReports(workspace: TuiWorkspace | undefined): Promise<TuiReportSummary[]> {
    if (this.tools.listReports) {
      const result = await this.tools.listReports(workspace);
      if (hasData(result)) {
        return result.data;
      }
    }
    return [];
  }

  private async listSchedules(workspace: TuiWorkspace | undefined): Promise<TuiScheduleSummary[]> {
    if (this.tools.listSchedules) {
      const result = await this.tools.listSchedules(workspace);
      if (hasData(result)) {
        return result.data;
      }
    }
    return [];
  }

  private async listSessions(workspace: TuiWorkspace | undefined): Promise<TuiSessionSummary[]> {
    if (this.tools.listSessions) {
      const result = await this.tools.listSessions(workspace);
      if (hasData(result)) {
        return result.data;
      }
    }
    return this.state.sessions;
  }

  private async saveCurrentSession(): Promise<void> {
    if (!this.tools.saveSession || this.state.transcript.length === 0) {
      return;
    }
    const now = new Date().toISOString();
    const active = activeWorkspace(this.state);
    const snapshot: TuiSessionSnapshot = {
      id: this.state.activeSessionId,
      workspaceId: this.sessionWorkspaceId(),
      title: active ? `Hermsec session - ${active.name}` : "Hermsec session",
      createdAt: this.state.transcript[0]?.at ?? now,
      updatedAt: now,
      messages: this.state.transcript,
      discussedScanIds: this.state.lastScan ? [this.state.lastScan.id] : [],
      discussedFindingIds: [],
      compactSummary: this.state.lastScan ? summarizeScan(this.state.lastScan) : "TUI chat session",
    };
    const result = await this.tools.saveSession(snapshot);
    if (hasData(result)) {
      this.state.sessions = [result.data, ...this.state.sessions.filter((session) => session.id !== result.data.id)].slice(0, 20);
    }
  }

  private sessionWorkspaceId(): string {
    return activeWorkspace(this.state)?.id ?? "global";
  }

  private setActions(actions: RichAction[], handler?: (action: RichAction) => Promise<void> | void): void {
    this.actionButtons.forEach((button) => button.destroy());
    this.actionButtons = [];
    this.toolbar?.setContent("");
    this.sidebar?.setContent(actions.map((action, index) => `${index + 1}. ${action.label}\n   ${action.description}`).join("\n\n"));

    actions.slice(0, 12).forEach((action, index) => {
      const button = blessed.button({
        parent: this.toolbar as never,
        mouse: true,
        keys: true,
        shrink: true,
        top: Math.floor(index / 4) * 2,
        left: 2 + (index % 4) * 19,
        height: 1,
        width: 17,
        align: "center",
        tags: true,
        content: action.label,
        style: {
          fg: "black",
          bg: "cyan",
          focus: { bg: "yellow", fg: "black" },
          hover: { bg: "yellow", fg: "black" },
        },
      }) as BlessedNode;
      button.on("press", () => {
        void (handler ? handler(action) : this.submit(action.command));
      });
      this.actionButtons.push(button);
    });
    this.inputBox?.focus?.();
    this.render();
  }

  private async refreshModelLine(): Promise<void> {
    const config = await loadUserConfig();
    this.modelLine?.setContent([
      `{gray-fg}model{/gray-fg}    {bold}${escapeTag(config.preferredModelProvider ?? "none")}{/bold}`,
      `{gray-fg}provider{/gray-fg} ${escapeTag(config.preferredModelProvider ?? "none")}`,
      `{gray-fg}key env{/gray-fg}  ${escapeTag(config.providerCredentialRef?.name ?? "not set")}`,
      "",
      "{gray-fg}/help for commands{/gray-fg}",
    ].join("\n"));
  }

  private addHermsecMessage(text: string): void {
    this.addMessage("hermsec", text);
    this.chat?.log?.(`{cyan-fg}Hermsec>{/cyan-fg} ${escapeTag(redactSecrets(text))}`);
  }

  private addMessage(role: ChatMessage["role"], text: string): void {
    this.state.transcript.push({
      role,
      text: redactSecrets(text),
      at: new Date().toISOString(),
    });
    if (this.state.transcript.length > 100) {
      this.state.transcript = this.state.transcript.slice(-100);
    }
  }

  private recordReportFromScan(scan: TuiScanResult): void {
    if (!scan.reportPath) {
      return;
    }
    const report: TuiReportSummary = {
      title: `Scan ${scan.id}`,
      path: scan.reportPath,
      createdAt: scan.finishedAt ?? scan.startedAt,
      summary: summarizeScan(scan),
    };
    this.state.reports = [report, ...this.state.reports.filter((item) => item.path !== report.path)].slice(0, 12);
  }

  private workspaceFromTarget(targetInput: string): TuiWorkspace {
    const target = isLikelyUrl(targetInput) ? targetInput.trim() : normalizeTargetPath(targetInput);
    const now = new Date().toISOString();
    return {
      id: stableId(target, "workspace"),
      name: defaultWorkspaceName(target),
      target,
      sourceKind: isLikelyUrl(target) ? "github-url" : "local",
      reportLocation: "app-data",
      privacyMode: this.state.privacyMode,
      modelMode: this.state.modelMode,
      scanPreference: this.state.scanPreference,
      createdAt: now,
      lastUsedAt: now,
      reportDir: defaultReportDir(),
      scannerReadiness: this.state.lastDoctor?.summary ?? "unknown",
    };
  }

  private findWorkspace(selector: string): TuiWorkspace | undefined {
    const numeric = Number.parseInt(selector, 10);
    if (Number.isInteger(numeric) && numeric > 0) {
      return this.state.workspaces[numeric - 1];
    }
    const normalized = selector.toLowerCase();
    return this.state.workspaces.find(
      (workspace) =>
        workspace.id.toLowerCase() === normalized ||
        workspace.name.toLowerCase() === normalized ||
        workspace.target.toLowerCase() === normalized,
    );
  }

  private async exit(reason: TuiRunSummary["exitReason"]): Promise<void> {
    this.addHermsecMessage("Goodbye. Reports and sessions stay local.");
    await this.saveCurrentSession();
    this.screen?.destroy();
    this.exitResolver?.({ exitReason: reason, state: this.state });
  }

  private render(): void {
    this.footer?.setContent(`Workspace: ${activeWorkspace(this.state)?.name ?? "none"} | Privacy: ${this.state.privacyMode} | Session: ${this.state.activeSessionId} | Paste supported in input | Ctrl+C exits`);
    this.screen?.render();
  }

  private isInteractive(): boolean {
    return this.forceInteractive ?? Boolean(this.input.isTTY && this.output.isTTY);
  }
}

function onboardingInstruction(step: OnboardingStep): string {
  switch (step) {
    case "workspace":
      return "Paste a workspace path/GitHub URL, or click Use current folder.";
    case "privacy":
      return "Choose the default privacy boundary.";
    case "report":
      return "Choose where reports should be written.";
    case "custom-report":
      return "Paste a custom report directory into the input.";
    case "model":
      return "Choose model behavior for explanations.";
    case "scan":
      return "Choose the default scan preference.";
    case "done":
      return "Onboarding is complete.";
  }
}

function onboardingActions(step: OnboardingStep, cwd: string): RichAction[] {
  switch (step) {
    case "workspace":
      return [
        { label: "Use current", command: "use-current", description: normalizedDisplayPath(cwd) },
        { label: "Skip", command: "skip", description: "Start without saving workspace" },
      ];
    case "privacy":
      return [
        { label: "Local only", command: "privacy-local", description: "No cloud model calls" },
        { label: "Balanced", command: "privacy-balanced", description: "Local scan plus online intel" },
        { label: "Cloud assisted", command: "privacy-cloud", description: "Allow cloud explanations after provider setup" },
      ];
    case "report":
      return [
        { label: "Default app", command: "report-app", description: defaultReportDir() },
        { label: "Project local", command: "report-project", description: ".hermsec/reports in workspace" },
        { label: "Custom", command: "report-custom", description: "Paste custom path" },
      ];
    case "model":
      return [
        { label: "No model", command: "model-none", description: "Scanner-only explanations" },
        { label: "Local", command: "model-local", description: "Ollama/local endpoint later" },
        { label: "Cloud", command: "model-cloud", description: "Provider env var required" },
      ];
    case "scan":
      return [
        { label: "Full", command: "scan-full", description: "Full approved scan" },
        { label: "Changed", command: "scan-changed", description: "Git-aware changed files" },
        { label: "Dependency", command: "scan-dependency", description: "Packages and lockfiles" },
        { label: "Secrets", command: "scan-secrets", description: "Secret-focused checks" },
      ];
    default:
      return DEFAULT_ACTIONS;
  }
}

async function localPathExists(target: string): Promise<boolean> {
  try {
    const stats = await fs.stat(normalizeTargetPath(target));
    return stats.isDirectory() || stats.isFile();
  } catch {
    return false;
  }
}

function formatIntel(summary: TuiIntelSummary): string {
  return [
    `{cyan-fg}${formatStatus(summary.status)}{/cyan-fg} ${summary.message}`,
    "",
    ...summary.items.map((item, index) => `${index + 1}. ${item}`),
  ].join("\n");
}

function summarizeScan(scan: TuiScanResult): string {
  if (!scan.summary) {
    return scan.message ?? scan.status;
  }
  return `CRITICAL ${scan.summary.critical}, HIGH ${scan.summary.high}, MEDIUM ${scan.summary.medium}, LOW ${scan.summary.low}, INFO ${scan.summary.info}`;
}

function extractNaturalTarget(input: string): string {
  const match = /\bscan\s+(.+)$/i.exec(input);
  return match?.[1]?.trim() ?? "";
}

function escapeTag(value: string): string {
  return blessed.escape(value);
}

function isPreferredModelProvider(value: string): value is PreferredModelProvider {
  return modelProviders.some((provider) => provider === value);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function nonInteractiveMessage(): string {
  return [
    "Hermsec TUI detected a non-interactive terminal, so it will not start a prompt.",
    "Use a TTY for the rich chatbot UI, or call scriptable commands such as:",
    "- hermsec doctor",
    "- hermsec scan <path>",
    "- hermsec chat",
    "No scanner, package manager, shell, or install command was run.",
    "",
  ].join("\n");
}

function hasData<T>(result: CommandResult<T>): result is Extract<CommandResult<T>, { ok: true }> & { data: T } {
  return result.ok && result.data !== undefined;
}
