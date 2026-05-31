import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { createInterface } from "node:readline/promises";
import type { Dirent } from "node:fs";
import type { Interface } from "node:readline/promises";

import { defaultReportDir, normalizeTargetPath } from "../shared/paths.js";
import { redactSecrets, stableId } from "../shared/text.js";
import type { CommandResult } from "../shared/types.js";
import {
  activeWorkspace,
  defaultWorkspaceName,
  formatDoctor,
  formatHelp,
  formatReports,
  formatSchedules,
  formatStatus,
  formatStatusRail,
  formatWorkspaces,
  isLikelyUrl,
  normalizedDisplayPath,
  renderFrame,
  scanPreferenceLabel,
} from "./format.js";
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
  TuiState,
  TuiToolbox,
  TuiWorkspace,
} from "./types.js";

type CommandOutcome = {
  shouldExit: boolean;
};

type Choice<TValue extends string> = {
  value: TValue;
  label: string;
  description: string;
};

const HELP_HINT = "Try /help, /doctor, /scan <path>, /reports, /workspace list, /intel, /schedule list, or /exit.";

const UNSAFE_INTENT =
  /\b(npm\s+install|pnpm\s+install|yarn\s+install|bun\s+install|npx|pnpm\s+dlx|bunx|curl\s+.+\|\s*(?:sh|bash)|wget\s+.+\|\s*(?:sh|bash)|edit\s+(?:my\s+)?(?:code|file|source)|modify\s+(?:my\s+)?(?:code|file|source)|write\s+(?:code|file)|delete\s+(?:files?|source)|rm\s+-rf|run\s+(?:a\s+)?shell|execute\s+(?:this\s+)?command|powershell|cmd\.exe)\b/i;

export class HermsecTui {
  private readonly cwd: string;
  private readonly input: NodeJS.ReadableStream & { isTTY?: boolean };
  private readonly output: NodeJS.WritableStream & { columns?: number; isTTY?: boolean };
  private readonly tools: TuiToolbox;
  private readonly forceInteractive: boolean | undefined;
  private readonly skipOnboarding: boolean;
  private readonly readline: Interface;
  private state: TuiState;

  constructor(options: TuiRunOptions = {}) {
    this.cwd = options.cwd ?? process.cwd();
    this.input = options.input ?? process.stdin;
    this.output = options.output ?? process.stdout;
    this.tools = options.tools ?? {};
    this.forceInteractive = options.forceInteractive;
    this.skipOnboarding = options.skipOnboarding ?? false;
    this.state = createDefaultState(this.cwd, options.initialState);
    this.readline = createInterface({
      input: this.input,
      output: this.output,
      terminal: this.isInteractive(),
    });
  }

  async run(): Promise<TuiRunSummary> {
    try {
      if (!this.isInteractive()) {
        this.write(nonInteractiveMessage());
        return { exitReason: "non-interactive", state: this.state };
      }

      await this.loadExternalState();
      this.addHermsecMessage(
        "Hermsec protects local projects by running scanners, explaining evidence, and saving reports on your machine.",
      );

      if (!this.skipOnboarding && this.state.workspaces.length === 0) {
        await this.runOnboarding();
      }

      this.render();

      while (true) {
        const raw = await this.readline.question("you> ");
        const input = raw.trim();

        if (input.length === 0) {
          continue;
        }

        this.addMessage("user", redactSecrets(input));
        const outcome = await this.handleInput(input);

        if (outcome.shouldExit) {
          this.addHermsecMessage("Goodbye. Reports stay local.");
          this.write("Hermsec> Goodbye. Reports stay local.\n");
          return { exitReason: "user-exit", state: this.state };
        }
      }
    } catch (error) {
      if (isInputClosed(error)) {
        return { exitReason: "input-closed", state: this.state };
      }

      throw error;
    } finally {
      this.readline.close();
    }
  }

  async handleInput(input: string): Promise<CommandOutcome> {
    const trimmed = input.trim();
    if (trimmed === "?") {
      return this.respond(formatHelp());
    }

    if (trimmed.startsWith("/")) {
      return this.handleSlashCommand(trimmed);
    }

    return this.handleNaturalLanguage(trimmed);
  }

  private async loadExternalState(): Promise<void> {
    if (!this.tools.loadState) {
      return;
    }

    const external = await this.tools.loadState();
    this.state = createDefaultState(this.cwd, { ...this.state, ...external });
  }

  private async runOnboarding(): Promise<void> {
    this.write("\nHermsec> Welcome. Hermsec scans repositories, explains evidence, and writes local reports.\n");
    this.write("Hermsec> First, I will set up a workspace profile without asking for secrets.\n\n");

    const workspaceTarget = await this.ask(
      "Workspace path or GitHub URL",
      normalizedDisplayPath(this.cwd),
    );

    const privacyMode = await this.choose<PrivacyMode>("Privacy mode", [
      {
        value: "local-only",
        label: "Local only",
        description: "Local scanners and local reports. No cloud model calls.",
      },
      {
        value: "balanced",
        label: "Balanced",
        description: "Local scanners plus online enrichment when allowed.",
      },
      {
        value: "cloud-assisted",
        label: "Cloud assisted",
        description: "Cloud explanations require explicit provider consent.",
      },
    ]);

    this.state.privacyMode = privacyMode;

    const reportLocation = await this.choose<ReportLocation>(
      "Where should Hermsec save reports for this workspace?",
      [
        {
          value: "app-data",
          label: "Default app folder",
          description: defaultReportDir(),
        },
        {
          value: "project-local",
          label: "Inside this workspace",
          description: ".hermsec/reports, only after confirmation by storage/report tooling.",
        },
        {
          value: "custom",
          label: "Custom local folder",
          description: "Use a folder you control.",
        },
        {
          value: "ask",
          label: "Ask every scan",
          description: "Choose per scan.",
        },
      ],
    );

    this.state.reportLocation = reportLocation;
    this.state.reportDir = await this.resolveReportDir(reportLocation, workspaceTarget);

    this.write("\nHermsec> I will check readiness through the doctor tool now.\n");
    const doctor = await this.runDoctor();
    this.write(`Hermsec> ${doctor.summary}\n\n`);

    const modelMode = await this.choose<ModelMode>("Model mode", [
      {
        value: "none",
        label: "No model",
        description: "Scanner-only explanations.",
      },
      {
        value: "local-provider",
        label: "Local provider",
        description: "Use Ollama or another local endpoint later.",
      },
      {
        value: "cloud-provider",
        label: "Cloud provider",
        description: "Requires explicit consent and environment-based credentials later.",
      },
    ]);

    this.state.modelMode = await this.confirmCloudModel(modelMode);

    const scanPreference = await this.choose<ScanPreference>("Default scan preference", [
      {
        value: "full",
        label: "Full scan",
        description: "Run the approved scanner plan.",
      },
      {
        value: "changed",
        label: "Changed files",
        description: "Prefer git-aware changed-file scans.",
      },
      {
        value: "dependency-only",
        label: "Dependency-only",
        description: "Focus on lockfiles and dependency advisories.",
      },
      {
        value: "secrets-only",
        label: "Secrets-only",
        description: "Focus on secret scanning.",
      },
    ]);

    this.state.scanPreference = scanPreference;

    const workspace = await this.createWorkspace(workspaceTarget, reportLocation, this.state.reportDir);
    this.write("\nHermsec> Review:\n");
    this.write(`- Workspace: ${workspace.target}\n`);
    this.write(`- Privacy: ${workspace.privacyMode}\n`);
    this.write(`- Model: ${workspace.modelMode}\n`);
    this.write(`- Reports: ${workspace.reportDir ?? reportLocation}\n`);
    this.write(`- Scan preference: ${scanPreferenceLabel(workspace.scanPreference)}\n`);
    this.write("- Secrets: no keys or tokens were requested.\n");

    const save = await this.ask("Save this workspace profile for the TUI session?", "yes");
    if (isYes(save)) {
      await this.addWorkspace(workspace);
      this.addHermsecMessage(`Workspace ${workspace.name} is ready. Next useful action: /scan`);
      this.write(`Hermsec> Workspace ${workspace.name} is ready. Next useful action: /scan\n\n`);
      return;
    }

    this.addHermsecMessage("Onboarding skipped saving. You can add a workspace with /workspace add <path>.");
    this.write("Hermsec> Onboarding skipped saving. You can add a workspace with /workspace add <path>.\n\n");
  }

  private async handleSlashCommand(input: string): Promise<CommandOutcome> {
    const [commandToken, ...restParts] = input.split(/\s+/);
    const command = commandToken?.toLowerCase() ?? "";
    const rest = input.slice(commandToken?.length ?? 0).trim();

    switch (command) {
      case "/help":
        return this.respond(formatHelp());
      case "/doctor":
        return this.doctorCommand();
      case "/scan":
        return this.scanCommand(rest);
      case "/reports":
        return this.reportsCommand();
      case "/workspace":
        return this.workspaceCommand(rest);
      case "/intel":
        return this.intelCommand();
      case "/schedule":
        return this.scheduleCommand(restParts.join(" "));
      case "/report-path":
        return this.reportPathCommand(rest);
      case "/privacy":
        return this.privacyCommand(rest);
      case "/onboard":
        await this.runOnboarding();
        this.render();
        return { shouldExit: false };
      case "/exit":
      case "/quit":
        return { shouldExit: true };
      default:
        return this.respond(`Unknown command: ${command || input}\n${HELP_HINT}`);
    }
  }

  private async handleNaturalLanguage(input: string): Promise<CommandOutcome> {
    if (UNSAFE_INTENT.test(input)) {
      return this.respond(
        [
          "I cannot do that from Hermsec's TUI.",
          "What happened: that sounds like package installation, arbitrary shell execution, source editing, or destructive file work.",
          "What Hermsec did instead: no command was run and no file was changed.",
          `What you can do next: ${HELP_HINT}`,
        ].join("\n"),
      );
    }

    const normalized = input.toLowerCase();

    if (/\b(exit|quit|goodbye)\b/.test(normalized)) {
      return { shouldExit: true };
    }

    if (/\b(help|what can you do|commands)\b/.test(normalized)) {
      return this.respond(formatHelp());
    }

    if (/\b(doctor|check readiness|scanner readiness|tools ready)\b/.test(normalized)) {
      return this.doctorCommand();
    }

    if (/\b(show|open|list)\b.*\breports?\b|\blatest report\b/.test(normalized)) {
      return this.reportsCommand();
    }

    if (/\b(schedule|scheduled scans?)\b/.test(normalized)) {
      return this.scheduleCommand("list");
    }

    if (/\b(intel|security news|vulnerability news|advisory feed|feed)\b/.test(normalized)) {
      return this.intelCommand();
    }

    const reportPath = extractReportPath(input);
    if (reportPath) {
      return this.reportPathCommand(reportPath);
    }

    if (/\b(workspaces?|projects?)\b.*\b(list|show)\b/.test(normalized)) {
      return this.workspaceCommand("list");
    }

    if (/\b(add|use)\b.*\b(workspace|project)\b/.test(normalized)) {
      return this.respond("I can do that safely. Use /workspace add <path> or /workspace use <name> so I do not guess the wrong target.");
    }

    if (/\bscan\b|\bcheck\b.*\bfolder\b|\bcheck\b.*\bchanged\b/.test(normalized)) {
      if (/\bchanged\b/.test(normalized)) {
        return this.scanCommand("changed");
      }

      if (/\bthis folder\b|\bcurrent folder\b|\bthis repo\b|\bcurrent repo\b/.test(normalized)) {
        return this.scanCommand(normalized.includes("changed") ? "changed" : "");
      }

      return this.respond("I can scan through the approved Hermsec harness. Use /scan <path>, or add a workspace with /workspace add <path>.");
    }

    if (/\bwhy\b.*\b(high|critical|risk|finding)\b|\bexplain\b.*\bfinding/.test(normalized)) {
      return this.respond(
        "I can explain findings after scanner evidence exists. Run /scan first, then use /reports to locate the grounded report output.",
      );
    }

    return this.respond(
      [
        "I am not sure which safe Hermsec action you want.",
        "I can route scanner, report, workspace, schedule, doctor, and security-intel requests.",
        HELP_HINT,
      ].join("\n"),
    );
  }

  private async doctorCommand(): Promise<CommandOutcome> {
    const report = await this.runDoctor();
    const active = activeWorkspace(this.state);

    if (active) {
      active.scannerReadiness = report.summary;
    }

    return this.respond(formatDoctor(report));
  }

  private async scanCommand(rawTarget: string): Promise<CommandOutcome> {
    const active = activeWorkspace(this.state);
    const changedOnly = rawTarget.trim().toLowerCase() === "changed";
    const target = changedOnly ? active?.target : rawTarget.trim() || active?.target;

    if (!target) {
      return this.respond(
        "No workspace is active yet. What happened: Hermsec has no scan target. What Hermsec did instead: no scan was started. What you can do next: /workspace add <path> or /scan <path>.",
      );
    }

    if (!isLikelyUrl(target) && !(await localPathExists(target))) {
      return this.respond(
        `The scan target does not exist: ${target}\nWhat Hermsec did instead: no scan was started.\nWhat you can do next: check the path or add the workspace with /workspace add <path>.`,
      );
    }

    const preference: ScanPreference = changedOnly ? "changed" : this.state.scanPreference;
    const request: TuiScanRequest = {
      target: isLikelyUrl(target) ? target : normalizeTargetPath(target),
      mode: this.state.scanMode,
      preference,
    };

    if (active?.id) {
      request.workspaceId = active.id;
    }

    const result = await this.runScan(request);

    if (!hasData(result)) {
      const message = result.ok ? "The scan harness reported success but did not return scan data." : result.message;
      const remediation = result.ok
        ? "Update the scan adapter to return a TuiScanResult payload."
        : result.remediation ?? "Run /doctor, then try /scan <path> after the scan harness is available.";
      return this.respond(
        [
          `What happened: ${message}`,
          "What Hermsec did instead: no generic shell command was run and no package install was attempted.",
          `What you can do next: ${remediation}`,
        ].join("\n"),
      );
    }

    this.state.lastScan = result.data;
    this.recordReportFromScan(result.data);

    if (active) {
      active.lastScanAt = result.data.finishedAt ?? result.data.startedAt;
      active.lastFindingSummary = summarizeScan(result.data);
    }

    const statusLines = result.data.scannerStatuses?.map(
      (status) => `- ${formatStatus(status.status)} ${status.label}: ${status.message}`,
    );

    return this.respond(
      [
        result.message,
        `Target: ${result.data.target}`,
        `Mode: ${result.data.mode}, preference: ${scanPreferenceLabel(result.data.preference)}`,
        result.data.reportPath ? `Report: ${result.data.reportPath}` : "Report: pending local report renderer",
        statusLines && statusLines.length > 0 ? statusLines.join("\n") : "",
      ]
        .filter(Boolean)
        .join("\n"),
    );
  }

  private async reportsCommand(): Promise<CommandOutcome> {
    const workspace = activeWorkspace(this.state);
    const reports = await this.listReports(workspace);
    this.state.reports = reports;
    return this.respond(formatReports(reports));
  }

  private async workspaceCommand(rest: string): Promise<CommandOutcome> {
    const [subcommandToken, ...remaining] = rest.trim().split(/\s+/).filter(Boolean);
    const subcommand = subcommandToken?.toLowerCase() ?? "list";
    const argument = remaining.join(" ").trim();

    if (subcommand === "list") {
      return this.respond(formatWorkspaces(this.state.workspaces, this.state.activeWorkspaceId));
    }

    if (subcommand === "add") {
      const target = argument || (await this.ask("Workspace path or GitHub URL", normalizedDisplayPath(this.cwd)));

      if (!isLikelyUrl(target) && !(await localPathExists(target))) {
        return this.respond(
          `The workspace path does not exist: ${target}\nWhat Hermsec did instead: it did not create or modify that folder.\nWhat you can do next: provide an existing local path or a GitHub URL.`,
        );
      }

      const workspace = await this.createWorkspace(target, this.state.reportLocation);
      await this.addWorkspace(workspace);
      return this.respond(`Workspace added and selected: ${workspace.name}\n${workspace.target}`);
    }

    if (subcommand === "use") {
      if (argument.length === 0) {
        return this.respond(`${formatWorkspaces(this.state.workspaces, this.state.activeWorkspaceId)}\nUse /workspace use <number|name|id>.`);
      }

      const workspace = this.findWorkspace(argument);
      if (!workspace) {
        return this.respond(`No workspace matched "${argument}".\n${formatWorkspaces(this.state.workspaces, this.state.activeWorkspaceId)}`);
      }

      await this.useWorkspace(workspace);
      return this.respond(`Active workspace: ${workspace.name}\n${workspace.target}`);
    }

    return this.respond("Workspace commands: /workspace list, /workspace add <path>, /workspace use <name>.");
  }

  private async intelCommand(): Promise<CommandOutcome> {
    const workspace = activeWorkspace(this.state);

    if (this.tools.updateIntel) {
      const result = await this.tools.updateIntel(workspace);
      if (!result.ok) {
        return this.respond(
          `What happened: ${result.message}\nWhat Hermsec did instead: no free-form web browsing was started.\nWhat you can do next: ${result.remediation ?? "Try again when trusted intel sources are configured."}`,
        );
      }

      if (!hasData(result)) {
        return this.respond(
          "What happened: the intel tool reported success but did not return feed data.\nWhat Hermsec did instead: no model summary was invented.\nWhat you can do next: check the intel adapter contract.",
        );
      }

      return this.respond(formatIntel(result.data));
    }

    const fallback: TuiIntelSummary = {
      status: "skipped",
      message: "The trusted security-intel fetcher is not connected to the TUI yet.",
      items: [
        "Hermsec will summarize normalized OSV, GHSA, NVD, CISA KEV, EPSS, and RSS data when the intel tool is available.",
        "The TUI will not let a model freely browse the web or invent advisory IDs.",
      ],
    };

    return this.respond(formatIntel(fallback));
  }

  private async scheduleCommand(rest: string): Promise<CommandOutcome> {
    const subcommand = rest.trim().toLowerCase() || "list";

    if (subcommand !== "list") {
      return this.respond("Schedule command available in this TUI build: /schedule list");
    }

    const workspace = activeWorkspace(this.state);
    const schedules = await this.listSchedules(workspace);
    this.state.schedules = schedules;
    return this.respond(formatSchedules(schedules));
  }

  private async reportPathCommand(rest: string): Promise<CommandOutcome> {
    const value = rest.trim() || (await this.ask("Report directory", this.state.reportDir ?? defaultReportDir()));
    const resolvedReportDir = normalizeTargetPath(value);
    this.state.reportLocation = "custom";
    this.state.reportDir = resolvedReportDir;

    const workspace = activeWorkspace(this.state);
    if (workspace) {
      workspace.reportLocation = "custom";
      workspace.reportDir = resolvedReportDir;
    }

    return this.respond(
      `Report destination updated for this TUI session: ${this.state.reportDir}\nHermsec stores reports locally and does not put secrets in report paths.`,
    );
  }

  private async privacyCommand(rest: string): Promise<CommandOutcome> {
    const normalized = rest.trim().toLowerCase();
    let mode: PrivacyMode | undefined;

    if (normalized === "local" || normalized === "local-only") {
      mode = "local-only";
    } else if (normalized === "balanced") {
      mode = "balanced";
    } else if (normalized === "cloud" || normalized === "cloud-assisted") {
      const confirmed = await this.ask("Cloud assisted mode can enable cloud model explanations later. Continue?", "no");
      mode = isYes(confirmed) ? "cloud-assisted" : "local-only";
    }

    if (!mode) {
      return this.respond("Privacy modes: /privacy local-only, /privacy balanced, /privacy cloud-assisted");
    }

    this.state.privacyMode = mode;
    const workspace = activeWorkspace(this.state);
    if (workspace) {
      workspace.privacyMode = mode;
    }

    return this.respond(`Privacy mode set to ${mode}. Cloud model calls still require explicit provider setup and consent.`);
  }

  private async runDoctor(): Promise<TuiDoctorReport> {
    if (this.tools.doctor) {
      const result = await this.tools.doctor();
      if (hasData(result)) {
        this.state.lastDoctor = result.data;
        return result.data;
      }

      const report: TuiDoctorReport = {
        summary: result.ok ? "Doctor tool returned no data" : "Doctor tool failed",
        checks: [
          {
            label: "Hermsec doctor",
            status: result.ok ? "skipped" : "failed",
            message: result.ok
              ? "The doctor adapter reported success without a readiness payload."
              : `${result.message}${result.remediation ? ` ${result.remediation}` : ""}`,
          },
        ],
      };
      this.state.lastDoctor = report;
      return report;
    }

    const major = Number.parseInt(process.versions.node.split(".")[0] ?? "0", 10);
    const reportDir = activeWorkspace(this.state)?.reportDir ?? this.state.reportDir ?? defaultReportDir();
    const checks: TuiDoctorReport["checks"] = [
      {
        label: "Node.js",
        status: major >= 22 ? "ready" : "missing",
        message: `Detected ${process.versions.node}; Hermsec targets Node.js 22 or newer.`,
      },
      {
        label: "Terminal",
        status: this.isInteractive() ? "ready" : "missing",
        message: this.isInteractive() ? "Interactive terminal detected." : "Non-interactive mode will not prompt.",
      },
      {
        label: "Report destination",
        status: "skipped",
        message: `Configured local report path: ${reportDir}. Writability is verified by the report/storage tool when connected.`,
      },
      {
        label: "Scanner harness",
        status: "skipped",
        message: "No scanner harness adapter is connected to this TUI session yet.",
      },
      {
        label: "Privacy boundary",
        status: "ready",
        message: "The TUI exposes only restricted Hermsec actions and no arbitrary shell or install tools.",
      },
    ];

    const readyCount = checks.filter((check) => check.status === "ready").length;
    const report: TuiDoctorReport = {
      summary: `${readyCount}/${checks.length} readiness checks ready; missing tools are reported without auto-installing anything.`,
      checks,
    };
    this.state.lastDoctor = report;
    return report;
  }

  private async runScan(request: TuiScanRequest): Promise<CommandResult<TuiScanResult>> {
    if (!this.tools.scan) {
      return {
        ok: false,
        errorCode: "scan_harness_unavailable",
        message: "The scan harness is not connected to the TUI yet.",
        remediation: "Wire the CLI/core scan adapter into runTui({ tools: { scan } }) so /scan uses the same approved harness as the CLI.",
      };
    }

    return this.tools.scan(request);
  }

  private async listReports(workspace: TuiWorkspace | undefined): Promise<TuiReportSummary[]> {
    if (this.tools.listReports) {
      const result = await this.tools.listReports(workspace);
      if (hasData(result)) {
        return result.data;
      }
    }

    const roots = uniqueStrings([
      workspace?.reportDir,
      this.state.reportDir,
      defaultReportDir(),
    ]);
    const reports: TuiReportSummary[] = [];

    for (const root of roots) {
      reports.push(...(await findReports(root)));
      if (reports.length >= 12) {
        break;
      }
    }

    return reports.slice(0, 12);
  }

  private async listSchedules(workspace: TuiWorkspace | undefined): Promise<TuiScheduleSummary[]> {
    if (this.tools.listSchedules) {
      const result = await this.tools.listSchedules(workspace);
      if (hasData(result)) {
        return result.data;
      }
    }

    if (!workspace) {
      return this.state.schedules;
    }

    return this.state.schedules.filter((schedule) => schedule.target === workspace.target);
  }

  private async createWorkspace(
    targetInput: string,
    reportLocation: ReportLocation,
    reportDirOverride?: string,
  ): Promise<TuiWorkspace> {
    const target = isLikelyUrl(targetInput) ? targetInput.trim() : normalizeTargetPath(targetInput);
    const now = new Date().toISOString();
    const reportDir = reportDirOverride ?? (await this.resolveReportDir(reportLocation, target));
    const workspace: TuiWorkspace = {
      id: stableId(target, "workspace"),
      name: defaultWorkspaceName(target),
      target,
      sourceKind: isLikelyUrl(target) ? "github-url" : "local",
      reportLocation,
      privacyMode: this.state.privacyMode,
      modelMode: this.state.modelMode,
      scanPreference: this.state.scanPreference,
      createdAt: now,
      lastUsedAt: now,
      scannerReadiness: this.state.lastDoctor?.summary ?? "unknown",
    };

    if (reportDir) {
      workspace.reportDir = reportDir;
    }

    return workspace;
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

    const index = this.state.workspaces.findIndex((item) => item.id === selected.id);
    if (index >= 0) {
      this.state.workspaces[index] = selected;
    }
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

  private async resolveReportDir(location: ReportLocation, workspaceTarget: string): Promise<string | undefined> {
    switch (location) {
      case "app-data":
        return defaultReportDir();
      case "project-local":
        return isLikelyUrl(workspaceTarget) ? defaultReportDir() : path.join(normalizeTargetPath(workspaceTarget), ".hermsec", "reports");
      case "custom": {
        const custom = await this.ask("Custom report folder", this.state.reportDir ?? defaultReportDir());
        return normalizeTargetPath(custom);
      }
      case "ask":
        return undefined;
    }
  }

  private async confirmCloudModel(mode: ModelMode): Promise<ModelMode> {
    if (mode !== "cloud-provider") {
      return mode;
    }

    const answer = await this.ask("Cloud providers can receive redacted evidence only after explicit consent. Use cloud provider mode?", "no");
    return isYes(answer) ? "cloud-provider" : "none";
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

  private async ask(question: string, defaultValue?: string): Promise<string> {
    const suffix = defaultValue ? ` [${defaultValue}]` : "";
    const answer = await this.readline.question(`${question}${suffix}: `);
    const trimmed = answer.trim();
    return trimmed.length > 0 ? trimmed : defaultValue ?? "";
  }

  private async choose<TValue extends string>(question: string, choices: Choice<TValue>[]): Promise<TValue> {
    this.write(`${question}\n`);
    choices.forEach((choice, index) => {
      this.write(`${index + 1}. ${choice.label} - ${choice.description}\n`);
    });

    while (true) {
      const answer = await this.ask("Choose", "1");
      const byIndex = Number.parseInt(answer, 10);
      if (Number.isInteger(byIndex) && byIndex >= 1 && byIndex <= choices.length) {
        const choice = choices[byIndex - 1];
        if (choice) {
          return choice.value;
        }
      }

      const normalized = answer.toLowerCase();
      const choice = choices.find(
        (item) => item.value.toLowerCase() === normalized || item.label.toLowerCase() === normalized,
      );
      if (choice) {
        return choice.value;
      }

      this.write("Hermsec> Please choose one of the listed options.\n");
    }
  }

  private respond(text: string): CommandOutcome {
    const redacted = redactSecrets(text);
    this.addHermsecMessage(redacted);
    this.write(`Hermsec> ${redacted}\n`);
    this.writeStatusAfterResponse();
    return { shouldExit: false };
  }

  private addHermsecMessage(text: string): void {
    this.addMessage("hermsec", redactSecrets(text));
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

  private render(): void {
    this.write(`${renderFrame(this.state, this.terminalWidth())}\n`);
  }

  private writeStatusAfterResponse(): void {
    const lines = formatStatusRail(this.state);
    this.write(`Status: ${lines.join(" | ")}\n\n`);
  }

  private write(value: string): void {
    this.output.write(value);
  }

  private terminalWidth(): number {
    return this.output.columns ?? 100;
  }

  private isInteractive(): boolean {
    return this.forceInteractive ?? Boolean(this.input.isTTY && this.output.isTTY);
  }
}

export function createDefaultState(cwd: string, initialState: Partial<TuiState> = {}): TuiState {
  return {
    workspaces: initialState.workspaces ?? [],
    activeWorkspaceId: initialState.activeWorkspaceId,
    privacyMode: initialState.privacyMode ?? "local-only",
    modelMode: initialState.modelMode ?? "none",
    scanMode: initialState.scanMode ?? "auto",
    scanPreference: initialState.scanPreference ?? "full",
    reportLocation: initialState.reportLocation ?? "app-data",
    reportDir: initialState.reportDir ?? defaultReportDir(),
    lastScan: initialState.lastScan,
    lastDoctor: initialState.lastDoctor,
    schedules: initialState.schedules ?? [],
    reports: initialState.reports ?? [],
    transcript: initialState.transcript ?? [
      {
        role: "system",
        text: `TUI cwd: ${normalizedDisplayPath(cwd)}`,
        at: new Date().toISOString(),
      },
    ],
  };
}

function nonInteractiveMessage(): string {
  return [
    "Hermsec TUI detected a non-interactive terminal, so it will not start a prompt.",
    "Use a TTY for chatbot mode, or call scriptable commands such as:",
    "- hermsec doctor",
    "- hermsec scan <path>",
    "- hermsec chat",
    "No scanner, package manager, shell, or install command was run.",
    "",
  ].join("\n");
}

async function localPathExists(target: string): Promise<boolean> {
  try {
    const stats = await fs.stat(normalizeTargetPath(target));
    return stats.isDirectory() || stats.isFile();
  } catch {
    return false;
  }
}

async function findReports(root: string): Promise<TuiReportSummary[]> {
  const reports: TuiReportSummary[] = [];
  await walkReports(root, 0, reports);
  return reports.sort((left, right) => (right.createdAt ?? "").localeCompare(left.createdAt ?? ""));
}

async function walkReports(root: string, depth: number, reports: TuiReportSummary[]): Promise<void> {
  if (depth > 4 || reports.length >= 12) {
    return;
  }

  let entries: Dirent[];
  try {
    entries = await fs.readdir(root, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    if (reports.length >= 12) {
      return;
    }

    const fullPath = path.join(root, entry.name);
    if (entry.isDirectory()) {
      await walkReports(fullPath, depth + 1, reports);
      continue;
    }

    if (!entry.isFile() || !/^report\.(?:md|html)$|^summary\.json$/i.test(entry.name)) {
      continue;
    }

    let createdAt: string | undefined;
    try {
      const stats = await fs.stat(fullPath);
      createdAt = stats.mtime.toISOString();
    } catch {
      createdAt = undefined;
    }

    const report: TuiReportSummary = {
      title: entry.name,
      path: fullPath,
    };

    if (createdAt) {
      report.createdAt = createdAt;
    }

    reports.push(report);
  }
}

function formatIntel(summary: TuiIntelSummary): string {
  return [
    `${formatStatus(summary.status)} ${summary.message}`,
    ...summary.items.map((item, index) => `${index + 1}. ${item}`),
  ].join("\n");
}

function summarizeScan(scan: TuiScanResult): string {
  if (!scan.summary) {
    return scan.message ?? scan.status;
  }

  return `CRITICAL ${scan.summary.critical}, HIGH ${scan.summary.high}, MEDIUM ${scan.summary.medium}, LOW ${scan.summary.low}, INFO ${scan.summary.info}`;
}

function extractReportPath(input: string): string | undefined {
  const match = /\bsave\s+reports?\s+to\s+(.+)$/i.exec(input);
  const value = match?.[1]?.trim();
  return value && value.length > 0 ? value : undefined;
}

function uniqueStrings(values: Array<string | undefined>): string[] {
  const seen = new Set<string>();
  const output: string[] = [];

  for (const value of values) {
    if (!value || seen.has(value)) {
      continue;
    }

    seen.add(value);
    output.push(value);
  }

  return output;
}

function isYes(value: string): boolean {
  return /^(y|yes|true|1)$/i.test(value.trim());
}

function isInputClosed(error: unknown): boolean {
  return error instanceof Error && /closed|abort/i.test(error.message);
}

function hasData<T>(result: CommandResult<T>): result is Extract<CommandResult<T>, { ok: true }> & { data: T } {
  return result.ok && result.data !== undefined;
}
