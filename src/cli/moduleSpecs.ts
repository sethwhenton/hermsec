import type { OptionalModuleSpec } from "./types.js";

export const moduleSpecs = {
  chat: {
    modulePath: "../tui/cli.js",
    exportName: "launchChat",
    expectedShape:
      "export async function launchChat(options: { cwd: string; args: string[]; firstRun: boolean }): Promise<CommandResult>",
    unavailableMessage: "The chat TUI is not available yet.",
    remediation: "Implement the TUI CLI facade before using `hermsec` or `hermsec chat`.",
  },
  onboard: {
    modulePath: "../tui/cli.js",
    exportName: "runOnboarding",
    expectedShape:
      "export async function runOnboarding(options: { cwd: string; args: string[] }): Promise<CommandResult>",
    unavailableMessage: "The onboarding flow is not available yet.",
    remediation: "Implement the TUI onboarding facade before using `hermsec onboard`.",
  },
  doctor: {
    modulePath: "../doctor/checks.js",
    exportName: "runDoctor",
    expectedShape:
      "export async function runDoctor(options: { cwd: string; json: boolean }): Promise<CommandResult<DoctorResult> | DoctorResult>",
    unavailableMessage: "The doctor module is not available yet; using CLI fallback checks.",
    remediation: "Implement the doctor checks facade for full scanner, provider, and system readiness.",
  },
  scan: {
    modulePath: "../core/harness.js",
    exportName: "runScan",
    expectedShape:
      "export async function runScan(options: { cwd: string; target: string; mode: 'auto' | 'offline' | 'online'; outputDirectory?: string; formats: ('json' | 'md' | 'html')[]; useModel: boolean }): Promise<CommandResult>",
    unavailableMessage: "The scanner harness is not available yet.",
    remediation: "Implement the core harness facade before running scans.",
  },
  configGet: {
    modulePath: "../storage/userConfig.js",
    exportName: "getConfigValue",
    expectedShape:
      "export async function getConfigValue(options: { cwd: string; key?: string }): Promise<CommandResult>",
    unavailableMessage: "The config store is not available yet.",
    remediation: "Implement user config storage before reading persisted settings.",
  },
  configSet: {
    modulePath: "../storage/userConfig.js",
    exportName: "setConfigValue",
    expectedShape:
      "export async function setConfigValue(options: { cwd: string; key: string; value: string }): Promise<CommandResult>",
    unavailableMessage: "The config store is not available yet.",
    remediation: "Implement user config storage before writing persisted settings.",
  },
  configPath: {
    modulePath: "../storage/userConfig.js",
    exportName: "getConfigPath",
    expectedShape:
      "export async function getConfigPath(options: { cwd: string }): Promise<CommandResult<{ path: string }>>",
    unavailableMessage: "The config path API is not available yet.",
    remediation: "Implement user config path lookup for storage-aware output.",
  },
  workspaceList: {
    modulePath: "../workspace/api.js",
    exportName: "listWorkspaces",
    expectedShape:
      "export async function listWorkspaces(options: { cwd: string }): Promise<CommandResult>",
    unavailableMessage: "Workspace storage is not available yet.",
    remediation: "Implement the workspace facade before listing workspaces.",
  },
  workspaceAdd: {
    modulePath: "../workspace/api.js",
    exportName: "addWorkspace",
    expectedShape:
      "export async function addWorkspace(options: { cwd: string; target: string; name?: string }): Promise<CommandResult>",
    unavailableMessage: "Workspace storage is not available yet.",
    remediation: "Implement the workspace facade before adding workspaces.",
  },
  workspaceUse: {
    modulePath: "../workspace/api.js",
    exportName: "useWorkspace",
    expectedShape:
      "export async function useWorkspace(options: { cwd: string; selector: string }): Promise<CommandResult>",
    unavailableMessage: "Workspace storage is not available yet.",
    remediation: "Implement the workspace facade before switching workspaces.",
  },
  reportList: {
    modulePath: "../reports/reportStore.js",
    exportName: "listReports",
    expectedShape:
      "export async function listReports(options: { cwd: string; workspaceId?: string }): Promise<CommandResult>",
    unavailableMessage: "Report storage is not available yet.",
    remediation: "Implement the report store facade before listing reports.",
  },
  reportOpen: {
    modulePath: "../reports/reportStore.js",
    exportName: "openReport",
    expectedShape:
      "export async function openReport(options: { cwd: string; selector: string }): Promise<CommandResult>",
    unavailableMessage: "Report opening is not available yet.",
    remediation: "Implement the report store facade before opening reports.",
  },
  reportPath: {
    modulePath: "../reports/reportStore.js",
    exportName: "getReportPath",
    expectedShape:
      "export async function getReportPath(options: { cwd: string; workspaceId?: string; reportId?: string }): Promise<CommandResult<{ path: string }>>",
    unavailableMessage: "Report path lookup is not available yet.",
    remediation: "Implement the report store facade for storage-aware report paths.",
  },
  sync: {
    modulePath: "../scheduler/sync.js",
    exportName: "runSync",
    expectedShape:
      "export async function runSync(options: { cwd: string; offline?: boolean }): Promise<CommandResult>",
    unavailableMessage: "Sync support is not available yet.",
    remediation: "Implement queued enrichment sync before using `hermsec sync`.",
  },
  scheduleAdd: {
    modulePath: "../scheduler/cli.js",
    exportName: "addSchedule",
    expectedShape:
      "export async function addSchedule(options: { cwd: string; target: string; dailyTime: string; mode: 'auto' | 'offline' | 'online' }): Promise<CommandResult>",
    unavailableMessage: "Scheduling is not available yet.",
    remediation: "Implement schedule storage and runner before adding schedules.",
  },
  scheduleList: {
    modulePath: "../scheduler/cli.js",
    exportName: "listSchedules",
    expectedShape:
      "export async function listSchedules(options: { cwd: string }): Promise<CommandResult>",
    unavailableMessage: "Scheduling is not available yet.",
    remediation: "Implement schedule storage before listing schedules.",
  },
  scheduleRun: {
    modulePath: "../scheduler/cli.js",
    exportName: "runSchedule",
    expectedShape:
      "export async function runSchedule(options: { cwd: string; scheduleId: string; force?: boolean }): Promise<CommandResult>",
    unavailableMessage: "Scheduling is not available yet.",
    remediation: "Implement the schedule runner before running schedules.",
  },
  scheduleUpdate: {
    modulePath: "../scheduler/cli.js",
    exportName: "updateSchedule",
    expectedShape:
      "export async function updateSchedule(options: { cwd: string; scheduleId: string; target?: string; dailyTime?: string; mode?: 'auto' | 'offline' | 'online'; enabled?: boolean }): Promise<CommandResult>",
    unavailableMessage: "Scheduling is not available yet.",
    remediation: "Implement schedule storage before editing schedules.",
  },
  scheduleSetEnabled: {
    modulePath: "../scheduler/cli.js",
    exportName: "setScheduleEnabled",
    expectedShape:
      "export async function setScheduleEnabled(options: { cwd: string; scheduleId: string; enabled: boolean }): Promise<CommandResult>",
    unavailableMessage: "Scheduling is not available yet.",
    remediation: "Implement schedule storage before toggling schedules.",
  },
  scheduleRemove: {
    modulePath: "../scheduler/cli.js",
    exportName: "removeSchedule",
    expectedShape:
      "export async function removeSchedule(options: { cwd: string; scheduleId: string }): Promise<CommandResult>",
    unavailableMessage: "Scheduling is not available yet.",
    remediation: "Implement schedule storage before removing schedules.",
  },
  watch: {
    modulePath: "../scheduler/watch.js",
    exportName: "watchTarget",
    expectedShape:
      "export async function watchTarget(options: { cwd: string; target: string; afterIdle: string; mode: 'auto' | 'offline' | 'online' }): Promise<CommandResult>",
    unavailableMessage: "Watch mode is not available yet.",
    remediation: "Implement the scheduler watch facade before using watch mode.",
  },
  intelUpdate: {
    modulePath: "../intel/update.js",
    exportName: "updateIntel",
    expectedShape:
      "export async function updateIntel(options: { cwd: string; workspaceId?: string; sources?: string[]; offline: boolean }): Promise<CommandResult>",
    unavailableMessage: "Security intelligence updates are not available yet.",
    remediation: "Implement the intel update facade before refreshing intelligence feeds.",
  },
  evalRun: {
    modulePath: "../eval/evalRunner.js",
    exportName: "runEvaluation",
    expectedShape:
      "export async function runEvaluation(options: { cwd: string; suite?: string; mode?: 'scanner-only' | 'agent-assisted'; outputDirectory?: string }): Promise<CommandResult>",
    unavailableMessage: "Evaluation runner is not available yet.",
    remediation: "Implement the evaluation runner facade before running benchmark suites.",
  },
  evalCompare: {
    modulePath: "../eval/modeComparison.js",
    exportName: "compareEvaluations",
    expectedShape:
      "export async function compareEvaluations(options: { cwd: string; scannerOnly: string; agentAssisted: string; outputPath?: string }): Promise<CommandResult>",
    unavailableMessage: "Evaluation comparison is not available yet.",
    remediation: "Implement the mode comparison facade before comparing evaluation runs.",
  },
  evalExplainMatch: {
    modulePath: "../eval/matcher.js",
    exportName: "explainMatch",
    expectedShape:
      "export async function explainMatch(options: { cwd: string; suite?: string; caseId: string; findingId: string }): Promise<CommandResult>",
    unavailableMessage: "Evaluation match explanation is not available yet.",
    remediation: "Implement the matcher explanation facade before explaining benchmark matches.",
  },
} satisfies Record<string, OptionalModuleSpec>;
