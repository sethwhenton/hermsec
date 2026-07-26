import type { HermsecProductScanAssistMode, ScanProjectResult } from "../renderer/src/types/scan";

const KNOWN_MODEL_ENVIRONMENT_NAMES = [
  "HERMSEC_MODEL_PROVIDER",
  "HERMSEC_MODEL",
  "HERMSEC_MODEL_BASE_URL",
  "HERMSEC_MODEL_API_KEY_ENV",
  "HERMSEC_ALLOW_REMOTE_PROVIDERS",
  "HERMSEC_AGENT_MODEL_CONFIG",
  "HERMSEC_PRODUCT_AGENT_SPECIALIST_COUNT",
  "HERMSEC_PRODUCT_AGENT_PANEL",
  "OPENAI_API_KEY",
  "OPENAI_BASE_URL",
  "OPENROUTER_API_KEY",
  "OPENROUTER_BASE_URL",
  "ANTHROPIC_API_KEY",
  "ANTHROPIC_BASE_URL",
  "GEMINI_API_KEY",
  "GEMINI_BASE_URL",
  "OPENCODE_GO_API_KEY",
  "OLLAMA_API_KEY",
  "OLLAMA_HOST",
] as const;

export interface CliProcessSpecOptions {
  isPackaged: boolean;
  electronExecutable: string;
  platform: NodeJS.Platform;
  args: string[];
  inheritedEnv: NodeJS.ProcessEnv;
  extraEnv?: Record<string, string>;
  /**
   * Packaged scans/Doctor runs use an execution-lease snapshot. Values listed
   * here take precedence over both inherited and UI-generated environment data,
   * including case-insensitive Windows aliases.
   */
  trustedRuntime?: {
    values: Record<string, string>;
    controlledNames: Iterable<string>;
  };
  includeModel: boolean;
  modelEnvironmentNames: Iterable<string>;
}

export interface CliProcessSpec {
  executable: string;
  args: string[];
  env: NodeJS.ProcessEnv;
}

export interface CliFailureInput {
  exitCode: number;
  outcome: {
    ok?: boolean;
    message?: string;
    errorCode?: string;
    remediation?: string;
  };
  runId: string;
  assistMode: HermsecProductScanAssistMode;
  assistModeLabel: string;
  targetPath: string;
  reportDir: string;
}

type DoctorLikeCheck = {
  id: string;
  status: string;
  requirement?: string;
  message?: string;
  remediation?: string;
};

type DoctorLikeOutcome = {
  ok?: boolean;
  errorCode?: string;
  message?: string;
  data?: {
    checks?: DoctorLikeCheck[];
  };
};

const PACKAGED_OPTIONAL_HOST_COMMANDS = new Map([
  [
    "command-git",
    "Git is not installed; repository metadata and change-aware scans are unavailable, but bundled scanners remain ready.",
  ],
  [
    "command-npm",
    "npm is not installed; PMG-backed npm audit is unavailable, but bundled non-npm scanners remain ready.",
  ],
]);

const PACKAGED_OPTIONAL_HOST_LABELS = new Map([
  ["Git", "command-git"],
  ["npm", "command-npm"],
]);

export function collectModelEnvironmentVariableNames(configuredNames: Iterable<string | undefined> = []): string[] {
  const names = new Set<string>(KNOWN_MODEL_ENVIRONMENT_NAMES);
  for (const configuredName of configuredNames) {
    const name = configuredName?.trim();
    if (name) names.add(name);
  }
  return [...names];
}

export function createCliProcessSpec(options: CliProcessSpecOptions): CliProcessSpec {
  const env: NodeJS.ProcessEnv = { ...options.inheritedEnv, ...options.extraEnv };
  if (options.trustedRuntime) {
    applyTrustedRuntimeEnvironment(env, options.trustedRuntime, options.platform);
  }
  if (!options.includeModel) {
    const normalizedNames = new Set(
      [...options.modelEnvironmentNames].map((name) => normalizeEnvironmentName(name, options.platform)),
    );
    for (const variableName of Object.keys(env)) {
      if (normalizedNames.has(normalizeEnvironmentName(variableName, options.platform))) {
        delete env[variableName];
      }
    }
  }

  if (options.isPackaged) {
    env.ELECTRON_RUN_AS_NODE = "1";
    return {
      executable: options.electronExecutable,
      args: [...options.args],
      env,
    };
  }

  return {
    executable: options.platform === "win32" ? "node.exe" : "node",
    args: [...options.args],
    env,
  };
}

function applyTrustedRuntimeEnvironment(
  environment: NodeJS.ProcessEnv,
  trustedRuntime: NonNullable<CliProcessSpecOptions["trustedRuntime"]>,
  platform: NodeJS.Platform,
): void {
  const controlled = new Set(
    [...trustedRuntime.controlledNames].map((name) => normalizeEnvironmentName(name, platform)),
  );
  for (const name of Object.keys(environment)) {
    if (controlled.has(normalizeEnvironmentName(name, platform))) {
      delete environment[name];
    }
  }
  for (const [name, value] of Object.entries(trustedRuntime.values)) {
    environment[name] = value;
  }
}

export function normalizePackagedDoctorOutcome<T extends DoctorLikeOutcome>(
  outcome: T,
  exitCode: number,
  isPackaged: boolean,
): { outcome: T; ok: boolean } {
  const rawChecks = outcome.data?.checks ?? [];
  if (!isPackaged) {
    return {
      outcome,
      ok: outcome.ok !== false && exitCode === 0,
    };
  }

  const messageFailureChecks = rawChecks.length === 0
    ? packagedHostFailureChecksFromMessage(outcome)
    : undefined;
  const sourceChecks = rawChecks.length > 0 ? rawChecks : messageFailureChecks ?? [];
  const rawFailures = sourceChecks.filter((check) => check.status === "fail");
  const normalizedChecks = sourceChecks.map((check) => {
    const packagedMessage = PACKAGED_OPTIONAL_HOST_COMMANDS.get(check.id);
    if (!packagedMessage) return check;
    return {
      ...check,
      requirement: "recommended",
      status: check.status === "fail" ? "warn" : check.status,
      message: check.status === "fail" ? packagedMessage : check.message,
    };
  });
  const recoveredOptionalHostFailure = rawFailures.length > 0
    && rawFailures.every((check) => PACKAGED_OPTIONAL_HOST_COMMANDS.has(check.id))
    && normalizedChecks.every((check) => check.status !== "fail");
  const normalizedOutcome = {
    ...outcome,
    ...(recoveredOptionalHostFailure
      ? {
          message:
            "Hermsec doctor completed. Git and npm remain optional host capabilities; bundled scanners are verified separately.",
        }
      : {}),
    data: outcome.data || normalizedChecks.length > 0
      ? {
          ...(outcome.data ?? {}),
          checks: normalizedChecks,
        }
      : outcome.data,
  } as T;

  return {
    outcome: normalizedOutcome,
    ok: (outcome.ok !== false && exitCode === 0) || recoveredOptionalHostFailure,
  };
}

function packagedHostFailureChecksFromMessage(
  outcome: DoctorLikeOutcome,
): DoctorLikeCheck[] | undefined {
  if (outcome.errorCode !== "DOCTOR_REQUIRED_CHECK_FAILED" || !outcome.message) {
    return undefined;
  }

  const failureLabels = outcome.message
    .split(/\r?\n/u)
    .map((line) => /^FAIL:\s+(.+?)\s+-\s+/u.exec(line)?.[1])
    .filter((label): label is string => Boolean(label));
  if (failureLabels.length === 0) return undefined;

  const failureIds = failureLabels.map((label) => PACKAGED_OPTIONAL_HOST_LABELS.get(label));
  if (failureIds.some((id) => !id)) return undefined;

  return failureIds.map((id) => ({
    id: id!,
    status: "fail",
    requirement: "required",
  }));
}

function normalizeEnvironmentName(name: string, platform: NodeJS.Platform): string {
  return platform === "win32" ? name.toUpperCase() : name;
}

export function failedScanResultFromCli(input: CliFailureInput): ScanProjectResult | undefined {
  if (input.exitCode === 0 && input.outcome.ok !== false) return undefined;

  const providerRequired = input.outcome.errorCode === "MODEL_PROVIDER_REQUIRED";
  const message = input.outcome.message?.trim()
    || (providerRequired
      ? `${input.assistModeLabel} requires a configured model provider.`
      : `Hermsec CLI failed with exit code ${input.exitCode}.`);
  const remediation = input.outcome.remediation?.trim();

  return {
    ok: false,
    message,
    error: providerRequired ? "provider-required" : input.outcome.errorCode || "cli-failed",
    runId: input.runId,
    targetPath: input.targetPath,
    reportDir: input.reportDir,
    assistMode: input.assistMode,
    assistModeLabel: input.assistModeLabel,
    terminalStatus: "failed",
    degradationReasons: [remediation || message],
  };
}
