import { accessSync } from "node:fs";
import { readFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { credentialStatusFromEnv, providerCredentialEnv } from "../../model/credentials.js";
import { defaultReportDir, appDataDir } from "../../shared/paths.js";
import type { CommandResult } from "../../shared/types.js";
import { parseArgs, unknownFlagResult } from "../args.js";
import { commandHelp, helpResult } from "../help.js";
import { moduleSpecs } from "../moduleSpecs.js";
import { invokeOptionalModule, isModuleUnavailable } from "../optionalModule.js";
import { toOutcome } from "../output.js";
import type { CliOutcome, CommandContext } from "../types.js";

type DoctorStatus = "pass" | "warn" | "fail" | "skip";

type DoctorCheck = {
  id: string;
  label: string;
  status: DoctorStatus;
  message: string;
  requirement?: "required" | "recommended" | "optional";
  remediation?: string;
};

type DoctorData = {
  generatedAt: string;
  cwd: string;
  appDataDir: string;
  reportDirectory: string;
  checks: DoctorCheck[];
  summary: {
    pass: number;
    warn: number;
    fail: number;
    skip: number;
  };
  fallback: boolean;
};

type DoctorOptions = {
  cwd: string;
  json: boolean;
  env: NodeJS.ProcessEnv;
};

export async function runDoctorCommand(args: string[], context: CommandContext): Promise<CliOutcome> {
  const parsed = parseArgs(args, {
    booleanFlags: ["json", "help"],
  });

  if (parsed.unknownFlags.length > 0) {
    return toOutcome(unknownFlagResult(parsed.unknownFlags, "hermsec doctor --help"), parsed.flags.json === true);
  }

  if (parsed.flags.help === true) {
    return toOutcome(helpResult(commandHelp("doctor")));
  }

  const json = parsed.flags.json === true;
  const moduleResult = await invokeOptionalModule<DoctorOptions, DoctorData>(
    moduleSpecs.doctor,
    { cwd: context.cwd, json, env: context.env },
    "Doctor checks completed.",
  );

  if (!isModuleUnavailable(moduleResult)) {
    return toOutcome(moduleResult, json, doctorExitCode(moduleResult));
  }

  const fallback = await runFallbackDoctor(context);
  return toOutcome(fallback, json, doctorExitCode(fallback));
}

async function runFallbackDoctor(context: CommandContext): Promise<CommandResult<DoctorData>> {
  const checks: DoctorCheck[] = [];
  const npmrcPath = path.join(context.cwd, ".npmrc");

  checks.push(nodeVersionCheck());
  checks.push(platformCheck());
  checks.push(await npmrcCheck(npmrcPath));
  checks.push(pathCheck("app-data-dir", "Hermsec app data path", appDataDir()));
  checks.push(pathCheck("report-dir", "Default report directory", defaultReportDir()));

  for (const command of [
    ["pmg", "SafeDep PMG", "recommended"],
    ["git", "Git", "required"],
    ["gh", "GitHub CLI", "optional"],
    ["npm", "npm", "required"],
    ["bandit", "Bandit", "optional"],
    ["semgrep", "Semgrep", "optional"],
    ["gitleaks", "Gitleaks", "optional"],
    ["osv-scanner", "OSV-Scanner", "optional"],
    ["pip-audit", "pip-audit", "optional"],
  ] as const) {
    checks.push(commandAvailabilityCheck(command[0], command[1], command[2], context.env));
  }

  checks.push(...providerCredentialChecks());

  checks.push({
    id: "network",
    label: "Network checks",
    status: "skip",
    message: "Skipped in CLI fallback mode to avoid surprise outbound requests.",
  });
  checks.push({
    id: "tracked-secrets",
    label: "Tracked config secret check",
    status: "skip",
    message: "Skipped until storage paths and git-aware secret checks are available.",
  });
  checks.push({
    id: "os-scheduler",
    label: "OS scheduler support",
    status: "skip",
    message: "Skipped until the scheduler module is available.",
  });

  const data: DoctorData = {
    generatedAt: context.now().toISOString(),
    cwd: context.cwd,
    appDataDir: appDataDir(),
    reportDirectory: defaultReportDir(),
    checks,
    summary: summarize(checks),
    fallback: true,
  };

  const requiredFailures = checks.filter((check) => check.status === "fail" && check.requirement === "required");
  const warnings = checks.filter((check) => check.status === "warn");
  if (requiredFailures.length > 0) {
    return {
      ok: false,
      errorCode: "DOCTOR_REQUIRED_CHECK_FAILED",
      message: renderDoctorSummary(data),
      remediation: "Fix required checks, then run `hermsec doctor` again.",
    };
  }

  if (warnings.length > 0) {
    return {
      ok: true,
      message: renderDoctorSummary(data),
      data,
    };
  }

  return {
    ok: true,
    message: renderDoctorSummary(data),
    data,
  };
}

function nodeVersionCheck(): DoctorCheck {
  const major = Number(process.versions.node.split(".")[0] ?? "0");
  if (major >= 22) {
    return {
      id: "node",
      label: "Node.js",
      status: "pass",
      requirement: "required",
      message: `Node ${process.versions.node} satisfies Hermsec's >=22 requirement.`,
    };
  }

  return {
    id: "node",
    label: "Node.js",
    status: "fail",
    requirement: "required",
    message: `Node ${process.versions.node} is below Hermsec's >=22 requirement.`,
    remediation: "Install Node.js 22 or newer before running Hermsec.",
  };
}

function platformCheck(): DoctorCheck {
  if (process.platform === "win32" || process.platform === "darwin" || process.platform === "linux") {
    return {
      id: "platform",
      label: "Platform",
      status: "pass",
      message: `${os.type()} ${os.release()} is a supported local platform.`,
    };
  }

  return {
    id: "platform",
    label: "Platform",
    status: "warn",
    message: `${process.platform} is not a primary Hermsec target platform.`,
    remediation: "Use Windows, macOS, or Linux for the supported MVP path.",
  };
}

async function npmrcCheck(npmrcPath: string): Promise<DoctorCheck> {
  let text: string;
  try {
    text = await readFile(npmrcPath, "utf8");
  } catch {
    return {
      id: "npmrc",
      label: ".npmrc hardening",
      status: "fail",
      requirement: "required",
      message: `No .npmrc found at ${npmrcPath}.`,
      remediation: "Add project .npmrc controls that are supported by the local npm version.",
    };
  }

  const entries = npmrcEntries(text);
  const unsupportedKeys = [
    "min-release-age",
    "allow-git",
    "allow-remote",
    "allow-file",
    "allow-directory",
  ];
  const unsupportedPresent = unsupportedKeys.filter((key) => entries.has(key));
  if (unsupportedPresent.length > 0) {
    return {
      id: "npmrc",
      label: ".npmrc hardening",
      status: "fail",
      requirement: "required",
      message: `.npmrc contains npm-unsupported hardening keys that produce warnings: ${unsupportedPresent.join(", ")}.`,
      remediation: "Remove unsupported npm keys from .npmrc and enforce those supply-chain controls through PMG or documented review policy.",
    };
  }

  const required = [
    ["ignore-scripts", "true"],
    ["engine-strict", "true"],
    ["save-exact", "true"],
    ["package-lock", "true"],
  ] as const;
  const missing = required.filter(([key, value]) => !entries.get(key)?.includes(value)).map(([key, value]) => `${key}=${value}`);

  if (missing.length === 0) {
    return {
      id: "npmrc",
      label: ".npmrc hardening",
      status: "pass",
      requirement: "required",
      message: ".npmrc includes npm-supported supply-chain hardening controls without unknown-key warnings.",
    };
  }

  return {
    id: "npmrc",
    label: ".npmrc hardening",
    status: "fail",
    requirement: "required",
    message: `.npmrc is missing: ${missing.join(", ")}.`,
    remediation: "Restore npm-supported hardening controls before dependency work.",
  };
}

function pathCheck(id: string, label: string, value: string): DoctorCheck {
  return {
    id,
    label,
    status: "pass",
    message: value,
  };
}

function commandAvailabilityCheck(
  command: string,
  label: string,
  requirement: NonNullable<DoctorCheck["requirement"]>,
  env: NodeJS.ProcessEnv,
): DoctorCheck {
  const location = findOnPath(command, env);
  if (location !== undefined) {
    return {
      id: `command-${command}`,
      label,
      status: "pass",
      requirement,
      message: `Found ${command} at ${location}.`,
    };
  }

  return {
    id: `command-${command}`,
    label,
    status: requirement === "required" ? "fail" : requirement === "recommended" ? "warn" : "skip",
    requirement,
    message: `${command} was not found on PATH.`,
    remediation: requirement === "required"
      ? `Install ${label} or add it to PATH.`
      : requirement === "recommended"
        ? `Install ${label} for stronger package-manager protection. See docs/pmg-setup.md for SafeDep PMG setup.`
        : `Install ${label} if you want Hermsec to use that optional capability.`,
  };
}

function providerCredentialChecks(): DoctorCheck[] {
  return Object.entries(providerCredentialEnv).map(([provider, envName]) => {
    const status = credentialStatusFromEnv(envName);
    if (status.present) {
      return {
        id: `provider-env-${provider}`,
        label: `${provider} credential`,
        status: "pass",
        requirement: "optional",
        message: `${status.envName} is set for ${provider} (${status.fingerprint}).`,
      };
    }

    return {
      id: `provider-env-${provider}`,
      label: `${provider} credential`,
      status: status.validEnvName ? "skip" : "fail",
      requirement: "optional",
      message: status.validEnvName
        ? `${status.envName} is not set. ${provider} remains disabled unless explicitly configured.`
        : "Provider credential reference is not a valid environment variable name.",
      remediation: status.validEnvName
        ? `Set ${status.envName} only if you explicitly enable ${provider}.`
        : "Store provider credentials in environment variables and save only the variable name.",
    };
  });
}

function findOnPath(command: string, env: NodeJS.ProcessEnv = process.env): string | undefined {
  const pathValue = env.PATH ?? "";
  const pathEntries = pathValue.split(path.delimiter).filter(Boolean);
  const extensions = process.platform === "win32"
    ? ["", ...(env.PATHEXT ?? ".EXE;.CMD;.BAT;.COM").split(";")]
    : [""];

  for (const entry of pathEntries) {
    for (const extension of extensions) {
      const candidate = path.join(entry, process.platform === "win32" ? `${command}${extension}` : command);
      try {
        accessSync(candidate);
        return candidate;
      } catch {
        continue;
      }
    }
  }

  return undefined;
}

function npmrcEntries(text: string): Map<string, string[]> {
  const entries = new Map<string, string[]>();
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) {
      continue;
    }
    const match = /^([^=\s]+)\s*=\s*(.*)$/.exec(line);
    if (!match?.[1]) {
      continue;
    }
    const key = match[1].toLowerCase();
    const value = (match[2] ?? "").trim().toLowerCase();
    entries.set(key, [...(entries.get(key) ?? []), value]);
  }
  return entries;
}

function summarize(checks: DoctorCheck[]): DoctorData["summary"] {
  return {
    pass: checks.filter((check) => check.status === "pass").length,
    warn: checks.filter((check) => check.status === "warn").length,
    fail: checks.filter((check) => check.status === "fail").length,
    skip: checks.filter((check) => check.status === "skip").length,
  };
}

function renderDoctorSummary(data: DoctorData): string {
  const lines = [
    "Hermsec doctor completed.",
    `Checks: ${data.summary.pass} passed, ${data.summary.warn} warnings, ${data.summary.fail} failed, ${data.summary.skip} skipped.`,
    `Config path: ${path.join(data.appDataDir, "config.json")}`,
    `Report directory: ${data.reportDirectory}`,
  ];

  const notable = data.checks.filter((check) => check.status === "fail" || check.status === "warn");
  for (const check of notable) {
    lines.push(`${check.status.toUpperCase()}: ${check.label} - ${check.message}`);
  }

  return lines.join("\n");
}

function doctorExitCode(result: CommandResult<DoctorData>): number {
  const data = "data" in result ? result.data : undefined;
  if (!result.ok) {
    return result.errorCode === "DOCTOR_REQUIRED_CHECK_FAILED" ? 1 : 2;
  }
  return 0;
}
