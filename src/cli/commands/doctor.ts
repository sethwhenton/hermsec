import { accessSync } from "node:fs";
import { readFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import process from "node:process";
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
    { cwd: context.cwd, json },
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
    ["pmg", "SafeDep PMG"],
    ["git", "Git"],
    ["gh", "GitHub CLI"],
    ["npm", "npm"],
    ["bandit", "Bandit"],
    ["semgrep", "Semgrep"],
    ["gitleaks", "Gitleaks"],
    ["osv-scanner", "OSV-Scanner"],
    ["pip-audit", "pip-audit"],
  ] as const) {
    checks.push(commandAvailabilityCheck(command[0], command[1]));
  }

  checks.push({
    id: "network",
    label: "Network checks",
    status: "skip",
    message: "Skipped in CLI fallback mode to avoid surprise outbound requests.",
  });
  checks.push({
    id: "provider",
    label: "Model provider connectivity",
    status: "skip",
    message: "Skipped until provider configuration storage is available.",
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

  const requiredFailures = checks.filter((check) => check.status === "fail");
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
      message: `Node ${process.versions.node} satisfies Hermsec's >=22 requirement.`,
    };
  }

  return {
    id: "node",
    label: "Node.js",
    status: "fail",
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
      message: `No .npmrc found at ${npmrcPath}.`,
      remediation: "Add the project .npmrc hardening controls from implementationplan.md.",
    };
  }

  const required = [
    "min-release-age=7",
    "ignore-scripts=true",
    "engine-strict=true",
    "allow-git=none",
    "allow-remote=none",
    "allow-file=none",
    "allow-directory=none",
  ];
  const missing = required.filter((entry) => !text.includes(entry));

  if (missing.length === 0) {
    return {
      id: "npmrc",
      label: ".npmrc hardening",
      status: "pass",
      message: ".npmrc includes the expected supply-chain hardening controls.",
    };
  }

  return {
    id: "npmrc",
    label: ".npmrc hardening",
    status: "fail",
    message: `.npmrc is missing: ${missing.join(", ")}.`,
    remediation: "Restore the recommended npm hardening controls before dependency work.",
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

function commandAvailabilityCheck(command: string, label: string): DoctorCheck {
  const location = findOnPath(command);
  if (location !== undefined) {
    return {
      id: `command-${command}`,
      label,
      status: "pass",
      message: `Found ${command} at ${location}.`,
    };
  }

  const required = command === "git" || command === "npm";
  return {
    id: `command-${command}`,
    label,
    status: required ? "fail" : "warn",
    message: `${command} was not found on PATH.`,
    remediation: required
      ? `Install ${label} or add it to PATH.`
      : `Install ${label} if you want Hermsec to use that optional capability.`,
  };
}

function findOnPath(command: string): string | undefined {
  const pathValue = process.env.PATH ?? "";
  const pathEntries = pathValue.split(path.delimiter).filter(Boolean);
  const extensions = process.platform === "win32"
    ? ["", ...(process.env.PATHEXT ?? ".EXE;.CMD;.BAT;.COM").split(";")]
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
