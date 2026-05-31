import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { providerCredentialEnv, credentialStatusFromEnv } from "../model/credentials.js";
import { externalScannerCatalog } from "../scanners/external.js";
import { findExecutableOnPath } from "../shared/executable.js";
import { appDataDir, defaultReportDir } from "../shared/paths.js";
import type { CommandResult } from "../shared/types.js";

type DoctorStatus = "pass" | "warn" | "fail" | "skip";
type DoctorRequirement = "required" | "recommended" | "optional";

type DoctorCheck = {
  id: string;
  label: string;
  status: DoctorStatus;
  requirement: DoctorRequirement;
  message: string;
  remediation?: string;
};

type DoctorResult = {
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
  fallback: false;
};

export async function runDoctor(options: { cwd: string; json: boolean; env?: NodeJS.ProcessEnv }): Promise<CommandResult<DoctorResult>> {
  const checks: DoctorCheck[] = [
    nodeVersionCheck(),
    platformCheck(),
    await npmrcCheck(path.join(options.cwd, ".npmrc")),
    await writablePathCheck("app-data-dir", "Hermsec app data path", appDataDir()),
    await writablePathCheck("report-dir", "Default report directory", defaultReportDir()),
    commandCheck("git", "Git", "required", options.env),
    commandCheck("npm", "npm", "required", options.env),
    commandCheck("gh", "GitHub CLI", "optional", options.env),
    ...externalScannerCatalog().map((scanner) =>
      commandCheck(scanner.executable, scanner.label, scanner.id === "pmg" ? "recommended" : "optional", options.env),
    ),
    ...providerChecks(),
    networkPolicyCheck(),
    schedulerCheck(),
  ];

  const data: DoctorResult = {
    generatedAt: new Date().toISOString(),
    cwd: options.cwd,
    appDataDir: appDataDir(),
    reportDirectory: defaultReportDir(),
    checks,
    summary: summarize(checks),
    fallback: false,
  };

  const requiredFailures = checks.filter((check) => check.status === "fail" && check.requirement === "required");
  if (requiredFailures.length > 0) {
    return {
      ok: false,
      errorCode: "DOCTOR_REQUIRED_CHECK_FAILED",
      message: renderSummary(data),
      remediation: "Fix required checks, then run `hermsec doctor` again.",
    };
  }

  return {
    ok: true,
    message: renderSummary(data),
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
    remediation: "Install Node.js 22 or newer.",
  };
}

function platformCheck(): DoctorCheck {
  const supported = process.platform === "win32" || process.platform === "darwin" || process.platform === "linux";
  return {
    id: "platform",
    label: "Platform",
    status: supported ? "pass" : "warn",
    requirement: supported ? "required" : "recommended",
    message: supported
      ? `${os.type()} ${os.release()} is a supported local platform.`
      : `${process.platform} is not a primary Hermsec target platform.`,
  };
}

async function npmrcCheck(filePath: string): Promise<DoctorCheck> {
  let text = "";
  try {
    text = await fs.readFile(filePath, "utf8");
  } catch {
    return {
      id: "npmrc",
      label: ".npmrc hardening",
      status: "fail",
      requirement: "required",
      message: `No .npmrc found at ${filePath}.`,
      remediation: "Restore the project .npmrc controls.",
    };
  }

  const entries = npmrcEntries(text);
  const unsupported = ["min-release-age", "allow-git", "allow-remote", "allow-file", "allow-directory"]
    .filter((key) => entries.has(key));
  if (unsupported.length > 0) {
    return {
      id: "npmrc",
      label: ".npmrc hardening",
      status: "fail",
      requirement: "required",
      message: `.npmrc contains npm-unsupported keys: ${unsupported.join(", ")}.`,
      remediation: "Keep unsupported policy in docs/doctor guidance, not project .npmrc.",
    };
  }

  const required = [
    ["ignore-scripts", "true"],
    ["engine-strict", "true"],
    ["save-exact", "true"],
    ["package-lock", "true"],
  ] as const;
  const missing = required.filter(([key, value]) => !entries.get(key)?.includes(value));
  if (missing.length > 0) {
    return {
      id: "npmrc",
      label: ".npmrc hardening",
      status: "fail",
      requirement: "required",
      message: `.npmrc is missing ${missing.map(([key, value]) => `${key}=${value}`).join(", ")}.`,
      remediation: "Restore npm-supported supply-chain hardening before dependency work.",
    };
  }

  return {
    id: "npmrc",
    label: ".npmrc hardening",
    status: "pass",
    requirement: "required",
    message: ".npmrc uses npm-supported hardening controls without unknown-key warnings.",
  };
}

async function writablePathCheck(id: string, label: string, dir: string): Promise<DoctorCheck> {
  try {
    await fs.mkdir(dir, { recursive: true });
    await fs.access(dir);
    return {
      id,
      label,
      status: "pass",
      requirement: "required",
      message: dir,
    };
  } catch (error) {
    return {
      id,
      label,
      status: "fail",
      requirement: "required",
      message: `${dir} is not writable: ${error instanceof Error ? error.message : String(error)}`,
      remediation: "Choose a writable Hermsec app data/report directory.",
    };
  }
}

function commandCheck(command: string, label: string, requirement: DoctorRequirement, env?: NodeJS.ProcessEnv): DoctorCheck {
  const location = findExecutableOnPath(command, env);
  if (location) {
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
        ? `Install ${label} for stronger supply-chain protection.`
        : `Install ${label} to enable this optional scanner.`,
  };
}

function providerChecks(): DoctorCheck[] {
  return Object.entries(providerCredentialEnv).map(([provider, envName]) => {
    const status = credentialStatusFromEnv(envName);
    if (!status.validEnvName) {
      return {
        id: `provider-env-${provider}`,
        label: `${provider} credential`,
        status: "fail",
        requirement: "optional",
        message: "Provider credential reference is not a valid environment variable name.",
        remediation: "Store only environment-variable names in Hermsec config.",
      };
    }
    if (status.present) {
      return {
        id: `provider-env-${provider}`,
        label: `${provider} credential`,
        status: "pass",
        requirement: "optional",
        message: `${status.envName} is set (${status.fingerprint}).`,
      };
    }
    return {
      id: `provider-env-${provider}`,
      label: `${provider} credential`,
      status: "skip",
      requirement: "optional",
      message: `${status.envName} is not set; ${provider} remains disabled until configured.`,
    };
  });
}

function networkPolicyCheck(): DoctorCheck {
  return {
    id: "network-policy",
    label: "Online intelligence",
    status: "pass",
    requirement: "optional",
    message: "Online intel is enabled through deterministic fetchers for CISA KEV, OSV, GitHub Advisory, and NVD when `intel update` or online scans request it.",
  };
}

function schedulerCheck(): DoctorCheck {
  return {
    id: "scheduler",
    label: "Hermsec scheduler",
    status: "pass",
    requirement: "recommended",
    message: "Local schedule storage, manual schedule runs, and watch mode are available. OS-level registration remains an explicit future adapter.",
  };
}

function npmrcEntries(text: string): Map<string, string[]> {
  const entries = new Map<string, string[]>();
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    const match = /^([^=\s]+)\s*=\s*(.*)$/.exec(line);
    if (!match?.[1]) continue;
    const key = match[1].toLowerCase();
    const value = (match[2] ?? "").trim().toLowerCase();
    entries.set(key, [...(entries.get(key) ?? []), value]);
  }
  return entries;
}

function summarize(checks: DoctorCheck[]): DoctorResult["summary"] {
  return {
    pass: checks.filter((check) => check.status === "pass").length,
    warn: checks.filter((check) => check.status === "warn").length,
    fail: checks.filter((check) => check.status === "fail").length,
    skip: checks.filter((check) => check.status === "skip").length,
  };
}

function renderSummary(data: DoctorResult): string {
  const lines = [
    "Hermsec doctor completed.",
    `Checks: ${data.summary.pass} passed, ${data.summary.warn} warnings, ${data.summary.fail} failed, ${data.summary.skip} skipped.`,
    `Config path: ${path.join(data.appDataDir, "config.json")}`,
    `Report directory: ${data.reportDirectory}`,
  ];
  for (const check of data.checks.filter((item) => item.status === "fail" || item.status === "warn")) {
    lines.push(`${check.status.toUpperCase()}: ${check.label} - ${check.message}`);
  }
  return lines.join("\n");
}
