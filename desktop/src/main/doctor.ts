import { spawn } from "node:child_process";
import path from "node:path";
import type {
  DoctorCheck,
  DoctorConnectivityCheck,
  DoctorGroupSummary,
  DoctorProgressEvent,
  DoctorRunResult,
  DoctorStatus,
  DoctorSummary,
} from "../renderer/src/types/doctor";
import type { AppSettings, ProviderConfig } from "../renderer/src/types/settings";
import { findHermsecRoot } from "./scan";
import { readSettings } from "./store";

const CLI_RELATIVE_PATH = path.join("dist", "src", "bin", "hermsec.js");
const MAX_OUTPUT_CHARS = 2_000_000;
const CONNECTIVITY_TIMEOUT_MS = 7_000;
const DOCTOR_CLI_TIMEOUT_MS = 20_000;

type DoctorCliOutcome = {
  ok?: boolean;
  message?: string;
  data?: {
    generatedAt?: string;
    cwd?: string;
    appDataDir?: string;
    reportDirectory?: string;
    checks?: DoctorCheck[];
    summary?: DoctorSummary;
  };
};

type ConnectivityTarget = {
  id: string;
  label: string;
  url: string;
  request?: RequestInit;
  fallback?: {
    label: string;
    url: string;
    request?: RequestInit;
  };
};

type DoctorProgressEmitter = (event: DoctorProgressEvent) => void;

const CONNECTIVITY_TARGETS: ConnectivityTarget[] = [
  {
    id: "github",
    label: "GitHub",
    url: "https://github.com",
    request: { method: "HEAD" },
  },
  {
    id: "npm",
    label: "npm",
    url: "https://registry.npmjs.org/-/ping?write=false",
    request: { method: "GET" },
  },
  {
    id: "osv",
    label: "OSV",
    url: "https://api.osv.dev/v1/query",
    request: {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        package: { ecosystem: "npm", name: "lodash" },
        version: "4.17.20",
      }),
    },
  },
  {
    id: "cisa-kev",
    label: "CISA KEV",
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    request: { method: "HEAD" },
  },
  {
    id: "nvd",
    label: "NVD",
    url: "https://nvd.nist.gov/vuln",
    request: { method: "HEAD" },
  },
];

const SCANNER_IDS = new Set([
  "command-semgrep",
  "command-gitleaks",
  "command-bandit",
  "command-osv-scanner",
  "command-pip-audit",
  "command-pmg",
]);

export async function runDoctor(onProgress?: DoctorProgressEmitter): Promise<DoctorRunResult> {
  const started = Date.now();
  const root = findHermsecRoot();
  const [cli, connectivity] = await Promise.all([
    runDoctorCli(root, onProgress),
    runConnectivityChecks(onProgress),
  ]);

  const settings = readSettings();
  const providerChecks = desktopProviderChecks(settings);
  providerChecks.forEach((check) => emitCheckProgress(onProgress, check));
  const checks = [...(cli.data?.checks ?? []), ...providerChecks];
  const summary = summarizeChecks(checks);
  const groups = buildGroups(checks, connectivity);
  const healthScore = calculateHealthScore(groups);
  const status = resultStatus(groups);

  return {
    ok: Boolean(cli.ok) && status !== "blocked",
    message: cli.message ?? "Hermsec doctor completed.",
    generatedAt: cli.data?.generatedAt ?? new Date().toISOString(),
    durationMs: Date.now() - started,
    cwd: cli.data?.cwd ?? root,
    appDataDir: cli.data?.appDataDir ?? "",
    reportDirectory: cli.data?.reportDirectory ?? "",
    checks,
    summary,
    connectivity,
    groups,
    healthScore,
    status,
  };
}

async function runDoctorCli(
  root: string,
  onProgress?: DoctorProgressEmitter,
): Promise<DoctorCliOutcome> {
  emitProgress(onProgress, {
    id: "doctor-cli",
    groupId: "required",
    label: "Hermsec CLI",
    status: "running",
    requirement: "required",
    message: "Starting Hermsec's scanner readiness command.",
  });

  const cliPath = path.join(root, CLI_RELATIVE_PATH);
  try {
    const outcome = await runNodeCli(root, [cliPath, "doctor", "--json"], DOCTOR_CLI_TIMEOUT_MS);
    if (outcome.timedOut) {
      const message = `Hermsec doctor timed out after ${DOCTOR_CLI_TIMEOUT_MS} ms.`;
      emitProgress(onProgress, {
        id: "doctor-cli",
        groupId: "required",
        label: "Hermsec CLI",
        status: "fail",
        requirement: "required",
        message,
      });
      return failedCliOutcome(root, message);
    }

    const parsed = parseCliJson(outcome.stdout);
    const ok = parsed.ok !== false && outcome.exitCode === 0;
    emitProgress(onProgress, {
      id: "doctor-cli",
      groupId: "required",
      label: "Hermsec CLI",
      status: ok ? "pass" : "warn",
      requirement: "required",
      message: parsed.message ?? (outcome.stderr.trim() || "Hermsec doctor completed."),
    });
    (parsed.data?.checks ?? []).forEach((check) => emitCheckProgress(onProgress, check));
    return {
      ...parsed,
      ok,
      message: parsed.message ?? (outcome.stderr.trim() || "Hermsec doctor completed."),
    };
  } catch (error) {
    const message = `Hermsec doctor could not complete: ${error instanceof Error ? error.message : String(error)}`;
    emitProgress(onProgress, {
      id: "doctor-cli",
      groupId: "required",
      label: "Hermsec CLI",
      status: "fail",
      requirement: "required",
      message,
    });
    return failedCliOutcome(root, message);
  }
}

function runNodeCli(
  cwd: string,
  args: string[],
  timeoutMs: number,
): Promise<{ stdout: string; stderr: string; exitCode: number; timedOut?: boolean }> {
  return new Promise((resolve, reject) => {
    const nodeBinary = process.platform === "win32" ? "node.exe" : "node";
    const child = spawn(nodeBinary, args, {
      cwd,
      env: process.env,
      windowsHide: true,
    });
    let stdout = "";
    let stderr = "";
    let settled = false;
    const timer = windowlessSetTimeout(() => {
      settled = true;
      stderr = collectOutput(`Timed out after ${timeoutMs} ms.`, stderr);
      child.kill();
      resolve({
        stdout,
        stderr,
        exitCode: 124,
        timedOut: true,
      });
    }, timeoutMs);

    child.stdout.on("data", (chunk) => {
      stdout = collectOutput(chunk, stdout);
    });
    child.stderr.on("data", (chunk) => {
      stderr = collectOutput(chunk, stderr);
    });
    child.on("error", (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(error);
    });
    child.on("close", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({
        stdout,
        stderr,
        exitCode: code ?? 1,
      });
    });
  });
}

function failedCliOutcome(root: string, message: string): DoctorCliOutcome {
  const checks: DoctorCheck[] = [
    {
      id: "doctor-cli",
      label: "Hermsec CLI",
      status: "fail",
      requirement: "required",
      message,
      remediation: "Check the local Hermsec build and retry Doctor.",
    },
  ];
  return {
    ok: false,
    message,
    data: {
      generatedAt: new Date().toISOString(),
      cwd: root,
      checks,
      summary: summarizeChecks(checks),
    },
  };
}

function collectOutput(chunk: unknown, current: string): string {
  const next = `${current}${Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk)}`;
  if (next.length > MAX_OUTPUT_CHARS) {
    return next.slice(next.length - MAX_OUTPUT_CHARS);
  }
  return next;
}

function parseCliJson(stdout: string): DoctorCliOutcome {
  const trimmed = stdout.trim();
  if (!trimmed) {
    throw new Error("Hermsec doctor returned no JSON output.");
  }

  try {
    return JSON.parse(trimmed) as DoctorCliOutcome;
  } catch {
    const objectStart = trimmed.indexOf("{");
    const objectEnd = trimmed.lastIndexOf("}");
    if (objectStart >= 0 && objectEnd > objectStart) {
      return JSON.parse(trimmed.slice(objectStart, objectEnd + 1)) as DoctorCliOutcome;
    }
    throw new Error("Hermsec doctor returned output that was not valid JSON.");
  }
}

async function runConnectivityChecks(
  onProgress?: DoctorProgressEmitter,
): Promise<DoctorConnectivityCheck[]> {
  return Promise.all(
    CONNECTIVITY_TARGETS.map(async (target) => {
      emitProgress(onProgress, {
        id: `connectivity-${target.id}`,
        groupId: "internet",
        label: target.label,
        status: "running",
        requirement: "recommended",
        message: `Pinging ${target.label}.`,
      });
      const check = await checkConnectivity(target);
      emitProgress(onProgress, {
        id: `connectivity-${check.id}`,
        groupId: "internet",
        label: check.label,
        status: check.status,
        requirement: "recommended",
        latencyMs: check.latencyMs,
        statusCode: check.statusCode,
        message: check.message,
      });
      return check;
    }),
  );
}

async function checkConnectivity(target: ConnectivityTarget): Promise<DoctorConnectivityCheck> {
  const primary = await requestConnectivityEndpoint(target.url, target.request);
  if (primary.ok) {
    return {
      id: target.id,
      label: target.label,
      url: target.url,
      status: primary.reachable ? "pass" : "warn",
      latencyMs: primary.latencyMs,
      ...(typeof primary.statusCode === "number" ? { statusCode: primary.statusCode } : {}),
      message: primary.reachable
        ? `HTTPS reachable in ${primary.latencyMs} ms with HTTP ${primary.statusCode}.`
        : `Endpoint responded in ${primary.latencyMs} ms with HTTP ${primary.statusCode}.`,
    };
  }

  if (target.fallback) {
    const fallback = await requestConnectivityEndpoint(target.fallback.url, target.fallback.request);
    if (fallback.ok && fallback.reachable) {
      return {
        id: target.id,
        label: target.label,
        url: target.url,
        status: "warn",
        latencyMs: fallback.latencyMs,
        ...(typeof fallback.statusCode === "number" ? { statusCode: fallback.statusCode } : {}),
        message: `${target.label} API did not respond (${primary.message}); ${target.fallback.label} is reachable in ${fallback.latencyMs} ms with HTTP ${fallback.statusCode}.`,
      };
    }
  }

  return {
    id: target.id,
    label: target.label,
    url: target.url,
    status: "fail",
    latencyMs: primary.latencyMs,
    message: primary.message,
  };
}

async function requestConnectivityEndpoint(
  url: string,
  request?: RequestInit,
): Promise<{
  ok: boolean;
  reachable: boolean;
  latencyMs: number;
  statusCode?: number;
  message: string;
}> {
  const started = Date.now();
  const controller = new AbortController();
  const timer = windowlessSetTimeout(() => controller.abort(), CONNECTIVITY_TIMEOUT_MS);

  try {
    const response = await fetch(url, {
      ...request,
      signal: controller.signal,
    });
    const latencyMs = Date.now() - started;
    const reachable = response.ok || response.status < 500;
    return {
      ok: true,
      reachable,
      latencyMs,
      statusCode: response.status,
      message: reachable
        ? `HTTPS reachable in ${latencyMs} ms with HTTP ${response.status}.`
        : `Endpoint responded in ${latencyMs} ms with HTTP ${response.status}.`,
    };
  } catch (error) {
    const latencyMs = Date.now() - started;
    return {
      ok: false,
      reachable: false,
      latencyMs,
      message:
        error instanceof Error && error.name === "AbortError"
          ? `Timed out after ${CONNECTIVITY_TIMEOUT_MS} ms.`
          : `Could not reach endpoint: ${error instanceof Error ? error.message : String(error)}`,
    };
  } finally {
    clearTimeout(timer);
  }
}

function windowlessSetTimeout(callback: () => void, ms: number): NodeJS.Timeout {
  return setTimeout(callback, ms);
}

function emitCheckProgress(onProgress: DoctorProgressEmitter | undefined, check: DoctorCheck): void {
  emitProgress(onProgress, {
    id: check.id,
    groupId: groupIdForCheck(check),
    label: check.label,
    status: check.status,
    requirement: check.requirement,
    message: check.message,
  });
}

function emitProgress(
  onProgress: DoctorProgressEmitter | undefined,
  event: Omit<DoctorProgressEvent, "at">,
): void {
  onProgress?.({
    ...event,
    at: Date.now(),
  });
}

function groupIdForCheck(check: DoctorCheck): DoctorGroupSummary["id"] {
  if (SCANNER_IDS.has(check.id)) return "scanners";
  if (check.id.startsWith("provider-")) return "providers";
  return "required";
}

function buildGroups(
  checks: DoctorCheck[],
  connectivity: DoctorConnectivityCheck[],
): DoctorGroupSummary[] {
  const requiredChecks = checks.filter((check) => check.requirement === "required");
  const scannerChecks = checks.filter((check) => SCANNER_IDS.has(check.id));
  const desktopProviderChecks = checks.filter((check) => check.id.startsWith("provider-desktop-"));
  const providerChecks = desktopProviderChecks.length > 0
    ? desktopProviderChecks
    : checks.filter((check) => check.id.startsWith("provider-env-"));

  return [
    groupFromChecks("required", "Required", requiredChecks, { countSkipsAsMissing: true }),
    groupFromChecks("scanners", "Scanners", scannerChecks, { countSkipsAsMissing: true }),
    groupFromConnectivity(connectivity),
    groupFromChecks("providers", "Providers", providerChecks, { optionalZeroIsOk: true }),
  ];
}

function desktopProviderChecks(settings: AppSettings): DoctorCheck[] {
  const enabledProviders = settings.providers.filter((provider) => provider.enabled);
  if (enabledProviders.length === 0) {
    return [
      {
        id: "provider-desktop-none",
        label: "Desktop model provider",
        status: "skip",
        requirement: "optional",
        message: "No desktop model provider is enabled; scanner-only fallback remains available.",
      },
    ];
  }

  return enabledProviders.map((provider) => desktopProviderCheck(provider, settings.activeProviderId, settings.activeModelId));
}

function desktopProviderCheck(provider: ProviderConfig, activeProviderId?: string, activeModelId?: string): DoctorCheck {
  if (provider.apiFormat === "cursor") {
    const hasKey = Boolean(resolveDesktopProviderApiKey(provider));
    const hasBaseUrl = Boolean(provider.baseUrl?.trim());

    if (!hasBaseUrl) {
      return {
        id: `provider-desktop-${provider.id}`,
        label: `${provider.displayName} integration`,
        status: "warn",
        requirement: "recommended",
        message: `${provider.displayName} is enabled but has no base URL configured.`,
        remediation: "Set the provider base URL in Settings > Providers.",
      };
    }

    if (!hasKey) {
      return {
        id: `provider-desktop-${provider.id}`,
        label: `${provider.displayName} integration`,
        status: "warn",
        requirement: "recommended",
        message: `${provider.displayName} is enabled but no API key is available to the desktop app.`,
        remediation: `Save a local API key or set ${provider.apiKeyEnvVar || "CURSOR_API_KEY"}.`,
      };
    }

    return {
      id: `provider-desktop-${provider.id}`,
      label: `${provider.displayName} integration`,
      status: "pass",
      requirement: "recommended",
      message: `${provider.displayName} is configured; credentials are available to the desktop app.`,
    };
  }

  const model =
    provider.models.find((item) => provider.id === activeProviderId && item.enabled && item.id === activeModelId) ??
    provider.models.find((item) => item.enabled);
  const requiresKey = !providerAllowsNoApiKey(provider);
  const hasKey = Boolean(resolveDesktopProviderApiKey(provider));
  const hasBaseUrl = Boolean(provider.baseUrl?.trim());

  if (!model?.id) {
    return {
      id: `provider-desktop-${provider.id}`,
      label: `${provider.displayName} desktop provider`,
      status: "warn",
      requirement: "recommended",
      message: `${provider.displayName} is enabled but has no enabled model selected.`,
      remediation: "Enable a model in Settings > Models.",
    };
  }

  if (!hasBaseUrl) {
    return {
      id: `provider-desktop-${provider.id}`,
      label: `${provider.displayName} desktop provider`,
      status: "warn",
      requirement: "recommended",
      message: `${provider.displayName} is enabled but has no base URL configured.`,
      remediation: "Set the provider base URL in Settings > Providers.",
    };
  }

  if (requiresKey && !hasKey) {
    return {
      id: `provider-desktop-${provider.id}`,
      label: `${provider.displayName} desktop provider`,
      status: "warn",
      requirement: "recommended",
      message: `${provider.displayName} is enabled but no API key is available to the desktop app.`,
      remediation: `Save a local API key or set ${provider.apiKeyEnvVar || "the provider API key environment variable"}.`,
    };
  }

  return {
    id: `provider-desktop-${provider.id}`,
    label: `${provider.displayName} desktop provider`,
    status: "pass",
    requirement: "recommended",
    message: requiresKey
      ? `${provider.displayName} is configured for ${model.id}; credentials are available to the desktop app.`
      : `${provider.displayName} is configured for ${model.id}; no API key is required.`,
  };
}

function resolveDesktopProviderApiKey(provider: ProviderConfig): string | undefined {
  if (providerAllowsNoApiKey(provider)) return undefined;
  if (provider.apiKey?.trim()) return provider.apiKey.trim();
  const envNames = [
    provider.apiKeyEnvVar,
    provider.id === "opencode-go" ? "OPENCODE_GO_API_KEY" : undefined,
    "HERMSEC_MODEL_API_KEY",
  ].filter((name): name is string => Boolean(name?.trim()));

  for (const envName of Array.from(new Set(envNames))) {
    const value = process.env[envName]?.trim();
    if (value) return value;
  }

  return undefined;
}

function providerAllowsNoApiKey(provider: ProviderConfig): boolean {
  return provider.id === "ollama-local" || provider.presetId === "ollama-local";
}

function groupFromChecks(
  id: DoctorGroupSummary["id"],
  label: string,
  checks: DoctorCheck[],
  options: { countSkipsAsMissing?: boolean; optionalZeroIsOk?: boolean } = {},
): DoctorGroupSummary {
  const total = checks.length;
  const ready = checks.filter((check) => check.status === "pass").length;
  const failed = checks.filter((check) => check.status === "fail").length;
  const warned = checks.filter((check) => check.status === "warn").length;
  const skipped = checks.filter((check) => check.status === "skip").length;
  const skippedMissing = options.countSkipsAsMissing && skipped > 0;
  const optionalEmpty = options.optionalZeroIsOk && ready === 0 && failed === 0 && warned === 0;

  let status: DoctorStatus = "pass";
  if (failed > 0) {
    status = "fail";
  } else if (warned > 0 || skippedMissing) {
    status = "warn";
  } else if (optionalEmpty) {
    status = "skip";
  }

  return {
    id,
    label,
    ready,
    total,
    status,
    message: `${ready}/${total} ready`,
  };
}

function groupFromConnectivity(connectivity: DoctorConnectivityCheck[]): DoctorGroupSummary {
  const total = connectivity.length;
  const ready = connectivity.filter((check) => check.status === "pass").length;
  const failed = connectivity.filter((check) => check.status === "fail").length;
  const warned = connectivity.filter((check) => check.status === "warn").length;
  const status: DoctorStatus = failed > 0 ? "fail" : warned > 0 ? "warn" : "pass";
  return {
    id: "internet",
    label: "Internet",
    ready,
    total,
    status,
    message: `${ready}/${total} reachable`,
  };
}

function summarizeChecks(checks: DoctorCheck[]): DoctorSummary {
  return {
    pass: checks.filter((check) => check.status === "pass").length,
    warn: checks.filter((check) => check.status === "warn").length,
    fail: checks.filter((check) => check.status === "fail").length,
    skip: checks.filter((check) => check.status === "skip").length,
  };
}

function calculateHealthScore(groups: DoctorGroupSummary[]): number {
  const required = ratio(groups.find((group) => group.id === "required"));
  const scanners = ratio(groups.find((group) => group.id === "scanners"));
  const internet = ratio(groups.find((group) => group.id === "internet"));
  const providers = providerScore(groups.find((group) => group.id === "providers"));
  return Math.round(required * 40 + scanners * 30 + internet * 20 + providers * 10);
}

function ratio(group?: DoctorGroupSummary): number {
  if (!group || group.total === 0) return 1;
  const penalty = group.status === "warn" ? 0.08 : group.status === "fail" ? 0.18 : 0;
  return Math.max(0, Math.min(1, group.ready / group.total - penalty));
}

function providerScore(group?: DoctorGroupSummary): number {
  if (!group) return 1;
  return group.status === "fail" ? 0.5 : 1;
}

function resultStatus(groups: DoctorGroupSummary[]): DoctorRunResult["status"] {
  const required = groups.find((group) => group.id === "required");
  const internet = groups.find((group) => group.id === "internet");
  if (required?.status === "fail" || internet?.status === "fail") return "blocked";
  if (groups.some((group) => group.status === "warn" || group.status === "fail")) {
    return "attention";
  }
  return "ready";
}
