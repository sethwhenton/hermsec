import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { emitScanProgress, type ScanProgressCallback } from "../core/progress.js";
import type { SourceFile } from "../core/files.js";
import type {
  CanonicalScanAssistMode,
  Finding,
  ScanProgressStatus,
  ScannerStatus,
} from "../shared/types.js";
import { scannerCatalog } from "./catalog.js";
import { parseScannerJson, type ParserContext } from "./parsers.js";
import {
  discoverCommand,
  safeExec,
  type CommandResolution,
  type SafeExecRequest,
  type SafeExecResult,
  type ScannerCommandId,
} from "./process.js";

export type ExternalScannerRuntime = {
  commandResolver?: (command: ScannerCommandId) => CommandResolution | undefined;
  exec?: (request: SafeExecRequest) => Promise<SafeExecResult>;
  timeoutMs?: number;
  maxOutputBytes?: number;
  onProgress?: ScanProgressCallback;
  assistMode?: CanonicalScanAssistMode;
  signal?: AbortSignal;
};

type ScannerDefinition = {
  id: ScannerCommandId;
  label: string;
  shouldRun: (files: readonly SourceFile[]) => boolean;
  build: (context: BuildContext) => Promise<BuildResult>;
};

export type ExternalScannerCatalogEntry = {
  id: ScannerCommandId;
  label: string;
  executable: string;
};

type BuildContext = {
  repoRoot: string;
  files: readonly SourceFile[];
  readText: (file: SourceFile) => Promise<string>;
  resolution: CommandResolution;
  timeoutMs: number;
  maxOutputBytes: number;
};

type BuildResult = {
  executions: ScannerExecution[];
  skipReason?: string;
};

type ScannerExecution = {
  scanner: ScannerCommandId;
  args: string[];
  cwd: string;
  allowedExitCodes: readonly number[];
  parserContext: ParserContext;
  timeoutMs?: number;
  maxOutputBytes?: number;
  outputFile?: string;
  cleanupDir?: string;
};

const DEFAULT_TIMEOUT_MS = 60_000;
const DEFAULT_MAX_OUTPUT_BYTES = 8_000_000;
const SEMGREP_LARGE_REPO_FILE_THRESHOLD = 300;
const SEMGREP_LARGE_REPO_CHUNK_SIZE = 75;
const SEMGREP_LARGE_REPO_TIMEOUT_MS = 90_000;
const LOCKFILES_FOR_OSV = new Set([
  "package-lock.json",
  "npm-shrinkwrap.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "bun.lock",
  "poetry.lock",
  "uv.lock",
  "Pipfile.lock",
  "go.sum",
  "Cargo.lock",
  "composer.lock",
  "Gemfile.lock",
  "packages.lock.json",
]);
const NPM_LOCKFILES = new Set(["package-lock.json", "npm-shrinkwrap.json"]);
const REQUIREMENTS_FILES = new Set(["requirements.txt", "requirements-dev.txt"]);
const COMPOSER_LOCKFILES = new Set(["composer.lock"]);
const CARGO_LOCKFILES = new Set(["Cargo.lock"]);
const GO_MANIFESTS = new Set(["go.mod"]);
const DOTNET_MANIFEST_EXTENSIONS = new Set([".csproj", ".sln"]);
const IAC_LANGUAGES = new Set(["terraform", "yaml"]);
const SEMGREP_LANGUAGES = new Set([
  "javascript",
  "typescript",
  "python",
  "java",
  "jsp",
  "php",
  "go",
  "rust",
  "ruby",
  "c",
  "cpp",
  "csharp",
  "kotlin",
  "swift",
  "dart",
  "html",
  "vue",
  "svelte",
  "terraform",
  "yaml",
]);

const EXTERNAL_SCANNERS: ScannerDefinition[] = [
  {
    id: "semgrep",
    label: "Semgrep",
    shouldRun: (files) => files.some((file) =>
      SEMGREP_LANGUAGES.has(file.language)
    ),
    build: buildSemgrep,
  },
  {
    id: "gitleaks",
    label: "Gitleaks",
    shouldRun: (files) => files.length > 0,
    build: buildGitleaks,
  },
  {
    id: "trufflehog",
    label: "TruffleHog",
    shouldRun: (files) => files.length > 0,
    build: buildTruffleHog,
  },
  {
    id: "trivy",
    label: "Trivy",
    shouldRun: (files) => files.length > 0,
    build: buildTrivy,
  },
  {
    id: "checkov",
    label: "Checkov",
    shouldRun: (files) => files.some((file) => IAC_LANGUAGES.has(file.language) || isDockerOrWorkflow(file.relativePath, file.baseName)),
    build: buildCheckov,
  },
  {
    id: "bandit",
    label: "Bandit",
    shouldRun: (files) => files.some((file) => file.language === "python"),
    build: buildBandit,
  },
  {
    id: "osv-scanner",
    label: "OSV-Scanner",
    shouldRun: (files) => files.some((file) => LOCKFILES_FOR_OSV.has(file.baseName)),
    build: buildOsvScanner,
  },
  {
    id: "pip-audit",
    label: "pip-audit",
    shouldRun: (files) => files.some((file) => REQUIREMENTS_FILES.has(file.baseName)),
    build: buildPipAudit,
  },
  {
    id: "pmg",
    label: "SafeDep PMG npm audit",
    shouldRun: (files) => files.some((file) => NPM_LOCKFILES.has(file.baseName)),
    build: buildPmgAudit,
  },
  {
    id: "retire",
    label: "Retire.js",
    shouldRun: (files) => files.some((file) =>
      file.language === "javascript" ||
      file.language === "typescript" ||
      file.language === "html" ||
      file.baseName === "package.json"
    ),
    build: buildRetire,
  },
  {
    id: "spotbugs",
    label: "FindSecBugs / SpotBugs",
    shouldRun: (files) => files.some((file) => file.language === "java" || file.language === "jsp" || file.language === "kotlin"),
    build: buildSpotBugs,
  },
  {
    id: "dependency-check",
    label: "OWASP Dependency-Check",
    shouldRun: (files) => files.some((file) => file.kind === "manifest" || file.kind === "lockfile"),
    build: buildDependencyCheck,
  },
  {
    id: "psalm",
    label: "Psalm taint analysis",
    shouldRun: (files) => files.some((file) => file.language === "php"),
    build: buildPsalm,
  },
  {
    id: "composer",
    label: "Composer audit",
    shouldRun: (files) => files.some((file) => COMPOSER_LOCKFILES.has(file.baseName)),
    build: buildComposerAudit,
  },
  {
    id: "gosec",
    label: "gosec",
    shouldRun: (files) => files.some((file) => file.language === "go"),
    build: buildGosec,
  },
  {
    id: "govulncheck",
    label: "govulncheck",
    shouldRun: (files) => files.some((file) => GO_MANIFESTS.has(file.baseName)),
    build: buildGovulncheck,
  },
  {
    id: "cargo",
    label: "cargo-audit",
    shouldRun: (files) => files.some((file) => CARGO_LOCKFILES.has(file.baseName)),
    build: buildCargoAudit,
  },
  {
    id: "brakeman",
    label: "Brakeman",
    shouldRun: (files) => files.some((file) => file.language === "ruby") && files.some((file) => file.relativePath === "config/routes.rb" || file.relativePath === "config/application.rb"),
    build: buildBrakeman,
  },
  {
    id: "flawfinder",
    label: "Flawfinder",
    shouldRun: (files) => files.some((file) => file.language === "c" || file.language === "cpp"),
    build: buildFlawfinder,
  },
  {
    id: "cppcheck",
    label: "Cppcheck",
    shouldRun: (files) => files.some((file) => file.language === "c" || file.language === "cpp"),
    build: buildCppcheck,
  },
  {
    id: "dotnet",
    label: ".NET vulnerable packages",
    shouldRun: (files) => files.some((file) => DOTNET_MANIFEST_EXTENSIONS.has(file.extension) || file.baseName === "packages.lock.json"),
    build: buildDotnetVulnerable,
  },
];

export async function runExternalScanners(
  files: SourceFile[],
  readText: (file: SourceFile) => Promise<string>,
  runtime: ExternalScannerRuntime = {},
): Promise<{ findings: Finding[]; statuses: ScannerStatus[] }> {
  const repoRoot = inferRepositoryRoot(files);
  const findings: Finding[] = [];
  const statuses: ScannerStatus[] = [];
  const resolver = runtime.commandResolver ?? discoverCommand;
  const exec = runtime.exec ?? safeExec;
  const timeoutMs = runtime.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxOutputBytes = runtime.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES;
  const enabledScanners = enabledScannerSet();
  const assistMode = runtime.assistMode;

  for (const scanner of EXTERNAL_SCANNERS) {
    if (runtime.signal?.aborted) {
      break;
    }
    if (enabledScanners && !enabledScanners.has(scanner.id)) {
      emitScannerProgress(runtime.onProgress, scanner, "skipped", `${scanner.label} is disabled in the current scanner settings.`, {
        assistMode,
      });
      continue;
    }

    if (!repoRoot || !scanner.shouldRun(files)) {
      const status = skipped(scanner, `${scanner.label} had no matching external scanner inputs.`);
      statuses.push(status);
      emitScannerProgress(runtime.onProgress, scanner, "skipped", status.message, { assistMode });
      continue;
    }

    const resolution = resolver(scanner.id);
    if (!resolution) {
      const status = skipped(scanner, `${scanner.label} was not found on PATH; skipped external scan and kept deterministic Hermsec fallback coverage.`);
      statuses.push(status);
      emitScannerProgress(runtime.onProgress, scanner, "skipped", status.message, { assistMode });
      continue;
    }

    const started = Date.now();
    emitScannerProgress(runtime.onProgress, scanner, "running", `${scanner.label} is preparing a safe command plan.`, {
      assistMode,
    });
    let build: BuildResult;
    try {
      build = await scanner.build({ repoRoot, files, readText, resolution, timeoutMs, maxOutputBytes });
    } catch (error) {
      const status: ScannerStatus = {
        id: `${scanner.id}-run`,
        label: `${scanner.label} scan`,
        status: "failed",
        message: `${scanner.label} could not build a safe command plan: ${error instanceof Error ? error.message : String(error)}`,
        durationMs: Date.now() - started,
      };
      statuses.push(status);
      emitScannerProgress(runtime.onProgress, scanner, "failed", status.message, {
        durationMs: status.durationMs,
        assistMode,
      });
      continue;
    }
    if (build.executions.length === 0) {
      const status: ScannerStatus = {
        id: `${scanner.id}-run`,
        label: `${scanner.label} scan`,
        status: "skipped",
        message: build.skipReason ?? `${scanner.label} had no safe command plan.`,
        durationMs: Date.now() - started,
      };
      statuses.push(status);
      emitScannerProgress(runtime.onProgress, scanner, "skipped", status.message, {
        durationMs: status.durationMs,
        assistMode,
      });
      continue;
    }

    const scannerFindings: Finding[] = [];
    const failures: string[] = [];
    const notes: string[] = [];
    try {
      for (const execution of build.executions) {
        emitScannerProgress(
          runtime.onProgress,
          scanner,
          "running",
          build.executions.length > 1
            ? `${scanner.label} is running chunk ${build.executions.indexOf(execution) + 1} of ${build.executions.length}.`
            : `${scanner.label} is running.`,
          {
            assistMode,
            details: [
              {
                label: "Command plan",
                status: "running",
                value: build.executions.length > 1 ? `${build.executions.indexOf(execution) + 1}/${build.executions.length}` : "1/1",
              },
            ],
          },
        );
        let result: SafeExecResult;
        try {
          result = await exec({
            tool: scanner.id,
            executablePath: resolution.executablePath,
            args: execution.args,
            cwd: execution.cwd,
            timeoutMs: execution.timeoutMs ?? timeoutMs,
            allowedExitCodes: execution.allowedExitCodes,
            maxOutputBytes: execution.maxOutputBytes ?? maxOutputBytes,
            ...(runtime.signal ? { signal: runtime.signal } : {}),
          });
        } catch (error) {
          failures.push(`${scanner.label} execution threw: ${error instanceof Error ? error.message : String(error)}`);
          continue;
        }
        if (result.stdoutTruncated || result.stderrTruncated) {
          notes.push("scanner output was truncated to the configured cap");
        }
        if (result.status === "timed_out") {
          failures.push(`${scanner.label} timed out after ${execution.timeoutMs ?? timeoutMs}ms.`);
          continue;
        }
        if (result.status === "failed") {
          failures.push(result.errorMessage ?? `${scanner.label} failed.`);
          continue;
        }

        const output = await outputForExecution(execution, result);
        const parsed = parseScannerJson(scanner.id, output, execution.parserContext);
        scannerFindings.push(...parsed.findings);
        failures.push(...parsed.errors);
      }
    } finally {
      await cleanupExecutions(build.executions);
    }

    findings.push(...scannerFindings);
    const durationMs = Date.now() - started;
    if (failures.length > 0) {
      const status: ScannerStatus = {
        id: `${scanner.id}-run`,
        label: `${scanner.label} scan`,
        status: "failed",
        message: `${scanner.label} failed without stopping the scan: ${[...failures, ...notes].join(" ")}`,
        durationMs,
      };
      statuses.push(status);
      emitScannerProgress(runtime.onProgress, scanner, "failed", status.message, {
        findingCount: scannerFindings.length,
        durationMs,
        assistMode,
      });
      continue;
    }

    const status: ScannerStatus = {
      id: `${scanner.id}-run`,
      label: `${scanner.label} scan`,
      status: "completed",
      message: `${scanner.label} completed with ${scannerFindings.length} finding${scannerFindings.length === 1 ? "" : "s"}${notes.length > 0 ? ` (${notes.join("; ")})` : ""}.`,
      durationMs,
    };
    statuses.push(status);
    emitScannerProgress(runtime.onProgress, scanner, "completed", status.message, {
      findingCount: scannerFindings.length,
      durationMs,
      assistMode,
    });
  }

  return { findings, statuses };
}

function emitScannerProgress(
  onProgress: ScanProgressCallback | undefined,
  scanner: ScannerDefinition,
  status: ScanProgressStatus,
  message: string,
  options: {
    findingCount?: number | undefined;
    durationMs?: number | undefined;
    assistMode?: CanonicalScanAssistMode | undefined;
    details?: Array<{ id?: string; label: string; status?: ScanProgressStatus; message?: string; value?: string }> | undefined;
  } = {},
): void {
  emitScanProgress(onProgress, {
    id: `${scanner.id}-run`,
    stage: "scanner",
    scannerId: scanner.id,
    label: scanner.label,
    status,
    message,
    ...(options.findingCount !== undefined ? { findingCount: options.findingCount } : {}),
    ...(options.durationMs !== undefined ? { durationMs: options.durationMs } : {}),
    ...(options.assistMode ? { assistMode: options.assistMode } : {}),
    ...(options.details ? { details: options.details } : {}),
  });
}

export function externalScannerCatalog(): ExternalScannerCatalogEntry[] {
  return EXTERNAL_SCANNERS.map((scanner) => {
    const catalogEntry = scannerCatalog.find((item) => scannerIdToCommandId(item.command ?? item.id) === scanner.id);
    return {
      id: scanner.id,
      label: scanner.label,
      executable: catalogEntry?.command ?? scanner.id,
    };
  });
}

function enabledScannerSet(): Set<string> | undefined {
  const raw = process.env.HERMSEC_ENABLED_SCANNERS;
  if (raw === undefined) {
    return new Set(
      scannerCatalog
        .filter((scanner) => scanner.defaultEnabled && scanner.command)
        .map((scanner) => scannerIdToCommandId(scanner.command ?? scanner.id)),
    );
  }
  const configured = raw.trim();
  if (!configured) {
    return new Set();
  }
  const values = configured.split(",").map((value) => value.trim()).filter(Boolean);
  if (values.includes("__none__")) {
    return new Set();
  }
  if (values.includes("all")) {
    return undefined;
  }
  return new Set(values.map(scannerIdToCommandId));
}

function scannerOnlineUpdatesAllowed(): boolean {
  return process.env.HERMSEC_SCANNER_ONLINE_UPDATES !== "false";
}

function scannerIdToCommandId(value: string): string {
  switch (value) {
    case "composer-audit":
      return "composer";
    case "cargo-audit":
      return "cargo";
    case "dotnet-vulnerable":
      return "dotnet";
    case "findsecbugs":
      return "spotbugs";
    default:
      return value;
  }
}

function scannerIdToCatalogId(value: string): string {
  switch (value) {
    case "composer":
      return "composer-audit";
    case "cargo":
      return "cargo-audit";
    case "dotnet":
      return "dotnet-vulnerable";
    case "spotbugs":
      return "findsecbugs";
    default:
      return value;
  }
}

export function inferRepositoryRoot(files: readonly SourceFile[]): string | undefined {
  const roots = files.map(rootFromFile).filter((item): item is string => item !== undefined);
  if (roots.length === 0) {
    return undefined;
  }
  return roots.sort((left, right) => left.length - right.length)[0];
}

async function buildSemgrep(context: BuildContext): Promise<BuildResult> {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-semgrep-"));
  const rulesPath = path.join(tempDir, "rules.yml");
  await fs.writeFile(rulesPath, defaultSemgrepRules(), "utf8");
  const targets = context.files
    .filter((file) => SEMGREP_LANGUAGES.has(file.language))
    .map((file) => file.absolutePath)
    .sort();
  if (targets.length === 0) {
    return { executions: [], skipReason: "Semgrep had no source file targets after filtering." };
  }
  if (targets.length > SEMGREP_LARGE_REPO_FILE_THRESHOLD) {
    return {
      executions: chunks(targets, SEMGREP_LARGE_REPO_CHUNK_SIZE).map((chunk, index) => {
        const outputFile = path.join(tempDir, `semgrep-${index + 1}.json`);
        return {
          scanner: "semgrep",
          args: ["scan", "--config", rulesPath, "--json", "--metrics", "off", "--output", outputFile, ...chunk],
          cwd: context.repoRoot,
          allowedExitCodes: [0, 1],
          parserContext: { repoRoot: context.repoRoot },
          cleanupDir: tempDir,
          outputFile,
          timeoutMs: Math.max(context.timeoutMs, SEMGREP_LARGE_REPO_TIMEOUT_MS),
          maxOutputBytes: Math.max(context.maxOutputBytes, DEFAULT_MAX_OUTPUT_BYTES),
        };
      }),
    };
  }
  const outputFile = path.join(tempDir, "semgrep.json");
  return {
    executions: [{
      scanner: "semgrep",
      args: ["scan", "--config", rulesPath, "--json", "--metrics", "off", "--output", outputFile, ...targets],
      cwd: context.repoRoot,
      allowedExitCodes: [0, 1],
      parserContext: { repoRoot: context.repoRoot },
      outputFile,
      cleanupDir: tempDir,
    }],
  };
}

function chunks<T>(items: readonly T[], size: number): T[][] {
  const result: T[][] = [];
  for (let index = 0; index < items.length; index += size) {
    result.push(items.slice(index, index + size));
  }
  return result;
}

async function buildGitleaks(context: BuildContext): Promise<BuildResult> {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-gitleaks-"));
  const outputFile = path.join(tempDir, "gitleaks.json");
  return {
    executions: [{
      scanner: "gitleaks",
      args: ["dir", context.repoRoot, "--report-format", "json", "--report-path", outputFile, "--no-banner", "--redact"],
      cwd: context.repoRoot,
      allowedExitCodes: [0, 1],
      parserContext: { repoRoot: context.repoRoot },
      outputFile,
      cleanupDir: tempDir,
    }],
  };
}

async function buildTruffleHog(context: BuildContext): Promise<BuildResult> {
  return {
    executions: [{
      scanner: "trufflehog",
      args: ["filesystem", context.repoRoot, "--json", "--no-update", "--no-verification"],
      cwd: context.repoRoot,
      allowedExitCodes: [0, 1, 183],
      parserContext: { repoRoot: context.repoRoot },
      timeoutMs: Math.max(context.timeoutMs, 120_000),
      maxOutputBytes: Math.max(context.maxOutputBytes, DEFAULT_MAX_OUTPUT_BYTES),
    }],
  };
}

async function buildTrivy(context: BuildContext): Promise<BuildResult> {
  const offlineArgs = scannerOnlineUpdatesAllowed() ? [] : ["--skip-db-update", "--skip-java-db-update"];
  return {
    executions: [{
      scanner: "trivy",
      args: [
        "fs",
        ...offlineArgs,
        "--format",
        "json",
        "--quiet",
        "--scanners",
        "vuln,secret,misconfig",
        "--skip-dirs",
        ".git",
        "--skip-dirs",
        "node_modules",
        context.repoRoot,
      ],
      cwd: context.repoRoot,
      allowedExitCodes: [0, 1],
      parserContext: { repoRoot: context.repoRoot },
      timeoutMs: Math.max(context.timeoutMs, 180_000),
      maxOutputBytes: Math.max(context.maxOutputBytes, DEFAULT_MAX_OUTPUT_BYTES),
    }],
  };
}

async function buildCheckov(context: BuildContext): Promise<BuildResult> {
  return {
    executions: [{
      scanner: "checkov",
      args: ["-d", context.repoRoot, "-o", "json", "--quiet", "--skip-download"],
      cwd: context.repoRoot,
      allowedExitCodes: [0, 1],
      parserContext: { repoRoot: context.repoRoot },
      timeoutMs: Math.max(context.timeoutMs, 120_000),
      maxOutputBytes: Math.max(context.maxOutputBytes, DEFAULT_MAX_OUTPUT_BYTES),
    }],
  };
}

async function buildBandit(context: BuildContext): Promise<BuildResult> {
  return {
    executions: [{
      scanner: "bandit",
      args: ["-r", context.repoRoot, "-f", "json", "-x", "node_modules,dist,build,coverage,.venv,venv,__pycache__", "--exit-zero"],
      cwd: context.repoRoot,
      allowedExitCodes: [0],
      parserContext: { repoRoot: context.repoRoot },
    }],
  };
}

async function buildOsvScanner(context: BuildContext): Promise<BuildResult> {
  const lockfiles = context.files.filter((file) => LOCKFILES_FOR_OSV.has(file.baseName));
  return {
    executions: lockfiles.map((file) => ({
      scanner: "osv-scanner",
      args: ["scan", "--format", "json", "-L", file.absolutePath],
      cwd: context.repoRoot,
      allowedExitCodes: [0, 1],
      parserContext: { repoRoot: context.repoRoot, sourcePath: file.absolutePath },
    })),
  };
}

async function buildPipAudit(context: BuildContext): Promise<BuildResult> {
  const requirements = context.files.filter((file) => REQUIREMENTS_FILES.has(file.baseName));
  const pinned: SourceFile[] = [];
  const unpinned: string[] = [];
  for (const file of requirements) {
    const content = await context.readText(file);
    if (requirementsFullyPinned(content)) {
      pinned.push(file);
    } else {
      unpinned.push(file.relativePath);
    }
  }

  if (pinned.length === 0) {
    return {
      executions: [],
      skipReason: unpinned.length > 0
        ? `pip-audit skipped because requirements are not fully pinned: ${unpinned.join(", ")}.`
        : "pip-audit had no requirements files to audit.",
    };
  }

  return {
    executions: pinned.map((file) => ({
      scanner: "pip-audit",
      args: ["-r", file.absolutePath, "--format", "json", "--progress-spinner", "off", "--no-deps", "--disable-pip"],
      cwd: context.repoRoot,
      allowedExitCodes: [0, 1],
      parserContext: { repoRoot: context.repoRoot, sourcePath: file.absolutePath },
    })),
    ...(unpinned.length > 0 ? { skipReason: `Unpinned requirements were skipped: ${unpinned.join(", ")}.` } : {}),
  };
}

async function buildPmgAudit(context: BuildContext): Promise<BuildResult> {
  const lockfiles = context.files.filter((file) => NPM_LOCKFILES.has(file.baseName));
  const packageRoots = [...new Set(lockfiles.map((file) => path.dirname(file.absolutePath)))].sort();
  return {
    executions: packageRoots.map((packageRoot) => ({
      scanner: "pmg",
      args: ["npm", "audit", "--json", "--package-lock-only", "--ignore-scripts=true"],
      cwd: packageRoot,
      allowedExitCodes: [0, 1],
      parserContext: { repoRoot: context.repoRoot, sourcePath: path.join(packageRoot, "package-lock.json") },
    })),
  };
}

async function buildRetire(context: BuildContext): Promise<BuildResult> {
  return {
    executions: [{
      scanner: "retire",
      args: ["--path", context.repoRoot, "--outputformat", "json"],
      cwd: context.repoRoot,
      allowedExitCodes: [0, 1, 13],
      parserContext: { repoRoot: context.repoRoot },
      maxOutputBytes: Math.max(context.maxOutputBytes, DEFAULT_MAX_OUTPUT_BYTES),
    }],
  };
}

async function buildSpotBugs(context: BuildContext): Promise<BuildResult> {
  const candidates = [
    path.join(context.repoRoot, "target", "classes"),
    path.join(context.repoRoot, "build", "classes"),
    path.join(context.repoRoot, "build", "classes", "java", "main"),
    path.join(context.repoRoot, "out", "production"),
  ];
  const classRoots = (await Promise.all(candidates.map(async (candidate) => await isDirectory(candidate) ? candidate : undefined)))
    .filter((candidate): candidate is string => candidate !== undefined)
    .sort();
  if (classRoots.length === 0) {
    return {
      executions: [],
      skipReason: "FindSecBugs/SpotBugs skipped because no compiled class directory was found. HermSec does not build projects automatically.",
    };
  }
  return {
    executions: [{
      scanner: "spotbugs",
      args: ["-textui", "-xml:withMessages", "-effort:max", "-low", ...classRoots],
      cwd: context.repoRoot,
      allowedExitCodes: [0, 1],
      parserContext: { repoRoot: context.repoRoot },
      timeoutMs: Math.max(context.timeoutMs, 120_000),
    }],
  };
}

async function buildDependencyCheck(context: BuildContext): Promise<BuildResult> {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-dependency-check-"));
  const outputFile = path.join(tempDir, "dependency-check-report.json");
  const offlineArgs = scannerOnlineUpdatesAllowed() ? [] : ["--noupdate"];
  return {
    executions: [{
      scanner: "dependency-check",
      args: ["--scan", context.repoRoot, "--format", "JSON", "--out", tempDir, "--disableAssembly", ...offlineArgs],
      cwd: context.repoRoot,
      allowedExitCodes: [0, 1, 14],
      parserContext: { repoRoot: context.repoRoot },
      outputFile,
      cleanupDir: tempDir,
      timeoutMs: Math.max(context.timeoutMs, 180_000),
      maxOutputBytes: Math.max(context.maxOutputBytes, DEFAULT_MAX_OUTPUT_BYTES),
    }],
  };
}

async function buildPsalm(context: BuildContext): Promise<BuildResult> {
  const hasConfig = context.files.some((file) => /^psalm(?:\.xml|\.xml\.dist)?$/i.test(file.baseName));
  if (!hasConfig) {
    return {
      executions: [],
      skipReason: "Psalm taint analysis skipped because no psalm.xml configuration was found.",
    };
  }
  return {
    executions: [{
      scanner: "psalm",
      args: ["--taint-analysis", "--output-format=json", "--no-cache"],
      cwd: context.repoRoot,
      allowedExitCodes: [0, 1, 2],
      parserContext: { repoRoot: context.repoRoot },
      timeoutMs: Math.max(context.timeoutMs, 120_000),
      maxOutputBytes: Math.max(context.maxOutputBytes, DEFAULT_MAX_OUTPUT_BYTES),
    }],
  };
}

async function buildComposerAudit(context: BuildContext): Promise<BuildResult> {
  const roots = [...new Set(context.files.filter((file) => COMPOSER_LOCKFILES.has(file.baseName)).map((file) => path.dirname(file.absolutePath)))].sort();
  return {
    executions: roots.map((root) => ({
      scanner: "composer",
      args: ["audit", "--format=json", "--locked", "--no-interaction"],
      cwd: root,
      allowedExitCodes: [0, 1],
      parserContext: { repoRoot: context.repoRoot, sourcePath: path.join(root, "composer.lock") },
    })),
  };
}

async function buildGosec(context: BuildContext): Promise<BuildResult> {
  return {
    executions: [{
      scanner: "gosec",
      args: ["-fmt=json", "./..."],
      cwd: context.repoRoot,
      allowedExitCodes: [0, 1],
      parserContext: { repoRoot: context.repoRoot },
      timeoutMs: Math.max(context.timeoutMs, 120_000),
      maxOutputBytes: Math.max(context.maxOutputBytes, DEFAULT_MAX_OUTPUT_BYTES),
    }],
  };
}

async function buildGovulncheck(context: BuildContext): Promise<BuildResult> {
  return {
    executions: [{
      scanner: "govulncheck",
      args: ["-json", "./..."],
      cwd: context.repoRoot,
      allowedExitCodes: [0, 1],
      parserContext: { repoRoot: context.repoRoot },
      timeoutMs: Math.max(context.timeoutMs, 120_000),
      maxOutputBytes: Math.max(context.maxOutputBytes, DEFAULT_MAX_OUTPUT_BYTES),
    }],
  };
}

async function buildCargoAudit(context: BuildContext): Promise<BuildResult> {
  const roots = [...new Set(context.files.filter((file) => CARGO_LOCKFILES.has(file.baseName)).map((file) => path.dirname(file.absolutePath)))].sort();
  return {
    executions: roots.map((root) => ({
      scanner: "cargo",
      args: ["audit", "--json"],
      cwd: root,
      allowedExitCodes: [0, 1],
      parserContext: { repoRoot: context.repoRoot, sourcePath: path.join(root, "Cargo.lock") },
      timeoutMs: Math.max(context.timeoutMs, 120_000),
      maxOutputBytes: Math.max(context.maxOutputBytes, DEFAULT_MAX_OUTPUT_BYTES),
    })),
  };
}

async function buildBrakeman(context: BuildContext): Promise<BuildResult> {
  return {
    executions: [{
      scanner: "brakeman",
      args: ["-f", "json", "-q", context.repoRoot],
      cwd: context.repoRoot,
      allowedExitCodes: [0, 1, 3],
      parserContext: { repoRoot: context.repoRoot },
      timeoutMs: Math.max(context.timeoutMs, 120_000),
      maxOutputBytes: Math.max(context.maxOutputBytes, DEFAULT_MAX_OUTPUT_BYTES),
    }],
  };
}

async function buildFlawfinder(context: BuildContext): Promise<BuildResult> {
  return {
    executions: [{
      scanner: "flawfinder",
      args: ["--sarif", "--dataonly", "--quiet", context.repoRoot],
      cwd: context.repoRoot,
      allowedExitCodes: [0, 1],
      parserContext: { repoRoot: context.repoRoot },
      maxOutputBytes: Math.max(context.maxOutputBytes, DEFAULT_MAX_OUTPUT_BYTES),
    }],
  };
}

async function buildCppcheck(context: BuildContext): Promise<BuildResult> {
  const targets = context.files
    .filter((file) => file.language === "c" || file.language === "cpp")
    .map((file) => file.absolutePath)
    .sort();
  if (targets.length === 0) {
    return { executions: [], skipReason: "Cppcheck had no C/C++ source targets." };
  }
  return {
    executions: chunks(targets, 200).map((chunk) => ({
      scanner: "cppcheck",
      args: [
        "--enable=warning,style,performance,portability,information",
        "--template={file}:{line}:{severity}:{id}:{message}",
        "--quiet",
        ...chunk,
      ],
      cwd: context.repoRoot,
      allowedExitCodes: [0, 1],
      parserContext: { repoRoot: context.repoRoot },
      timeoutMs: Math.max(context.timeoutMs, 120_000),
      maxOutputBytes: Math.max(context.maxOutputBytes, DEFAULT_MAX_OUTPUT_BYTES),
    })),
  };
}

async function buildDotnetVulnerable(context: BuildContext): Promise<BuildResult> {
  const projects = context.files.filter((file) => DOTNET_MANIFEST_EXTENSIONS.has(file.extension));
  if (projects.length === 0) {
    return {
      executions: [],
      skipReason: ".NET vulnerable package scan skipped because no .sln or .csproj file was found.",
    };
  }
  return {
    executions: projects.map((file) => ({
      scanner: "dotnet",
      args: ["list", file.absolutePath, "package", "--vulnerable", "--include-transitive", "--format", "json"],
      cwd: context.repoRoot,
      allowedExitCodes: [0, 1],
      parserContext: { repoRoot: context.repoRoot, sourcePath: file.absolutePath },
      timeoutMs: Math.max(context.timeoutMs, 120_000),
      maxOutputBytes: Math.max(context.maxOutputBytes, DEFAULT_MAX_OUTPUT_BYTES),
    })),
  };
}

async function outputForExecution(execution: ScannerExecution, result: SafeExecResult): Promise<string> {
  if (execution.outputFile) {
    try {
      const fromFile = await fs.readFile(execution.outputFile, "utf8");
      if (fromFile.trim()) {
        return fromFile;
      }
    } catch {
      // Some test doubles and older scanner versions emit JSON to stdout instead.
    }
  }
  if (execution.scanner === "cppcheck" && result.stderr.trim()) {
    return result.stdout.trim() ? `${result.stdout}\n${result.stderr}` : result.stderr;
  }
  return result.stdout;
}

async function cleanupExecutions(executions: readonly ScannerExecution[]): Promise<void> {
  const dirs = new Set(executions.map((execution) => execution.cleanupDir).filter((dir): dir is string => dir !== undefined));
  for (const dir of dirs) {
    await fs.rm(dir, { recursive: true, force: true });
  }
}

function skipped(scanner: ScannerDefinition, message: string): ScannerStatus {
  return {
    id: `${scanner.id}-run`,
    label: `${scanner.label} scan`,
    status: "skipped",
    message,
  };
}

function isDockerOrWorkflow(relativePath: string, baseName: string): boolean {
  const lower = relativePath.toLowerCase();
  return (
    baseName === "Dockerfile" ||
    lower.endsWith("docker-compose.yml") ||
    lower.endsWith("docker-compose.yaml") ||
    lower.includes(".github/workflows/") ||
    lower.includes("/k8s/") ||
    lower.includes("/kubernetes/")
  );
}

async function isDirectory(candidate: string): Promise<boolean> {
  try {
    const stats = await fs.stat(candidate);
    return stats.isDirectory();
  } catch {
    return false;
  }
}

function rootFromFile(file: SourceFile): string | undefined {
  const absolutePath = path.resolve(file.absolutePath);
  const relativePath = path.normalize(file.relativePath);
  if (!relativePath || relativePath === ".") {
    return path.dirname(absolutePath);
  }
  const absoluteLower = absolutePath.toLowerCase();
  const relativeLower = relativePath.toLowerCase();
  if (absoluteLower.endsWith(relativeLower)) {
    const root = absolutePath.slice(0, absolutePath.length - relativePath.length).replace(/[\\/]+$/, "");
    return root || path.parse(absolutePath).root;
  }
  return path.dirname(absolutePath);
}

function requirementsFullyPinned(content: string): boolean {
  const requirements = content.split(/\r?\n/)
    .map((line) => line.replace(/\s+#.*$/, "").trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"));
  if (requirements.length === 0) {
    return false;
  }
  return requirements.every((line) => /^[A-Za-z0-9_.-]+(?:\[[^\]]+\])?==[A-Za-z0-9_.!+\-]+(?:\s*;.+)?$/.test(line));
}

function defaultSemgrepRules(): string {
  return `rules:
  - id: hermsec.javascript.child-process-exec
    message: Shell execution through child_process
    languages: [javascript, typescript]
    severity: ERROR
    metadata:
      cwe: ["CWE-78"]
    pattern-either:
      - pattern: child_process.exec(...)
      - pattern: child_process.execSync(...)
      - pattern: exec(...)
      - pattern: execSync(...)
  - id: hermsec.javascript-eval
    message: Dynamic JavaScript code execution
    languages: [javascript, typescript]
    severity: ERROR
    metadata:
      cwe: ["CWE-95"]
    pattern-either:
      - pattern: eval(...)
      - pattern: new Function(...)
  - id: hermsec.python-subprocess-shell
    message: Python subprocess shell mode enabled
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ["CWE-78"]
    pattern: subprocess.$FUNC(..., shell=True, ...)
  - id: hermsec.python-os-system
    message: Python shell execution with os.system
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ["CWE-78"]
    pattern: os.system(...)
  - id: hermsec.python-dynamic-exec
    message: Dynamic Python code execution
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ["CWE-95"]
    pattern-either:
      - pattern: eval(...)
      - pattern: exec(...)
  - id: hermsec.java-process-exec
    message: Java process execution
    languages: [java]
    severity: ERROR
    metadata:
      cwe: ["CWE-78"]
      category: code
    pattern-either:
      - pattern: Runtime.getRuntime().exec(...)
      - pattern: $R.exec(...)
      - pattern: new ProcessBuilder(...)
  - id: hermsec.java-sql-dynamic
    message: Java SQL execution uses dynamic query construction
    languages: [java]
    severity: ERROR
    metadata:
      cwe: ["CWE-89"]
      category: code
    pattern-either:
      - pattern: |
          $SQL = $A + $B;
          ...
          $STMT.executeQuery($SQL);
      - pattern: |
          $SQL = $A + $B;
          ...
          $CONN.prepareStatement($SQL);
  - id: hermsec.java-xss-writer
    message: Java servlet response writes dynamic content
    languages: [java]
    severity: WARNING
    metadata:
      cwe: ["CWE-79"]
      category: code
    pattern-either:
      - pattern: response.getWriter().println(...)
      - pattern: response.getWriter().print(...)
      - pattern: response.getWriter().write(...)
      - pattern: response.getWriter().format(...)
  - id: hermsec.go-command-exec
    message: Go command execution
    languages: [go]
    severity: ERROR
    metadata:
      cwe: ["CWE-78"]
      category: code
    pattern-either:
      - pattern: exec.Command(...)
      - pattern: exec.CommandContext(...)
  - id: hermsec.php-dynamic-code
    message: PHP dynamic code execution
    languages: [php]
    severity: ERROR
    metadata:
      cwe: ["CWE-95"]
      category: code
    pattern-either:
      - pattern: eval(...)
      - pattern: assert(...)
  - id: hermsec.ruby-shell-exec
    message: Ruby shell command execution
    languages: [ruby]
    severity: ERROR
    metadata:
      cwe: ["CWE-78"]
      category: code
    pattern-either:
      - pattern: system(...)
      - pattern: exec(...)
  - id: hermsec.rust-command-exec
    message: Rust process command construction
    languages: [rust]
    severity: WARNING
    metadata:
      cwe: ["CWE-78"]
      category: code
    pattern: std::process::Command::new(...)
  - id: hermsec.c-dangerous-input
    message: C/C++ dangerous input or copy function
    languages: [c, cpp]
    severity: ERROR
    metadata:
      cwe: ["CWE-120"]
      category: code
    pattern-either:
      - pattern: gets(...)
      - pattern: strcpy(...)
      - pattern: strcat(...)
      - pattern: sprintf(...)
  - id: hermsec.csharp-process-start
    message: .NET process execution
    languages: [csharp]
    severity: ERROR
    metadata:
      cwe: ["CWE-78"]
      category: code
    pattern-either:
      - pattern: Process.Start(...)
      - pattern: System.Diagnostics.Process.Start(...)
`;
}
