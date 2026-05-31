import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { SourceFile } from "../core/files.js";
import type { Finding, ScannerStatus } from "../shared/types.js";
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
  outputFile?: string;
  cleanupDir?: string;
};

const DEFAULT_TIMEOUT_MS = 45_000;
const DEFAULT_MAX_OUTPUT_BYTES = 2_000_000;
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
]);
const NPM_LOCKFILES = new Set(["package-lock.json", "npm-shrinkwrap.json"]);
const REQUIREMENTS_FILES = new Set(["requirements.txt", "requirements-dev.txt"]);

const EXTERNAL_SCANNERS: ScannerDefinition[] = [
  {
    id: "semgrep",
    label: "Semgrep",
    shouldRun: (files) => files.some((file) => file.language === "javascript" || file.language === "typescript" || file.language === "python"),
    build: buildSemgrep,
  },
  {
    id: "gitleaks",
    label: "Gitleaks",
    shouldRun: (files) => files.length > 0,
    build: buildGitleaks,
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

  for (const scanner of EXTERNAL_SCANNERS) {
    if (!repoRoot || !scanner.shouldRun(files)) {
      statuses.push(skipped(scanner, `${scanner.label} had no matching external scanner inputs.`));
      continue;
    }

    const resolution = resolver(scanner.id);
    if (!resolution) {
      statuses.push(skipped(scanner, `${scanner.label} was not found on PATH; skipped external scan and kept deterministic Hermsec fallback coverage.`));
      continue;
    }

    const started = Date.now();
    let build: BuildResult;
    try {
      build = await scanner.build({ repoRoot, files, readText, resolution, timeoutMs, maxOutputBytes });
    } catch (error) {
      statuses.push({
        id: `${scanner.id}-run`,
        label: `${scanner.label} scan`,
        status: "failed",
        message: `${scanner.label} could not build a safe command plan: ${error instanceof Error ? error.message : String(error)}`,
        durationMs: Date.now() - started,
      });
      continue;
    }
    if (build.executions.length === 0) {
      statuses.push({
        id: `${scanner.id}-run`,
        label: `${scanner.label} scan`,
        status: "skipped",
        message: build.skipReason ?? `${scanner.label} had no safe command plan.`,
        durationMs: Date.now() - started,
      });
      continue;
    }

    const scannerFindings: Finding[] = [];
    const failures: string[] = [];
    const notes: string[] = [];
    try {
      for (const execution of build.executions) {
        let result: SafeExecResult;
        try {
          result = await exec({
            tool: scanner.id,
            executablePath: resolution.executablePath,
            args: execution.args,
            cwd: execution.cwd,
            timeoutMs,
            allowedExitCodes: execution.allowedExitCodes,
            maxOutputBytes,
          });
        } catch (error) {
          failures.push(`${scanner.label} execution threw: ${error instanceof Error ? error.message : String(error)}`);
          continue;
        }
        if (result.stdoutTruncated || result.stderrTruncated) {
          notes.push("scanner output was truncated to the configured cap");
        }
        if (result.status === "timed_out") {
          failures.push(`${scanner.label} timed out after ${timeoutMs}ms.`);
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
      statuses.push({
        id: `${scanner.id}-run`,
        label: `${scanner.label} scan`,
        status: "failed",
        message: `${scanner.label} failed without stopping the scan: ${[...failures, ...notes].join(" ")}`,
        durationMs,
      });
      continue;
    }

    statuses.push({
      id: `${scanner.id}-run`,
      label: `${scanner.label} scan`,
      status: "completed",
      message: `${scanner.label} completed with ${scannerFindings.length} finding${scannerFindings.length === 1 ? "" : "s"}${notes.length > 0 ? ` (${notes.join("; ")})` : ""}.`,
      durationMs,
    });
  }

  return { findings, statuses };
}

export function externalScannerCatalog(): ExternalScannerCatalogEntry[] {
  return EXTERNAL_SCANNERS.map((scanner) => ({
    id: scanner.id,
    label: scanner.label,
    executable: scanner.id,
  }));
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
  return {
    executions: [{
      scanner: "semgrep",
      args: ["scan", "--config", rulesPath, "--json", "--metrics", "off", context.repoRoot],
      cwd: context.repoRoot,
      allowedExitCodes: [0, 1],
      parserContext: { repoRoot: context.repoRoot },
      cleanupDir: tempDir,
    }],
  };
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
`;
}
