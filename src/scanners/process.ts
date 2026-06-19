import path from "node:path";
import { spawn } from "node:child_process";
import { findExecutableOnPath } from "../shared/executable.js";

export type ScannerCommandId = "semgrep" | "osv-scanner" | "gitleaks" | "bandit" | "pip-audit" | "pmg";

export type CommandResolution = {
  command: string;
  executablePath: string;
};

export type SafeExecRequest = {
  tool: ScannerCommandId;
  executablePath: string;
  args: string[];
  cwd: string;
  timeoutMs: number;
  allowedExitCodes: readonly number[];
  maxOutputBytes?: number;
  env?: Record<string, string>;
};

export type SafeExecResult = {
  tool: ScannerCommandId;
  status: "completed" | "failed" | "timed_out";
  exitCode?: number;
  stdout: string;
  stderr: string;
  durationMs: number;
  timedOut: boolean;
  stdoutTruncated: boolean;
  stderrTruncated: boolean;
  errorMessage?: string;
};

const DEFAULT_MAX_OUTPUT_BYTES = 2_000_000;
const BANNED_EXECUTABLES = new Set([
  "bash",
  "bun",
  "bunx",
  "cmd",
  "cmd.exe",
  "npx",
  "pnpm",
  "powershell",
  "powershell.exe",
  "pwsh",
  "pwsh.exe",
  "sh",
  "yarn",
]);

const EXPECTED_EXECUTABLE_NAMES: Record<ScannerCommandId, readonly string[]> = {
  semgrep: ["semgrep"],
  "osv-scanner": ["osv-scanner"],
  gitleaks: ["gitleaks"],
  bandit: ["bandit"],
  "pip-audit": ["pip-audit"],
  pmg: ["pmg"],
};

export function discoverCommand(command: ScannerCommandId, env: NodeJS.ProcessEnv = process.env): CommandResolution | undefined {
  const executablePath = findExecutableOnPath(command, env);
  if (executablePath && isExpectedExecutable(command, executablePath)) {
    return { command, executablePath };
  }

  return undefined;
}

export async function safeExec(request: SafeExecRequest): Promise<SafeExecResult> {
  const started = Date.now();
  const maxOutputBytes = request.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES;
  const validationError = validateRequest(request);
  if (validationError) {
    return {
      tool: request.tool,
      status: "failed",
      stdout: "",
      stderr: "",
      durationMs: Date.now() - started,
      timedOut: false,
      stdoutTruncated: false,
      stderrTruncated: false,
      errorMessage: validationError,
    };
  }

  return await new Promise<SafeExecResult>((resolve) => {
    let settled = false;
    let timedOut = false;
    let stdoutTruncated = false;
    let stderrTruncated = false;
    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;

    const child = spawn(request.executablePath, request.args, {
      cwd: request.cwd,
      env: scannerEnv(request.env),
      shell: false,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
      setTimeout(() => child.kill("SIGKILL"), 500).unref();
    }, request.timeoutMs);
    timer.unref();

    child.stdout?.on("data", (chunk: Buffer) => {
      const appendResult = appendCapped(stdoutChunks, stdoutBytes, chunk, maxOutputBytes);
      stdoutBytes = appendResult.bytes;
      stdoutTruncated ||= appendResult.truncated;
    });

    child.stderr?.on("data", (chunk: Buffer) => {
      const appendResult = appendCapped(stderrChunks, stderrBytes, chunk, maxOutputBytes);
      stderrBytes = appendResult.bytes;
      stderrTruncated ||= appendResult.truncated;
    });

    child.on("error", (error) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      resolve({
        tool: request.tool,
        status: "failed",
        stdout: Buffer.concat(stdoutChunks).toString("utf8"),
        stderr: Buffer.concat(stderrChunks).toString("utf8"),
        durationMs: Date.now() - started,
        timedOut,
        stdoutTruncated,
        stderrTruncated,
        errorMessage: error.message,
      });
    });

    child.on("close", (code) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      const exitCode = code ?? undefined;
      const allowed = exitCode !== undefined && request.allowedExitCodes.includes(exitCode);
      resolve({
        tool: request.tool,
        status: timedOut ? "timed_out" : allowed ? "completed" : "failed",
        ...(exitCode !== undefined ? { exitCode } : {}),
        stdout: Buffer.concat(stdoutChunks).toString("utf8"),
        stderr: Buffer.concat(stderrChunks).toString("utf8"),
        durationMs: Date.now() - started,
        timedOut,
        stdoutTruncated,
        stderrTruncated,
        ...(!timedOut && !allowed ? { errorMessage: `${request.tool} exited with code ${exitCode ?? "unknown"}.` } : {}),
      });
    });
  });
}

function appendCapped(chunks: Buffer[], currentBytes: number, chunk: Buffer, maxBytes: number): { bytes: number; truncated: boolean } {
  if (currentBytes >= maxBytes) {
    return { bytes: currentBytes, truncated: true };
  }
  const remaining = maxBytes - currentBytes;
  if (chunk.byteLength <= remaining) {
    chunks.push(chunk);
    return { bytes: currentBytes + chunk.byteLength, truncated: false };
  }
  chunks.push(chunk.subarray(0, remaining));
  return { bytes: maxBytes, truncated: true };
}

function validateRequest(request: SafeExecRequest): string | undefined {
  if (!isExpectedExecutable(request.tool, request.executablePath)) {
    return `${request.tool} executable path does not match the allowlist.`;
  }

  const executableName = path.basename(request.executablePath).toLowerCase();
  if (BANNED_EXECUTABLES.has(executableName) || BANNED_EXECUTABLES.has(stripExecutableExtension(executableName))) {
    return `${executableName} is not allowed as a scanner executable.`;
  }

  if (request.args.some((arg) => arg.includes("\0"))) {
    return "Scanner arguments may not contain NUL bytes.";
  }

  if (request.tool === "pmg") {
    return validatePmgArgs(request.args);
  }

  return undefined;
}

function validatePmgArgs(args: readonly string[]): string | undefined {
  if (args[0] !== "npm" || args[1] !== "audit") {
    return "PMG is only allowed to wrap `npm audit` in Hermsec scans.";
  }
  const lowered = args.map((arg) => arg.toLowerCase());
  if (lowered.some((arg) => ["install", "i", "ci", "add", "run", "exec", "dlx", "x", "fix", "publish"].includes(arg))) {
    return "PMG audit arguments may not install, execute package scripts, publish, or apply fixes.";
  }
  if (lowered.some((arg) => arg === "--force" || arg.startsWith("--force="))) {
    return "PMG audit arguments may not use --force.";
  }
  return undefined;
}

function scannerEnv(extra?: Record<string, string>): NodeJS.ProcessEnv {
  return {
    ...process.env,
    NO_COLOR: "1",
    SEMGREP_SEND_METRICS: "off",
    PMG_DISABLE_TELEMETRY: "true",
    ...extra,
  };
}

function isExpectedExecutable(command: ScannerCommandId, executablePath: string): boolean {
  const stripped = stripExecutableExtension(path.basename(executablePath).toLowerCase());
  return EXPECTED_EXECUTABLE_NAMES[command].includes(stripped);
}

function stripExecutableExtension(value: string): string {
  return value.replace(/\.(?:exe|cmd|bat|com)$/i, "");
}

