import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import type { SourceFile } from "../../../src/core/files.js";
import { inferRepositoryRoot, runExternalScanners } from "../../../src/scanners/external.js";
import { discoverCommand, safeExec, type CommandResolution, type SafeExecRequest, type SafeExecResult, type ScannerCommandId } from "../../../src/scanners/process.js";

test("external scanner suite normalizes mocked real JSON outputs", async () => {
  const repoRoot = path.join(os.tmpdir(), "Hermsec Mock Repo");
  const files = [
    sourceFile(repoRoot, "src/server.js", "javascript", "source"),
    sourceFile(repoRoot, "app.py", "python", "source"),
    sourceFile(repoRoot, "package-lock.json", "json", "lockfile"),
    sourceFile(repoRoot, "requirements.txt", "text", "manifest"),
  ];
  const executed: SafeExecRequest[] = [];
  const result = await withEnabledScanners("semgrep,gitleaks,bandit,osv-scanner,pip-audit,pmg", async () =>
    runExternalScanners(files, readFixtureText, {
      commandResolver: fakeResolver,
      exec: async (request) => {
        executed.push(request);
        return fakeExecResult(request, repoRoot);
      },
      timeoutMs: 1000,
    })
  );

  assert.deepEqual(result.statuses.map((status) => [status.id, status.status]), [
    ["semgrep-run", "completed"],
    ["gitleaks-run", "completed"],
    ["bandit-run", "completed"],
    ["osv-scanner-run", "completed"],
    ["pip-audit-run", "completed"],
    ["pmg-run", "completed"],
  ]);
  assert.deepEqual([...new Set(result.findings.map((finding) => finding.tool))].sort(), [
    "bandit",
    "gitleaks",
    "osv-scanner",
    "pip-audit",
    "pmg",
    "semgrep",
  ]);
  assert.equal(result.findings.some((finding) => finding.cwe?.includes("CWE-78")), true);
  assert.equal(result.findings.some((finding) => finding.identifiers?.cve?.includes("CVE-2021-23337")), true);
  assert.equal(result.findings.some((finding) => finding.evidence.includes("HERMSEC_FAKE_TEST_TOKEN_DO_NOT_USE")), false);

  const pmgRequest = executed.find((request) => request.tool === "pmg");
  assert.ok(pmgRequest);
  assert.deepEqual(pmgRequest.args.slice(0, 2), ["npm", "audit"]);
  assert.equal(pmgRequest.args.some((arg) => ["install", "ci", "fix"].includes(arg)), false);
});

test("external scanner suite records deterministic skipped statuses when binaries are missing", async () => {
  const repoRoot = path.join(os.tmpdir(), "Hermsec Missing Tools Repo");
  const files = [
    sourceFile(repoRoot, "src/server.js", "javascript", "source"),
    sourceFile(repoRoot, "app.py", "python", "source"),
    sourceFile(repoRoot, "package-lock.json", "json", "lockfile"),
    sourceFile(repoRoot, "requirements.txt", "text", "manifest"),
  ];

  const result = await withEnabledScanners("semgrep,gitleaks,bandit,osv-scanner,pip-audit,pmg", async () =>
    runExternalScanners(files, readFixtureText, {
      commandResolver: () => undefined,
    })
  );

  assert.equal(result.findings.length, 0);
  assert.equal(result.statuses.length, 6);
  assert.equal(result.statuses.every((status) => status.status === "skipped"), true);
  assert.equal(result.statuses.every((status) => /not found|missing|no matching/i.test(status.message)), true);
});

test("external scanner selection honors none, explicit, default, and all env modes", async () => {
  const repoRoot = path.join(os.tmpdir(), "Hermsec Scanner Selection Repo");
  const files = [
    sourceFile(repoRoot, "src/server.js", "javascript", "source"),
    sourceFile(repoRoot, "package-lock.json", "json", "lockfile"),
  ];

  const noneExecuted: ScannerCommandId[] = [];
  const none = await withEnabledScanners("__none__", async () =>
    runExternalScanners(files, readFixtureText, {
      commandResolver: fakeResolver,
      exec: async (request) => {
        noneExecuted.push(request.tool);
        return fakeExecResult(request, repoRoot);
      },
    })
  );
  assert.equal(none.statuses.length, 0);
  assert.equal(noneExecuted.length, 0);

  const explicitExecuted: ScannerCommandId[] = [];
  await withEnabledScanners("semgrep,gitleaks", async () =>
    runExternalScanners(files, readFixtureText, {
      commandResolver: fakeResolver,
      exec: async (request) => {
        explicitExecuted.push(request.tool);
        return fakeExecResult(request, repoRoot);
      },
    })
  );
  assert.deepEqual(explicitExecuted.sort(), ["gitleaks", "semgrep"]);

  const defaultExecuted: ScannerCommandId[] = [];
  await withEnabledScanners(undefined, async () =>
    runExternalScanners(files, readFixtureText, {
      commandResolver: fakeResolver,
      exec: async (request) => {
        defaultExecuted.push(request.tool);
        return fakeExecResult(request, repoRoot);
      },
    })
  );
  assert.equal(defaultExecuted.includes("trufflehog"), false);
  assert.equal(defaultExecuted.includes("semgrep"), true);
  assert.equal(defaultExecuted.includes("gitleaks"), true);

  const allExecuted: ScannerCommandId[] = [];
  await withEnabledScanners("all", async () =>
    runExternalScanners(files, readFixtureText, {
      commandResolver: fakeResolver,
      exec: async (request) => {
        allExecuted.push(request.tool);
        return fakeExecResult(request, repoRoot);
      },
    })
  );
  assert.equal(allExecuted.includes("trufflehog"), true);
});

test("external scanner suite fails one malformed scanner without throwing", async () => {
  const repoRoot = path.join(os.tmpdir(), "Hermsec Malformed Scanner Repo");
  const files = [sourceFile(repoRoot, "src/server.js", "javascript", "source")];
  const result = await withEnabledScanners("semgrep", async () =>
    runExternalScanners(files, readFixtureText, {
      commandResolver: (command) => command === "semgrep" ? fakeResolver(command) : undefined,
      exec: async (request) => ({
        tool: request.tool,
        status: "completed",
        exitCode: 0,
        stdout: "{not-json",
        stderr: "",
        durationMs: 1,
        timedOut: false,
        stdoutTruncated: false,
        stderrTruncated: false,
      }),
    })
  );

  const semgrep = result.statuses.find((status) => status.id === "semgrep-run");
  assert.equal(semgrep?.status, "failed");
  assert.match(semgrep?.message ?? "", /invalid JSON/);
  assert.equal(result.findings.length, 0);
});

test("semgrep scanner chunks large Java repositories", async () => {
  const repoRoot = path.join(os.tmpdir(), "Hermsec Large Java Repo");
  const files = Array.from({ length: 301 }, (_, index) =>
    sourceFile(repoRoot, `src/main/java/BenchmarkTest${String(index).padStart(5, "0")}.java`, "java", "source"),
  );
  const executed: SafeExecRequest[] = [];
  const result = await withEnabledScanners("semgrep", async () =>
    runExternalScanners(files, readFixtureText, {
      commandResolver: (command) => command === "semgrep" ? fakeResolver(command) : undefined,
      exec: async (request) => {
        executed.push(request);
        return fakeExecResult(request, repoRoot);
      },
      timeoutMs: 1000,
    })
  );

  const semgrepRequests = executed.filter((request) => request.tool === "semgrep");
  assert.equal(semgrepRequests.length > 1, true);
  assert.equal(semgrepRequests.every((request) => request.timeoutMs >= 90_000), true);
  assert.equal(semgrepRequests.every((request) => request.args.includes("--output")), true);
  assert.equal(result.statuses.find((status) => status.id === "semgrep-run")?.status, "completed");
});

test("command discovery supports PATH and scanner-specific overrides", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermsec-discovery-"));
  try {
    const semgrepPath = path.join(tempDir, process.platform === "win32" ? "semgrep.cmd" : "semgrep");
    fs.writeFileSync(semgrepPath, "", "utf8");
    const env = {
      PATH: tempDir,
      PATHEXT: ".CMD;.EXE",
    } as NodeJS.ProcessEnv;
    const resolved = discoverCommand("semgrep", env);
    assert.equal(resolved?.executablePath, semgrepPath);

    const overridePath = path.join(tempDir, process.platform === "win32" ? "gitleaks.exe" : "gitleaks");
    fs.writeFileSync(overridePath, "", "utf8");
    const override = discoverCommand("gitleaks", {
      ...env,
      HERMSEC_GITLEAKS_BIN: overridePath,
    });
    assert.equal(override?.executablePath, overridePath);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test("safeExec rejects PMG install-like arguments before spawning", async () => {
  const result = await safeExec({
    tool: "pmg",
    executablePath: path.join(os.tmpdir(), process.platform === "win32" ? "pmg.exe" : "pmg"),
    args: ["npm", "install", "left-pad"],
    cwd: process.cwd(),
    timeoutMs: 100,
    allowedExitCodes: [0],
  });

  assert.equal(result.status, "failed");
  assert.match(result.errorMessage ?? "", /only allowed|may not install/i);
});

test("repository root inference handles paths with spaces", () => {
  const repoRoot = path.join(os.tmpdir(), "Hermsec Repo With Spaces");
  assert.equal(inferRepositoryRoot([
    sourceFile(repoRoot, "src/server.js", "javascript", "source"),
    sourceFile(repoRoot, "requirements.txt", "text", "manifest"),
  ]), repoRoot);
});

function fakeResolver(command: ScannerCommandId): CommandResolution {
  return {
    command,
    executablePath: path.join(os.tmpdir(), process.platform === "win32" ? `${command}.exe` : command),
  };
}

function fakeExecResult(request: SafeExecRequest, repoRoot: string): SafeExecResult {
  return {
    tool: request.tool,
    status: "completed",
    exitCode: request.tool === "gitleaks" ? 1 : 0,
    stdout: scannerOutput(request.tool, repoRoot),
    stderr: "",
    durationMs: 1,
    timedOut: false,
    stdoutTruncated: false,
    stderrTruncated: false,
  };
}

function scannerOutput(scanner: ScannerCommandId, repoRoot: string): string {
  switch (scanner) {
    case "semgrep":
      return JSON.stringify({
        results: [{
          check_id: "hermsec.javascript.child-process-exec",
          path: "src/server.js",
          start: { line: 5 },
          end: { line: 5 },
          extra: {
            message: "Shell execution through child_process",
            severity: "ERROR",
            metadata: {
              cwe: ["CWE-78"],
              fix: "Use spawn or execFile with fixed argv arrays.",
            },
          },
        }],
      });
    case "gitleaks":
      return JSON.stringify([{
        RuleID: "generic-api-key",
        Description: "Generic API Key",
        File: "src/server.js",
        StartLine: 2,
        EndLine: 2,
        Secret: "HERMSEC_FAKE_TEST_TOKEN_DO_NOT_USE_123",
        Match: "token=HERMSEC_FAKE_TEST_TOKEN_DO_NOT_USE_123",
      }]);
    case "bandit":
      return JSON.stringify({
        results: [{
          filename: path.join(repoRoot, "app.py"),
          line_number: 3,
          line_range: [3],
          issue_text: "subprocess call with shell=True",
          issue_severity: "HIGH",
          issue_confidence: "HIGH",
          test_id: "B602",
          issue_cwe: { id: 78 },
        }],
      });
    case "osv-scanner":
      return JSON.stringify({
        results: [{
          source: { path: path.join(repoRoot, "package-lock.json"), type: "lockfile" },
          packages: [{
            package: { name: "lodash", version: "4.17.20", ecosystem: "npm" },
            vulnerabilities: [{
              id: "GHSA-35jh-r3h4-6jhm",
              aliases: ["CVE-2021-23337"],
              summary: "Command Injection in lodash",
              database_specific: { severity: "HIGH" },
            }],
          }],
        }],
      });
    case "pip-audit":
      return JSON.stringify({
        dependencies: [{
          name: "django",
          version: "2.2.0",
          vulns: [{
            id: "PYSEC-2021-9",
            aliases: ["CVE-2021-33203"],
            description: "Django vulnerability",
            fix_versions: ["2.2.24"],
          }],
        }],
      });
    case "pmg":
      return JSON.stringify({
        vulnerabilities: {
          lodash: {
            name: "lodash",
            severity: "high",
            via: [{
              source: 1106913,
              name: "lodash",
              dependency: "lodash",
              title: "Prototype Pollution in lodash",
              url: "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
              severity: "high",
              range: "<4.17.21",
            }],
            range: "<4.17.21",
            fixAvailable: { name: "lodash", version: "4.17.21" },
          },
        },
      });
    default:
      return "{}";
  }
}

async function withEnabledScanners<T>(value: string | undefined, run: () => Promise<T>): Promise<T> {
  const previous = process.env.HERMSEC_ENABLED_SCANNERS;
  if (value === undefined) {
    delete process.env.HERMSEC_ENABLED_SCANNERS;
  } else {
    process.env.HERMSEC_ENABLED_SCANNERS = value;
  }
  try {
    return await run();
  } finally {
    if (previous === undefined) {
      delete process.env.HERMSEC_ENABLED_SCANNERS;
    } else {
      process.env.HERMSEC_ENABLED_SCANNERS = previous;
    }
  }
}

async function readFixtureText(file: SourceFile): Promise<string> {
  if (file.baseName === "requirements.txt") {
    return "django==2.2.0\n";
  }
  return "";
}

function sourceFile(
  repoRoot: string,
  relativePath: string,
  language: SourceFile["language"],
  kind: SourceFile["kind"],
): SourceFile {
  return {
    absolutePath: path.join(repoRoot, ...relativePath.split("/")),
    relativePath,
    extension: path.extname(relativePath),
    baseName: path.basename(relativePath),
    size: 1,
    language,
    kind,
  };
}
