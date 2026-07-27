import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { stripTypeScriptTypes } from "node:module";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  collectModelEnvironmentVariableNames,
  createCliProcessSpec,
  failedScanResultFromCli,
  normalizePackagedDoctorOutcome,
} from "../src/main/cliProcess.ts";

const scanSourcePath = fileURLToPath(new URL("../src/main/scan.ts", import.meta.url));

test("packaged CLI uses Electron as Node and does not depend on PATH node", () => {
  const spec = createCliProcessSpec({
    isPackaged: true,
    electronExecutable: "C:\\Program Files\\Hermsec\\Hermsec.exe",
    platform: "win32",
    args: ["cli.js", "scan"],
    inheritedEnv: { PATH: "C:\\Windows\\System32" },
    includeModel: true,
    modelEnvironmentNames: [],
  });

  assert.equal(spec.executable, "C:\\Program Files\\Hermsec\\Hermsec.exe");
  assert.deepEqual(spec.args, ["cli.js", "scan"]);
  assert.equal(spec.env.ELECTRON_RUN_AS_NODE, "1");
});

test("development CLI preserves the existing system-node behavior", () => {
  const spec = createCliProcessSpec({
    isPackaged: false,
    electronExecutable: "C:\\Hermsec\\electron.exe",
    platform: "win32",
    args: ["cli.js"],
    inheritedEnv: {},
    includeModel: true,
    modelEnvironmentNames: [],
  });

  assert.equal(spec.executable, "node.exe");
  assert.equal(spec.env.ELECTRON_RUN_AS_NODE, undefined);
});

test("packaged Doctor downgrades only missing optional host Git/npm capabilities", () => {
  const hostOnly = normalizePackagedDoctorOutcome({
    ok: false,
    data: {
      checks: [
        { id: "node-version", status: "pass", requirement: "required" },
        { id: "command-git", status: "fail", requirement: "required", message: "missing" },
        { id: "command-npm", status: "fail", requirement: "required", message: "missing" },
        { id: "command-semgrep", status: "pass", requirement: "optional" },
      ],
    },
  }, 1, true);
  assert.equal(hostOnly.ok, true);
  assert.deepEqual(
    hostOnly.outcome.data?.checks?.filter((check) => check.id === "command-git" || check.id === "command-npm")
      .map((check) => [check.id, check.status, check.requirement]),
    [
      ["command-git", "warn", "recommended"],
      ["command-npm", "warn", "recommended"],
    ],
  );

  const scannerFailure = normalizePackagedDoctorOutcome({
    ok: false,
    data: {
      checks: [
        { id: "command-git", status: "fail", requirement: "required" },
        { id: "command-semgrep", status: "fail", requirement: "required" },
      ],
    },
  }, 1, true);
  assert.equal(scannerFailure.ok, false);

  const development = normalizePackagedDoctorOutcome({
    ok: false,
    data: {
      checks: [{ id: "command-npm", status: "fail", requirement: "required" }],
    },
  }, 1, false);
  assert.equal(development.ok, false);
  assert.equal(development.outcome.data?.checks?.[0]?.status, "fail");

  const messageOnly = normalizePackagedDoctorOutcome({
    ok: false,
    errorCode: "DOCTOR_REQUIRED_CHECK_FAILED",
    message: [
      "Hermsec doctor completed.",
      "FAIL: Git - git was not found on PATH.",
      "FAIL: npm - npm was not found on PATH.",
    ].join("\n"),
  }, 1, true);
  assert.equal(messageOnly.ok, true);
  assert.deepEqual(
    messageOnly.outcome.data?.checks?.map((check) => [check.id, check.status, check.requirement]),
    [
      ["command-git", "warn", "recommended"],
      ["command-npm", "warn", "recommended"],
    ],
  );

  const unknownMessageFailure = normalizePackagedDoctorOutcome({
    ok: false,
    errorCode: "DOCTOR_REQUIRED_CHECK_FAILED",
    message: "FAIL: Semgrep - semgrep was not found on PATH.",
  }, 1, true);
  assert.equal(unknownMessageFailure.ok, false);
});

test("scanner-only removes inherited known and configured custom provider variables", () => {
  const modelEnvironmentNames = collectModelEnvironmentVariableNames([
    "HERMSEC_CUSTOM_PROVIDER_TOKEN",
    "  TEAM_MODEL_KEY  ",
    "MIXED_CASE_PROVIDER_KEY",
  ]);
  const spec = createCliProcessSpec({
    isPackaged: true,
    electronExecutable: "Hermsec.exe",
    platform: "win32",
    args: ["cli.js"],
    inheritedEnv: {
      OPENAI_API_KEY: "known-secret",
      HERMSEC_CUSTOM_PROVIDER_TOKEN: "custom-secret",
      TEAM_MODEL_KEY: "team-secret",
      mixed_case_provider_key: "case-insensitive-secret",
      HERMSEC_ENABLED_SCANNERS: "semgrep",
    },
    extraEnv: {
      OPENROUTER_API_KEY: "extra-secret",
      HERMSEC_SCANNER_ONLINE_UPDATES: "true",
    },
    includeModel: false,
    modelEnvironmentNames,
  });

  assert.equal(spec.env.OPENAI_API_KEY, undefined);
  assert.equal(spec.env.OPENROUTER_API_KEY, undefined);
  assert.equal(spec.env.HERMSEC_CUSTOM_PROVIDER_TOKEN, undefined);
  assert.equal(spec.env.TEAM_MODEL_KEY, undefined);
  assert.equal(spec.env.mixed_case_provider_key, undefined);
  assert.equal(spec.env.HERMSEC_ENABLED_SCANNERS, "semgrep");
  assert.equal(spec.env.HERMSEC_SCANNER_ONLINE_UPDATES, "true");
  assert.equal(spec.env.ELECTRON_RUN_AS_NODE, "1");
});

test("packaged execution leases override managed scanner paths from inherited and UI environments", () => {
  const spec = createCliProcessSpec({
    isPackaged: true,
    electronExecutable: "Hermsec.exe",
    platform: "win32",
    args: ["safe-cli.js", "scan"],
    inheritedEnv: {
      HERMSEC_CLI_ROOT: "C:\\Users\\person\\AppData\\managed-cli",
      HERMSEC_SEMGREP_BIN: "C:\\Users\\person\\AppData\\managed-semgrep.exe",
      hermsec_osv_scanner_bin: "C:\\Users\\person\\AppData\\managed-osv.exe",
      NODE_OPTIONS: "--require=C:\\Users\\person\\attacker.js",
      NODE_EXTRA_CA_CERTS: "C:\\Users\\person\\attacker-ca.pem",
    },
    extraEnv: {
      HERMSEC_SEMGREP_BIN: "C:\\Users\\person\\AppData\\ui-semgrep.exe",
      HERMSEC_OSV_SCANNER_BIN: "C:\\Users\\person\\AppData\\ui-osv.exe",
    },
    trustedRuntime: {
      values: {
        HERMSEC_CLI_ROOT: "C:\\Temp\\hermsec-runtime-lease\\hermsec-cli",
        HERMSEC_SEMGREP_BIN: "C:\\Temp\\hermsec-runtime-lease\\runtime-tools\\win32-x64\\bin\\semgrep.exe",
        HERMSEC_OSV_SCANNER_BIN: "C:\\Temp\\hermsec-runtime-lease\\runtime-tools\\win32-x64\\bin\\osv-scanner.exe",
        PATH: "C:\\Temp\\hermsec-runtime-lease\\runtime-tools\\win32-x64\\bin",
        PATHEXT: ".EXE",
      },
      controlledNames: [
        "HERMSEC_CLI_ROOT",
        "HERMSEC_SEMGREP_BIN",
        "HERMSEC_OSV_SCANNER_BIN",
        "PATH",
        "PATHEXT",
        "NODE_OPTIONS",
        "NODE_EXTRA_CA_CERTS",
      ],
    },
    includeModel: false,
    modelEnvironmentNames: [],
  });

  assert.equal(spec.env.HERMSEC_CLI_ROOT, "C:\\Temp\\hermsec-runtime-lease\\hermsec-cli");
  assert.equal(spec.env.HERMSEC_SEMGREP_BIN, "C:\\Temp\\hermsec-runtime-lease\\runtime-tools\\win32-x64\\bin\\semgrep.exe");
  assert.equal(spec.env.HERMSEC_OSV_SCANNER_BIN, "C:\\Temp\\hermsec-runtime-lease\\runtime-tools\\win32-x64\\bin\\osv-scanner.exe");
  assert.equal(spec.env.hermsec_osv_scanner_bin, undefined);
  assert.equal(spec.env.PATH, "C:\\Temp\\hermsec-runtime-lease\\runtime-tools\\win32-x64\\bin");
  assert.equal(spec.env.PATHEXT, ".EXE");
  assert.equal(spec.env.NODE_OPTIONS, undefined);
  assert.equal(spec.env.NODE_EXTRA_CA_CERTS, undefined);
  assert.equal(spec.env.ELECTRON_RUN_AS_NODE, "1");
});

test("nonzero and provider-required CLI outcomes return structured failures", () => {
  const base = {
    runId: "run-1",
    assistMode: "single-agent" as const,
    assistModeLabel: "Single agent",
    targetPath: "C:\\repo",
    reportDir: "C:\\reports",
  };
  const provider = failedScanResultFromCli({
    ...base,
    exitCode: 1,
    outcome: {
      ok: false,
      errorCode: "MODEL_PROVIDER_REQUIRED",
      message: "Single agent requires an enabled model provider.",
      remediation: "Configure a provider.",
    },
  });
  assert.equal(provider?.error, "provider-required");
  assert.equal(provider?.terminalStatus, "failed");
  assert.deepEqual(provider?.degradationReasons, ["Configure a provider."]);

  const nonzero = failedScanResultFromCli({
    ...base,
    exitCode: 2,
    outcome: { ok: true },
  });
  assert.equal(nonzero?.ok, false);
  assert.equal(nonzero?.error, "cli-failed");

  assert.equal(
    failedScanResultFromCli({ ...base, exitCode: 0, outcome: { ok: true } }),
    undefined,
    "the process-level failure guard defers exit-zero payload validation to the scan envelope guard",
  );
});

test("scan flow validates current-run artifacts before report processing and has no prior-report fallback", async () => {
  const source = await fs.readFile(scanSourcePath, "utf8");
  const guard = source.indexOf("const cliFailure = failedScanResultFromCli");
  const envelopeGuard = source.indexOf("const cliSuccess = validateCurrentCliSuccessEnvelope", guard);
  const reportLookup = source.indexOf("const actualReportDir = cliSuccess.reportDir", envelopeGuard);
  const artifactGeneration = source.indexOf("generateReportArtifacts(", guard);

  assert.ok(guard >= 0, "missing failed CLI guard");
  assert.ok(envelopeGuard > guard, "missing current-run success envelope guard");
  assert.ok(reportLookup > envelopeGuard, "report processing must occur after current-run validation");
  assert.ok(artifactGeneration > guard, "artifact generation must occur after the failed CLI guard");
  const guardedSection = source.slice(guard, reportLookup);
  assert.match(guardedSection, /if\s*\(cliFailure\)[\s\S]*return cliFailure;/u);
  assert.match(guardedSection, /if\s*\(!cliSuccess\.ok\)[\s\S]*return invalidSuccessResult;/u);
  assert.doesNotMatch(source, /latestReportDir/u);
  assert.doesNotMatch(guardedSection, /generateReportArtifacts/u);
});

test("incomplete or stale exit-zero output cannot reuse a seeded prior report", async () => {
  const validateCurrentCliSuccessEnvelope = await loadCurrentCliSuccessEnvelopeValidator();
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-stale-report-"));

  try {
    const targetPath = path.join(root, "target");
    const oldReportDir = path.join(root, "project", "old-run");
    const oldHtmlPath = path.join(oldReportDir, "report.html");
    await fs.mkdir(targetPath, { recursive: true });
    await writeBoundReport(oldReportDir, {
      runId: "old-run",
      scanId: "old-scan",
      assistMode: "scanner-only",
    });
    const oldTime = new Date(Date.now() - 60_000);
    await Promise.all([
      fs.utimes(oldHtmlPath, oldTime, oldTime),
      fs.utimes(path.join(oldReportDir, "detector-evidence.json"), oldTime, oldTime),
      fs.utimes(path.join(oldReportDir, "report-document.json"), oldTime, oldTime),
    ]);

    const scanStartedMs = Date.now();
    const base = {
      expectedRunId: "current-run",
      expectedAssistMode: "scanner-only",
      expectedTargetPath: targetPath,
      configuredReportDir: root,
      scanStartedMs,
    } as const;

    for (const outcome of [{}, { ok: true }]) {
      const result = validateCurrentCliSuccessEnvelope({ ...base, outcome });
      assert.equal(result.ok, false);
    }

    const staleResult = validateCurrentCliSuccessEnvelope({
      ...base,
      outcome: successfulOutcome({
        runId: "current-run",
        scanId: "current-scan",
        targetPath,
        htmlPath: oldHtmlPath,
        assistMode: "scanner-only",
      }),
    });
    assert.equal(staleResult.ok, false);
    if (!staleResult.ok) {
      assert.match(staleResult.reason, /not written by the current scan|does not match the active scan run/u);
    }

    const currentReportDir = path.join(root, "project", "current-run");
    const currentHtmlPath = path.join(currentReportDir, "report.html");
    await writeBoundReport(currentReportDir, {
      runId: "current-run",
      scanId: "current-scan",
      assistMode: "scanner-only",
    });
    const currentResult = validateCurrentCliSuccessEnvelope({
      ...base,
      outcome: successfulOutcome({
        runId: "current-run",
        scanId: "current-scan",
        targetPath,
        htmlPath: currentHtmlPath,
        assistMode: "scanner-only",
      }),
    });
    assert.equal(currentResult.ok, true);
    if (currentResult.ok) {
      const [
        actualReport,
        expectedReport,
        actualHtml,
        expectedHtml,
      ] = await Promise.all([
        fs.stat(currentResult.reportDir, { bigint: true }),
        fs.stat(currentReportDir, { bigint: true }),
        fs.stat(currentResult.htmlPath, { bigint: true }),
        fs.stat(currentHtmlPath, { bigint: true }),
      ]);
      assert.deepEqual(
        [actualReport.dev, actualReport.ino],
        [expectedReport.dev, expectedReport.ino],
      );
      assert.deepEqual(
        [actualHtml.dev, actualHtml.ino],
        [expectedHtml.dev, expectedHtml.ino],
      );
    }
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

type EnvelopeValidator = (input: {
  outcome: Record<string, unknown>;
  expectedRunId: string;
  expectedAssistMode: string;
  expectedTargetPath: string;
  configuredReportDir: string;
  scanStartedMs: number;
}) => { ok: true; htmlPath: string; reportDir: string } | { ok: false; reason: string };

async function loadCurrentCliSuccessEnvelopeValidator(): Promise<EnvelopeValidator> {
  const source = await fs.readFile(scanSourcePath, "utf8");
  const startMarker = "// test-contract:start current-cli-success-envelope";
  const endMarker = "// test-contract:end current-cli-success-envelope";
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker);
  assert.ok(start >= 0 && end > start, "current CLI success validator test contract is missing");

  const functionSource = source.slice(start + startMarker.length, end);
  const moduleSource = stripTypeScriptTypes(
    [
      'import { readFileSync, realpathSync, statSync } from "node:fs";',
      'import path from "node:path";',
      functionSource,
    ].join("\n"),
    { mode: "transform" },
  );
  const moduleUrl = `data:text/javascript;base64,${Buffer.from(moduleSource).toString("base64")}#${Date.now()}`;
  const loaded = await import(moduleUrl) as {
    validateCurrentCliSuccessEnvelope: EnvelopeValidator;
  };
  return loaded.validateCurrentCliSuccessEnvelope;
}

async function writeBoundReport(
  reportDir: string,
  input: { runId: string; scanId: string; assistMode: string },
): Promise<void> {
  await fs.mkdir(reportDir, { recursive: true });
  await Promise.all([
    fs.writeFile(path.join(reportDir, "report.html"), "<!doctype html><title>Hermsec</title>", "utf8"),
    fs.writeFile(
      path.join(reportDir, "detector-evidence.json"),
      JSON.stringify({ runId: input.runId, mode: input.assistMode }),
      "utf8",
    ),
    fs.writeFile(
      path.join(reportDir, "report-document.json"),
      JSON.stringify({
        scanId: input.scanId,
        run: { id: input.scanId, assistMode: input.assistMode },
      }),
      "utf8",
    ),
  ]);
}

function successfulOutcome(input: {
  runId: string;
  scanId: string;
  targetPath: string;
  htmlPath: string;
  assistMode: string;
}): Record<string, unknown> {
  return {
    ok: true,
    data: {
      scan: {
        id: input.scanId,
        target: input.targetPath,
        summary: {
          total: 0,
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          info: 0,
        },
      },
      report: { htmlPath: input.htmlPath },
      orchestration: {
        runId: input.runId,
        mode: input.assistMode,
        terminalStatus: "success",
      },
    },
  };
}
