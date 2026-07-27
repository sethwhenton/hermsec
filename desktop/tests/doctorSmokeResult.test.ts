import assert from "node:assert/strict";
import test from "node:test";
import { createPackagedDoctorSmokeResult } from "../src/main/doctorSmokeResult.ts";
import { safeDiagnosticText } from "../src/main/safeDiagnostics.ts";

function resultWith(
  requiredStatus: string,
  scannerStatus: string,
  runtimeReady = true,
) {
  return {
    ok: false,
    runtimeReady,
    status: "blocked" as const,
    groups: [
      {
        id: "required",
        status: requiredStatus,
        message: "required detail",
      },
      {
        id: "scanners",
        status: scannerStatus,
        message: "scanner detail",
      },
      {
        id: "internet",
        status: "fail",
        message: "offline",
      },
      {
        id: "providers",
        status: "fail",
        message: "not configured",
      },
    ],
  };
}

test("packaged Doctor smoke tolerates only connectivity and provider failures", () => {
  const input = resultWith("pass", "pass");
  const normalized = createPackagedDoctorSmokeResult(input);

  assert.equal(normalized.ok, true);
  assert.equal(normalized.status, "attention");
  assert.deepEqual(normalized.groups, input.groups);
});

test("packaged Doctor smoke rejects required runtime failures", () => {
  assert.throws(
    () =>
      createPackagedDoctorSmokeResult(
        resultWith("pass", "pass", false),
      ),
    /packaged CLI runtime is not ready/u,
  );
});

test("packaged Doctor smoke rejects required check failures", () => {
  assert.throws(
    () => createPackagedDoctorSmokeResult(resultWith("fail", "pass")),
    /Required checks are not ready/u,
  );
});

test("packaged Doctor smoke rejects bundled scanner failures", () => {
  assert.throws(
    () => createPackagedDoctorSmokeResult(resultWith("pass", "fail")),
    /Scanner checks are not ready/u,
  );
});

test("packaged Doctor diagnostics redact secrets and bound public log text", () => {
  assert.equal(
    safeDiagnosticText("scanner api_key=example-secret-value-123456"),
    "scanner api_key=[REDACTED]",
  );
  assert.equal(
    safeDiagnosticText(`prefix-${"x".repeat(40)}`, 16),
    `[truncated]\n${"x".repeat(16)}`,
  );
});
