import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";

type ExitPolicy = {
  failedCells: unknown[];
  liveNonSuccessCells: unknown[];
  liveNonSucceededPhysicalModelCalls: unknown[];
  exitCode: number;
};

const policyModule = (await import(
  pathToFileURL(
    path.resolve("scripts/research/experiment-exit-policy.mjs"),
  ).href
)) as {
  classifyExperimentExit(result: unknown): ExitPolicy;
};

function cell(
  status: string,
  terminalStates: string[] = [],
): Record<string, unknown> {
  return {
    status,
    physical: true,
    modelCallTrace: {
      calls: terminalStates.map((terminalState) => ({
        terminalState,
      })),
    },
  };
}

test("live CLI exit policy rejects partial and degraded cells", () => {
  for (const status of ["partial", "degraded"]) {
    const policy = policyModule.classifyExperimentExit({
      execution: "live",
      cells: [cell(status, ["succeeded"])],
    });
    assert.equal(policy.exitCode, 2);
    assert.equal(policy.failedCells.length, 0);
    assert.equal(policy.liveNonSuccessCells.length, 1);
  }
});

test("live CLI exit policy rejects a non-succeeded physical trace", () => {
  const policy = policyModule.classifyExperimentExit({
    execution: "live",
    cells: [cell("success", ["failed", "succeeded"])],
  });
  assert.equal(policy.exitCode, 2);
  assert.equal(policy.liveNonSuccessCells.length, 0);
  assert.equal(policy.liveNonSucceededPhysicalModelCalls.length, 1);
});

test("mock and replay CLI exit behavior remains failed-or-canceled only", () => {
  for (const execution of ["mock", "replay"]) {
    const nonSuccess = policyModule.classifyExperimentExit({
      execution,
      cells: [cell("degraded", ["failed"])],
    });
    assert.equal(nonSuccess.exitCode, 0);
    const failed = policyModule.classifyExperimentExit({
      execution,
      cells: [cell("failed")],
    });
    assert.equal(failed.exitCode, 2);
  }
});
