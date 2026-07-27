import assert from "node:assert/strict";
import test from "node:test";
import {
  runIdsMatch,
  shouldAcceptRunEvent,
  shouldApplyRunCompletion,
} from "../src/shared/scanRunIsolation.ts";

test("cancel matching requires the exact active run id", () => {
  assert.equal(runIdsMatch("run-a", "run-a"), true);
  assert.equal(runIdsMatch("run-a", "run-b"), false);
  assert.equal(runIdsMatch("run-a", undefined), false);
  assert.equal(runIdsMatch(undefined, "run-a"), false);
});

test("late progress and completion from a predecessor cannot mutate its successor", () => {
  const activeSuccessor = "run-b";
  const terminalPredecessor = "run-a";

  assert.equal(shouldAcceptRunEvent(activeSuccessor, terminalPredecessor, "run-a"), false);
  assert.equal(shouldApplyRunCompletion(activeSuccessor, "run-a"), false);
  assert.equal(shouldAcceptRunEvent(activeSuccessor, terminalPredecessor, "run-b"), true);
  assert.equal(shouldApplyRunCompletion(activeSuccessor, "run-b"), true);
  assert.equal(shouldAcceptRunEvent(activeSuccessor, activeSuccessor, "run-b"), false);
});
