import assert from "node:assert/strict";
import test from "node:test";
import {
  canonicalScanAssistModes,
  resolveScanAssistMode,
  scanAssistModeLabel,
  scanAssistModeRequiresModel,
  scanAssistModeRunsScanners,
  scanAssistModeSpec,
} from "../../src/core/scanAssistModes.js";

test("canonical assist modes expose the seven research modes in stable order", () => {
  assert.deepEqual(canonicalScanAssistModes, [
    "scanner-only",
    "single-agent",
    "moa-low",
    "moa-high",
    "scanner-single",
    "scanner-moa-low",
    "scanner-moa-high",
  ]);
});

test("legacy assist modes resolve deterministically without changing historical data", () => {
  assert.equal(resolveScanAssistMode(undefined), "scanner-only");
  assert.equal(resolveScanAssistMode("deep-assisted"), "scanner-only");
  assert.equal(resolveScanAssistMode("scanner-model-summary"), "scanner-only");
  assert.equal(resolveScanAssistMode("single-agent-inspection"), "single-agent");
  assert.equal(resolveScanAssistMode("moa-assisted"), "moa-low");
  assert.equal(resolveScanAssistMode("moa-assisted", { legacyMoaLevel: "high" }), "moa-high");
  assert.equal(resolveScanAssistMode("scanner-moa-assisted"), "scanner-moa-low");
  assert.equal(
    resolveScanAssistMode("scanner-moa-assisted", { legacyMoaLevel: "high" }),
    "scanner-moa-high",
  );
});

test("mode specifications make detector behavior explicit", () => {
  assert.equal(scanAssistModeRequiresModel("scanner-only"), false);
  assert.equal(scanAssistModeRunsScanners("scanner-only"), true);
  assert.equal(scanAssistModeRunsScanners("single-agent"), false);
  assert.equal(scanAssistModeRunsScanners("scanner-single"), true);
  assert.deepEqual(scanAssistModeSpec("moa-low").moaLevel, "low");
  assert.deepEqual(scanAssistModeSpec("scanner-moa-high").moaLevel, "high");
  assert.equal(scanAssistModeLabel("scanner-single"), "Scanner + Single");
});
