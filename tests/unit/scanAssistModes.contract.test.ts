import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { assistModeFrom } from "../../src/core/progress.js";

const coreAssistModes = [
  "scanner-only",
  "single-agent",
  "moa-low",
  "moa-high",
  "scanner-single",
  "scanner-moa-low",
  "scanner-moa-high",
];
const canonicalLabels = [
  "Scanner only",
  "Single agent",
  "MoA Low",
  "MoA High",
  "Scanner + Single",
  "Scanner + MoA Low",
  "Scanner + MoA High",
];

test("scanner-model-summary remains an input alias for scanner-only", () => {
  assert.equal(
    assistModeFrom("scanner-model-summary" as Parameters<typeof assistModeFrom>[0]),
    "scanner-only",
  );
});

test("core scan assist mode union documents the seven canonical modes", async () => {
  const source = await fs.readFile(path.resolve("src/shared/types.ts"), "utf8");

  assert.deepEqual(extractStringUnion(source, "ScanAssistMode"), coreAssistModes);
});

test("renderer types and options expose exactly the seven canonical modes and labels", async () => {
  const typesSource = await fs.readFile(path.resolve("desktop/src/renderer/src/types/scan.ts"), "utf8");
  const optionsSource = await fs.readFile(path.resolve("desktop/src/renderer/src/lib/scanModes.ts"), "utf8");
  const optionsBlock = optionsSource.match(/export\s+const\s+scanModeOptions[\s\S]*?\n\];/)?.[0];
  const optionIds = [...optionsSource.matchAll(/\bid:\s*"([^"]+)"/g)].map((match) => match[1]);
  const optionLabels = [...optionsSource.matchAll(/\blabel:\s*"([^"]+)"/g)].map((match) => match[1]);

  assert.ok(optionsBlock, "missing renderer scan mode options");
  assert.deepEqual(extractStringArray(typesSource, "hermsecCanonicalScanAssistModes"), coreAssistModes);
  assert.deepEqual(optionIds, coreAssistModes);
  assert.deepEqual(optionLabels, canonicalLabels);
  assert.doesNotMatch(optionsBlock, /Deep assisted scan|Single agent inspection|MoA inspection|scanner-model-summary/);
});

test("desktop defaults new settings and automations to scanner-only", async () => {
  const storeSource = await fs.readFile(path.resolve("desktop/src/main/store.ts"), "utf8");
  const defaults = [...storeSource.matchAll(/\bscanMode:\s*"([^"]+)"/g)].map((match) => match[1]);

  assert.deepEqual(defaults.slice(0, 2), ["scanner-only", "scanner-only"]);
});

test("agent settings expose only low and high MoA panels", async () => {
  const settingsSource = await fs.readFile(path.resolve("desktop/src/renderer/src/types/settings.ts"), "utf8");
  const agentsSource = await fs.readFile(path.resolve("desktop/src/renderer/src/components/settings/AgentsSettings.tsx"), "utf8");

  assert.deepEqual(extractStringUnion(settingsSource, "MoAInspectionPresetId"), ["low-panel", "high-panel"]);
  assert.match(agentsSource, /label:\s*"Low panel"/);
  assert.match(agentsSource, /label:\s*"High panel"/);
  assert.doesNotMatch(agentsSource, /Fast quorum|Balanced panel|Deep panel/);
});

test("automation setup surfaces use the shared product scan mode options", async () => {
  const popoverSource = await fs.readFile(path.resolve("desktop/src/renderer/src/components/automation/AutomationPopover.tsx"), "utf8");
  const viewSource = await fs.readFile(path.resolve("desktop/src/renderer/src/components/automation/AutomationsView.tsx"), "utf8");
  const chatSource = await fs.readFile(path.resolve("desktop/src/renderer/src/components/chat/ChatView.tsx"), "utf8");

  assert.match(popoverSource, /<ScanModeSegmentedControl/);
  assert.match(viewSource, /<ScanModeSegmentedControl/);
  assert.match(chatSource, /AUTOMATION_SCAN_MODE_QUESTION_ID/);
  assert.match(chatSource, /options:\s*scanModeOptions\.map/);
});

function extractStringUnion(source: string, typeName: string): string[] {
  const match = source.match(new RegExp(`export\\s+type\\s+${typeName}\\s*=\\s*([^;]+);`));
  const unionSource = match?.[1];
  assert.ok(unionSource, `missing exported ${typeName} union`);
  return [...unionSource.matchAll(/"([^"]+)"/g)].map((item) => {
    assert.ok(item[1]);
    return item[1];
  });
}

function extractStringArray(source: string, variableName: string): string[] {
  const match = source.match(new RegExp(`export\\s+const\\s+${variableName}\\s*=\\s*\\[([\\s\\S]*?)\\]\\s+as\\s+const`));
  const arraySource = match?.[1];
  assert.ok(arraySource, `missing exported ${variableName} array`);
  return [...arraySource.matchAll(/"([^"]+)"/g)].map((item) => {
    assert.ok(item[1]);
    return item[1];
  });
}
