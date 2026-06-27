import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { assistModeFrom } from "../../src/core/progress.js";

const coreAssistModes = ["deep-assisted", "single-agent", "moa-assisted", "scanner-moa-assisted"];
const visibleAssistModes = ["deep-assisted", "single-agent", "moa-assisted", "scanner-moa-assisted"];

test("scanner-model-summary remains a legacy alias for deep-assisted", () => {
  assert.equal(
    assistModeFrom("scanner-model-summary" as Parameters<typeof assistModeFrom>[0]),
    "deep-assisted",
  );
});

test("core scan assist mode union documents the planned product modes only", async () => {
  const source = await fs.readFile(path.resolve("src/shared/types.ts"), "utf8");

  assert.deepEqual(extractStringUnion(source, "ScanAssistMode"), coreAssistModes);
});

test("renderer scan mode options expose only the planned product modes and labels", async () => {
  const source = await fs.readFile(path.resolve("desktop/src/renderer/src/lib/scanModes.ts"), "utf8");
  const optionIds = [...source.matchAll(/\bid:\s*"([^"]+)"/g)].map((match) => match[1]);

  assert.deepEqual(optionIds, visibleAssistModes);
  assert.equal(optionIds.includes("scanner-model-summary"), false);
  assert.match(source, /label:\s*"Deep assisted scan"/);
  assert.match(source, /label:\s*"Single agent inspection"/);
  assert.match(source, /label:\s*"MoA inspection"/);
  assert.match(source, /label:\s*"Scanner \+ MoA inspection"/);
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
