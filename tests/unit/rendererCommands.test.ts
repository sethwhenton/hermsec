import assert from "node:assert/strict";
import test from "node:test";
import { parseComposerCommand } from "../../src/renderer/commandLogic.js";

test("renderer command parser recognizes Hermsec slash commands", () => {
  assert.deepEqual(parseComposerCommand("/scan tests/fixture"), { command: "scan", args: "tests/fixture" });
  assert.deepEqual(parseComposerCommand("/commands"), { command: "help", args: "" });
  assert.deepEqual(parseComposerCommand("hello"), undefined);
});
