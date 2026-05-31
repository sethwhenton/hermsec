import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { Readable, Writable } from "node:stream";
import test from "node:test";
import { createCliToolbox } from "../../src/tui/cli.js";
import { formatHelp, formatHistory } from "../../src/tui/format.js";
import { __richTuiTestInternals, RichHermsecTui } from "../../src/tui/RichApp.js";
import type { TuiWorkspace } from "../../src/tui/types.js";

test("TUI help advertises command, session, and history commands", () => {
  const help = formatHelp();

  assert.match(help, /\/commands/);
  assert.match(help, /\/sessions/);
  assert.match(help, /\/history/);
  assert.match(help, /\/settings/);
  assert.match(help, /\/model/);
  assert.match(help, /\/provider/);
});

test("rich TUI falls back safely in non-interactive terminals", async () => {
  const input = Readable.from([]) as Readable & { isTTY?: boolean };
  const chunks: string[] = [];
  const output = new Writable({
    write(chunk, _encoding, callback) {
      chunks.push(String(chunk));
      callback();
    },
  }) as Writable & { columns?: number; isTTY?: boolean };
  input.isTTY = false;
  output.isTTY = false;
  output.columns = 100;

  const app = new RichHermsecTui({ input, output, cwd: process.cwd() });
  const summary = await app.run();

  assert.equal(summary.exitReason, "non-interactive");
  assert.match(chunks.join(""), /rich chatbot UI/);
  assert.doesNotMatch(chunks.join(""), /HERMSEC_FAKE_TEST_TOKEN_DO_NOT_USE/);
});

test("TUI history formatter shows recent transcript messages", () => {
  const history = formatHistory([
    { role: "system", text: "TUI cwd: test", at: "2026-05-31T00:00:00.000Z" },
    { role: "user", text: "/doctor", at: "2026-05-31T00:00:01.000Z" },
    { role: "hermsec", text: "Doctor completed.", at: "2026-05-31T00:00:02.000Z" },
  ], 2);

  assert.doesNotMatch(history, /TUI cwd/);
  assert.match(history, /You/);
  assert.match(history, /Hermsec/);
});

test("rich TUI command palette keeps slash commands navigable", () => {
  const { commandActions, filterCommandActions, formatActionOverlay, resolveAction } = __richTuiTestInternals;
  const actions = commandActions();

  assert.equal(actions.find((action) => action.label === "Provider")?.command, "/provider");
  assert.equal(filterCommandActions("/provid")[0]?.command, "/provider");
  assert.equal(filterCommandActions("/connect")[0]?.command, "/provider");
  assert.equal(resolveAction("/connect", actions)?.command, "/provider");

  const overlay = formatActionOverlay("/", actions, "commands", actions.length - 1);
  assert.match(overlay, /\/exit/);
  assert.match(overlay, /\{yellow-bg\}\/exit/);
});

test("TUI scan adapter uses the real scan harness", async () => {
  const previousHome = process.env.HERMSEC_HOME;
  const hermsecHome = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-tui-scan-"));
  process.env.HERMSEC_HOME = hermsecHome;

  try {
    const fixture = path.resolve("tests/fixtures/repos/node-express-vulnerable");
    const scan = createCliToolbox(process.cwd()).scan;
    assert.ok(scan);

    const result = await scan({
      target: fixture,
      mode: "offline",
      preference: "full",
    });

    if (!result.ok || !result.data) {
      assert.fail(result.message);
    }
    assert.equal(result.data.status, "completed");
    assert.equal(result.data.summary?.critical ?? 0, 1);
    assert.match(result.message, /Scan completed:/);
  } finally {
    if (previousHome === undefined) {
      delete process.env.HERMSEC_HOME;
    } else {
      process.env.HERMSEC_HOME = previousHome;
    }
    await fs.rm(hermsecHome, { recursive: true, force: true });
  }
});

test("TUI session adapter saves and lists session history", async () => {
  const previousHome = process.env.HERMSEC_HOME;
  const hermsecHome = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-tui-session-"));
  process.env.HERMSEC_HOME = hermsecHome;

  try {
    const toolbox = createCliToolbox(process.cwd());
    assert.ok(toolbox.saveSession);
    assert.ok(toolbox.listSessions);

    const saved = await toolbox.saveSession({
      id: "ses-test-session",
      workspaceId: "ws-test",
      title: "Hermsec session - test",
      createdAt: "2026-05-31T00:00:00.000Z",
      updatedAt: "2026-05-31T00:00:03.000Z",
      messages: [
        { role: "system", text: "TUI cwd: test", at: "2026-05-31T00:00:00.000Z" },
        { role: "user", text: "/scan .", at: "2026-05-31T00:00:01.000Z" },
        { role: "hermsec", text: "Scan completed.", at: "2026-05-31T00:00:02.000Z" },
      ],
      discussedScanIds: ["scan-test"],
      discussedFindingIds: [],
      compactSummary: "CRITICAL 1, HIGH 0, MEDIUM 0, LOW 0, INFO 0",
    });

    if (!saved.ok || !saved.data) {
      assert.fail(saved.message);
    }

    const workspace: TuiWorkspace = {
      id: "ws-test",
      name: "test",
      target: process.cwd(),
      sourceKind: "local",
      reportLocation: "custom",
      privacyMode: "local-only",
      modelMode: "none",
      scanPreference: "full",
      createdAt: "2026-05-31T00:00:00.000Z",
    };
    const listed = await toolbox.listSessions(workspace);

    if (!listed.ok || !listed.data) {
      assert.fail(listed.message);
    }

    assert.equal(listed.data.length, 1);
    assert.equal(listed.data[0]?.id, "ses-test-session");
    assert.equal(listed.data[0]?.messageCount, 3);
    assert.deepEqual(listed.data[0]?.discussedScanIds, ["scan-test"]);
  } finally {
    if (previousHome === undefined) {
      delete process.env.HERMSEC_HOME;
    } else {
      process.env.HERMSEC_HOME = previousHome;
    }
    await fs.rm(hermsecHome, { recursive: true, force: true });
  }
});
