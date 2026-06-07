import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test, { type TestContext } from "node:test";
import { promisify } from "node:util";
import { runSchedule, addSchedule, setScheduleEnabled, updateSchedule } from "../../src/scheduler/cli.js";
import { updateSchedule as updateScheduleRecord } from "../../src/scheduler/schedules.js";
import { setConfigValue } from "../../src/storage/userConfig.js";

const execFileAsync = promisify(execFile);

test("scheduler supports toggle, edit, force run, and git-aware unchanged skips", async (t) => {
  if (!(await hasGit())) {
    t.skip("git is unavailable for scheduler git-aware test");
    return;
  }

  const workspace = await withTempHermsecHome(t);
  const repo = await createGitFixture(workspace);
  const reportDir = path.join(workspace, "reports");

  await setConfigValue({
    cwd: workspace,
    key: "customReportDir",
    value: reportDir,
  });

  const added = await addSchedule({
    cwd: workspace,
    target: repo,
    dailyTime: "09:00",
    mode: "offline",
  });
  if (!added.ok) throw new Error(added.message);
  const schedule = (added.data as { schedule: { id: string } }).schedule;

  const disabled = await setScheduleEnabled({
    cwd: workspace,
    scheduleId: schedule.id,
    enabled: false,
  });
  if (!disabled.ok) throw new Error(disabled.message);
  assert.equal((disabled.data as { schedule: { enabled: boolean } }).schedule.enabled, false);

  const edited = await updateSchedule({
    cwd: workspace,
    scheduleId: schedule.id,
    dailyTime: "10:30",
    enabled: true,
  });
  if (!edited.ok) throw new Error(edited.message);
  assert.equal((edited.data as { schedule: { time: string; enabled: boolean } }).schedule.time, "10:30");
  assert.equal((edited.data as { schedule: { time: string; enabled: boolean } }).schedule.enabled, true);

  const forced = await runSchedule({
    cwd: workspace,
    scheduleId: schedule.id,
    force: true,
  });
  if (!forced.ok) throw new Error(forced.message);
  const forcedData = forced.data as { report?: { htmlPath?: string } };
  assert.ok(forcedData.report?.htmlPath?.startsWith(reportDir));
  await assertFileExists(forcedData.report?.htmlPath);

  await updateScheduleRecord(schedule.id, (current) => ({
    ...current,
    nextRunAt: new Date(Date.now() - 60_000).toISOString(),
  }));

  const skipped = await runSchedule({
    cwd: workspace,
    scheduleId: schedule.id,
  });
  assert.equal(skipped.ok, true);
  assert.match(skipped.message, /skipped|unchanged/i);
});

async function createGitFixture(workspace: string): Promise<string> {
  const repo = path.join(workspace, "repo");
  await fs.mkdir(repo, { recursive: true });
  await fs.writeFile(
    path.join(repo, "server.js"),
    'const secret = "HERMSEC_FAKE_TEST_TOKEN_DO_NOT_USE_SCHEDULER";\nconsole.log(secret);\n',
    "utf8",
  );

  await git(repo, ["init"]);
  await git(repo, ["config", "user.email", "hermsec@example.invalid"]);
  await git(repo, ["config", "user.name", "Hermsec Test"]);
  await git(repo, ["add", "."]);
  await git(repo, ["commit", "-m", "fixture"]);

  return repo;
}

async function hasGit(): Promise<boolean> {
  try {
    await execFileAsync("git", ["--version"]);
    return true;
  } catch {
    return false;
  }
}

async function git(cwd: string, args: string[]): Promise<void> {
  await execFileAsync("git", args, { cwd });
}

async function assertFileExists(filePath: string | undefined): Promise<void> {
  assert.ok(filePath);
  const stat = await fs.stat(filePath);
  assert.equal(stat.isFile(), true);
}

async function withTempHermsecHome(t: TestContext): Promise<string> {
  const previous = process.env.HERMSEC_HOME;
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-scheduler-test-"));
  process.env.HERMSEC_HOME = directory;
  t.after(async () => {
    if (previous === undefined) {
      delete process.env.HERMSEC_HOME;
    } else {
      process.env.HERMSEC_HOME = previous;
    }
    await fs.rm(directory, { recursive: true, force: true });
  });
  return directory;
}
