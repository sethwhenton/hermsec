import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createCodeInspectionRuntime } from "../../src/agent/codeInspection.js";
import { auditMoaCoverage } from "../../src/agent/coverageAudit.js";
import {
  MOA_ROLES,
  selectMoaRoles,
  type MoaRoleId,
} from "../../src/agent/moaRoles.js";
import { profileProject } from "../../src/agent/projectProfiler.js";

test("MoA Low selects the three roles most relevant to a web application", async () => {
  const repo = await createWebFixture();

  try {
    const runtime = await createCodeInspectionRuntime(repo);
    const profile = await profileProject(runtime);
    const plan = selectMoaRoles(profile, "low");

    assert.deepEqual(
      plan.roles.map((entry) => entry.role.id),
      [
        "injection-and-execution",
        "identity-and-request-security",
        "dependencies-and-supply-chain",
      ],
    );
    assert.ok(profile.capabilities.some((signal) => signal.id === "http-api"));
    assert.ok(profile.capabilities.some((signal) => signal.id === "authentication"));
    assert.ok(profile.capabilities.some((signal) => signal.id === "database"));
    assert.deepEqual(profile.frameworks, ["express"]);
    assert.deepEqual(profile.ecosystems, ["npm"]);
  } finally {
    await fs.rm(repo, { recursive: true, force: true });
  }
});

test("MoA High selects all five specialists in canonical order", async () => {
  const repo = await createWebFixture();

  try {
    const profile = await profileProject(await createCodeInspectionRuntime(repo));
    const plan = selectMoaRoles(profile, "high");

    assert.equal(plan.roles.length, 5);
    assert.deepEqual(
      plan.roles.map((entry) => entry.role.id),
      MOA_ROLES.map((role) => role.id),
    );
  } finally {
    await fs.rm(repo, { recursive: true, force: true });
  }
});

test("empty and signal-free profiles use the canonical role tie-break order", async () => {
  const emptyRepo = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-moa-empty-"));
  const tiedRepo = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-moa-tied-"));

  try {
    await fs.writeFile(path.join(tiedRepo, "notes.txt"), "neutral notes\n", "utf8");
    const emptyPlan = selectMoaRoles(
      await profileProject(await createCodeInspectionRuntime(emptyRepo)),
      "low",
    );
    const tiedPlan = selectMoaRoles(
      await profileProject(await createCodeInspectionRuntime(tiedRepo)),
      "low",
    );
    const expected = [
      "injection-and-execution",
      "identity-and-request-security",
      "sensitive-data-and-cryptography",
    ];

    assert.deepEqual(emptyPlan.roles.map((entry) => entry.role.id), expected);
    assert.deepEqual(tiedPlan.roles.map((entry) => entry.role.id), expected);
    assert.ok(emptyPlan.rankedRoles.every((entry) => entry.score === 0));
    assert.ok(tiedPlan.rankedRoles.every((entry) => entry.score === 0));
  } finally {
    await fs.rm(emptyRepo, { recursive: true, force: true });
    await fs.rm(tiedRepo, { recursive: true, force: true });
  }
});

test("profile truncation distinguishes an exact limit from omitted files", async () => {
  const repo = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-moa-limit-"));

  try {
    await fs.writeFile(path.join(repo, "alpha.js"), "export const alpha = 1;\n", "utf8");
    await fs.writeFile(path.join(repo, "beta.js"), "export const beta = 2;\n", "utf8");
    const exact = await profileProject(
      await createCodeInspectionRuntime(repo),
      { maxFiles: 2 },
    );

    assert.equal(exact.fileSummary.total, 2);
    assert.equal(exact.fileSummary.truncated, false);
    assert.equal(exact.limitations.some((item) => item.includes("file metadata limit")), false);

    await fs.writeFile(path.join(repo, "gamma.js"), "export const gamma = 3;\n", "utf8");
    const truncated = await profileProject(
      await createCodeInspectionRuntime(repo),
      { maxFiles: 2 },
    );

    assert.equal(truncated.fileSummary.total, 2);
    assert.equal(truncated.fileSummary.truncated, true);
    assert.equal(truncated.limitations.some((item) => item.includes("file metadata limit")), true);
  } finally {
    await fs.rm(repo, { recursive: true, force: true });
  }
});

test("role planning and bounded gap-fill recommendations are deterministic", async () => {
  const repo = await createWebFixture();

  try {
    const profile = await profileProject(await createCodeInspectionRuntime(repo));
    const selectedRoleIds: MoaRoleId[] = [
      "injection-and-execution",
      "identity-and-request-security",
      "dependencies-and-supply-chain",
    ];
    const executions = [
      {
        roleId: "dependencies-and-supply-chain" as const,
        status: "completed" as const,
        inspectedFiles: ["package.json", "package-lock.json"],
        coveredCategories: ["dependencies" as const],
      },
      {
        roleId: "identity-and-request-security" as const,
        status: "failed" as const,
        inspectedFiles: [],
        coveredCategories: [],
      },
      {
        roleId: "injection-and-execution" as const,
        status: "partial" as const,
        inspectedFiles: ["src/routes/auth.js"],
        coveredCategories: ["injection" as const],
      },
    ];

    const first = auditMoaCoverage({
      profile,
      selectedRoleIds,
      roleExecutions: executions,
      supportedLanguages: ["javascript"],
      maxGapFillFiles: 2,
      maxGapFillCategories: 1,
    });
    const second = auditMoaCoverage({
      profile,
      selectedRoleIds: [...selectedRoleIds].reverse(),
      roleExecutions: [...executions].reverse(),
      supportedLanguages: ["javascript"],
      maxGapFillFiles: 2,
      maxGapFillCategories: 1,
    });

    assert.deepEqual(second, first);
    assert.equal(first.status, "degraded");
    assert.deepEqual(first.roles.failed, ["identity-and-request-security"]);
    assert.ok(first.categories.missing.includes("request-security"));
    assert.equal(first.gapFill?.bounded, true);
    assert.equal(first.gapFill?.maxAdditionalRounds, 1);
    assert.equal(first.gapFill?.roleId, "identity-and-request-security");
    assert.ok((first.gapFill?.files.length ?? 0) <= 2);
    assert.ok((first.gapFill?.categories.length ?? 0) <= 1);
  } finally {
    await fs.rm(repo, { recursive: true, force: true });
  }
});

test("duplicate role execution records merge conservatively and deterministically", async () => {
  const repo = await createWebFixture();

  try {
    const profile = await profileProject(await createCodeInspectionRuntime(repo));
    const executions = [
      {
        roleId: "injection-and-execution" as const,
        status: "completed" as const,
        inspectedFiles: ["src/routes/auth.js"],
        coveredCategories: ["injection" as const],
      },
      {
        roleId: "injection-and-execution" as const,
        status: "partial" as const,
        inspectedFiles: ["views/profile.html"],
        coveredCategories: ["unsafe-execution" as const],
      },
    ];
    const first = auditMoaCoverage({
      profile,
      selectedRoleIds: ["injection-and-execution"],
      roleExecutions: executions,
    });
    const second = auditMoaCoverage({
      profile,
      selectedRoleIds: ["injection-and-execution"],
      roleExecutions: [...executions].reverse(),
    });

    assert.deepEqual(second, first);
    assert.deepEqual(first.roles.partial, ["injection-and-execution"]);
    assert.deepEqual(first.categories.covered, ["injection", "unsafe-execution"]);
    assert.ok(first.files.inspected.includes("src/routes/auth.js"));
    assert.ok(first.files.inspected.includes("views/profile.html"));
  } finally {
    await fs.rm(repo, { recursive: true, force: true });
  }
});

test("unknown reported files prevent otherwise complete coverage", async () => {
  const repo = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-moa-outside-"));

  try {
    await fs.writeFile(path.join(repo, "app.js"), "export const app = true;\n", "utf8");
    const profile = await profileProject(await createCodeInspectionRuntime(repo));
    const result = auditMoaCoverage({
      profile,
      selectedRoleIds: ["injection-and-execution"],
      roleExecutions: [{
        roleId: "injection-and-execution",
        status: "completed",
        inspectedFiles: ["app.js", "../outside.js"],
        coveredCategories: ["injection", "unsafe-execution"],
      }],
      supportedLanguages: ["javascript"],
    });

    assert.deepEqual(result.files.uninspected, []);
    assert.deepEqual(result.categories.missing, []);
    assert.deepEqual(result.files.unknownReportedFiles, ["../outside.js"]);
    assert.equal(result.status, "degraded");
  } finally {
    await fs.rm(repo, { recursive: true, force: true });
  }
});

test("unselected role claims cannot contribute files or categories", async () => {
  const repo = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-moa-unselected-"));

  try {
    await fs.writeFile(path.join(repo, "app.js"), "export const app = true;\n", "utf8");
    const profile = await profileProject(await createCodeInspectionRuntime(repo));
    const result = auditMoaCoverage({
      profile,
      selectedRoleIds: ["injection-and-execution"],
      roleExecutions: [
        {
          roleId: "injection-and-execution",
          status: "completed",
          inspectedFiles: [],
          coveredCategories: [],
        },
        {
          roleId: "identity-and-request-security",
          status: "completed",
          inspectedFiles: ["app.js"],
          coveredCategories: ["injection", "unsafe-execution"],
        },
      ],
      supportedLanguages: ["javascript"],
    });

    assert.deepEqual(result.files.inspected, []);
    assert.deepEqual(result.files.uninspected, ["app.js"]);
    assert.deepEqual(result.categories.covered, []);
    assert.deepEqual(result.categories.missing, ["injection", "unsafe-execution"]);
    assert.equal(result.status, "partial");
  } finally {
    await fs.rm(repo, { recursive: true, force: true });
  }
});

test("skipped and failed selected roles contribute no coverage and degrade the audit", async () => {
  const repo = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-moa-skipped-"));

  try {
    await fs.writeFile(path.join(repo, "app.js"), "export const app = true;\n", "utf8");
    const profile = await profileProject(await createCodeInspectionRuntime(repo));
    const skipped = auditMoaCoverage({
      profile,
      selectedRoleIds: ["injection-and-execution"],
      roleExecutions: [{
        roleId: "injection-and-execution",
        status: "skipped",
        inspectedFiles: ["app.js"],
        coveredCategories: ["injection", "unsafe-execution"],
      }],
      supportedLanguages: ["javascript"],
    });
    const failed = auditMoaCoverage({
      profile,
      selectedRoleIds: ["injection-and-execution"],
      roleExecutions: [{
        roleId: "injection-and-execution",
        status: "failed",
        inspectedFiles: ["app.js"],
        coveredCategories: ["injection", "unsafe-execution"],
      }],
      supportedLanguages: ["javascript"],
    });

    assert.deepEqual(skipped.roles.skipped, ["injection-and-execution"]);
    assert.deepEqual(failed.roles.failed, ["injection-and-execution"]);
    for (const result of [skipped, failed]) {
      assert.deepEqual(result.files.inspected, []);
      assert.deepEqual(result.files.uninspected, ["app.js"]);
      assert.deepEqual(result.categories.covered, []);
      assert.deepEqual(result.categories.missing, ["injection", "unsafe-execution"]);
      assert.equal(result.status, "degraded");
    }
  } finally {
    await fs.rm(repo, { recursive: true, force: true });
  }
});

async function createWebFixture(): Promise<string> {
  const repo = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-moa-profile-"));
  await fs.mkdir(path.join(repo, "src", "routes"), { recursive: true });
  await fs.mkdir(path.join(repo, "views"), { recursive: true });
  await fs.writeFile(
    path.join(repo, "package.json"),
    JSON.stringify({
      name: "moa-profile-fixture",
      version: "1.0.0",
      dependencies: {
        express: "5.0.0",
        passport: "0.7.0",
        sqlite3: "5.1.7",
      },
    }, null, 2),
    "utf8",
  );
  await fs.writeFile(
    path.join(repo, "package-lock.json"),
    JSON.stringify({
      name: "moa-profile-fixture",
      version: "1.0.0",
      lockfileVersion: 3,
      packages: {},
    }, null, 2),
    "utf8",
  );
  await fs.writeFile(
    path.join(repo, "src", "routes", "auth.js"),
    "export function login(request, response) { response.json({ ok: true }); }\n",
    "utf8",
  );
  await fs.writeFile(
    path.join(repo, "views", "profile.html"),
    "<main>Profile</main>\n",
    "utf8",
  );
  return repo;
}
