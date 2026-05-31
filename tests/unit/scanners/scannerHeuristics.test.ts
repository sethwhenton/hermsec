import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { scanFile } from "../../../src/scanners/heuristics.js";

const fixturesRoot = path.join(process.cwd(), "tests", "fixtures", "repos");

test("fixture scanner heuristics select expected offline scanner families", () => {
  assert.deepEqual(inferScannerFamilies("node-express-vulnerable"), [
    "gitleaks",
    "npm-audit",
    "osv-scanner",
    "semgrep",
  ]);
  assert.deepEqual(inferScannerFamilies("python-flask-vulnerable"), [
    "bandit",
    "gitleaks",
    "osv-scanner",
    "pip-audit",
    "semgrep",
  ]);
  assert.deepEqual(inferScannerFamilies("node-express-clean"), ["npm-audit", "osv-scanner", "semgrep"]);
  assert.deepEqual(inferScannerFamilies("python-flask-clean"), [
    "bandit",
    "osv-scanner",
    "pip-audit",
    "semgrep",
  ]);
});

test("offline scanner heuristics flag toy vulnerable fixture patterns", () => {
  const nodeSource = fs.readFileSync(
    path.join(fixturesRoot, "node-express-vulnerable", "src", "routes", "search.js"),
    "utf8",
  );
  const findings = scanFile("src/routes/search.js", nodeSource);
  const categories = new Set(findings.map((finding) => finding.category));
  const cwes = new Set(findings.flatMap((finding) => finding.cwe ?? []));

  assert.ok(categories.has("secret"));
  assert.ok(categories.has("code"));
  assert.ok(cwes.has("CWE-78"));
  assert.ok(cwes.has("CWE-89"));
});

test("offline scanner heuristics keep clean fixture noise low", () => {
  const cleanSource = fs.readFileSync(
    path.join(fixturesRoot, "node-express-clean", "src", "routes", "search.js"),
    "utf8",
  );
  const findings = scanFile("src/routes/search.js", cleanSource);
  const highOrCritical = findings.filter((finding) => finding.severity === "high" || finding.severity === "critical");

  assert.deepEqual(highOrCritical, []);
});

test("fixture package files do not define package scripts", () => {
  for (const packagePath of listFiles(fixturesRoot).filter((file) => path.basename(file) === "package.json")) {
    const parsed = JSON.parse(fs.readFileSync(packagePath, "utf8")) as { scripts?: unknown };
    assert.equal(parsed.scripts, undefined, `${packagePath} must not define package scripts`);
  }
});

test("fixture manifests enforce local-only fake-secret governance", () => {
  for (const fixtureDir of fs.readdirSync(fixturesRoot, { withFileTypes: true }).filter((entry) => entry.isDirectory())) {
    const manifestPath = path.join(fixturesRoot, fixtureDir.name, "hermsec-fixture.json");
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as {
      fakeSecretsOnly?: boolean;
      safety?: {
        requiresNetwork?: boolean;
        containsExploitCode?: boolean;
        packageScriptsMustNotRun?: boolean;
        allowedTargets?: string[];
      };
    };

    assert.equal(manifest.fakeSecretsOnly, true, `${fixtureDir.name} must allow fake secrets only`);
    assert.equal(manifest.safety?.requiresNetwork, false, `${fixtureDir.name} must not require network`);
    assert.equal(manifest.safety?.containsExploitCode, false, `${fixtureDir.name} must not contain exploit code`);
    assert.equal(
      manifest.safety?.packageScriptsMustNotRun,
      true,
      `${fixtureDir.name} package scripts must not run`,
    );
    assert.deepEqual(manifest.safety?.allowedTargets, ["localhost", "127.0.0.1"]);
  }
});

function inferScannerFamilies(fixtureId: string): string[] {
  const repoPath = path.join(fixturesRoot, fixtureId);
  const files = listFiles(repoPath);
  const relativeFiles = files.map((file) => path.relative(repoPath, file).replace(/\\/g, "/"));
  const text = files.map((file) => fs.readFileSync(file, "utf8")).join("\n");
  const scanners = new Set<string>();

  if (relativeFiles.some((file) => file.endsWith(".js") || file.endsWith(".ts"))) {
    scanners.add("semgrep");
  }

  if (relativeFiles.some((file) => file.endsWith(".py"))) {
    scanners.add("bandit");
    scanners.add("semgrep");
  }

  if (relativeFiles.includes("package-lock.json")) {
    scanners.add("npm-audit");
    scanners.add("osv-scanner");
  }

  if (relativeFiles.includes("requirements.txt")) {
    scanners.add("pip-audit");
    scanners.add("osv-scanner");
  }

  if (text.includes("HERMSEC_FAKE_TEST_TOKEN_DO_NOT_USE")) {
    scanners.add("gitleaks");
  }

  return [...scanners].sort();
}

function listFiles(root: string): string[] {
  return fs.readdirSync(root, { withFileTypes: true }).flatMap((entry) => {
    const fullPath = path.join(root, entry.name);
    return entry.isDirectory() ? listFiles(fullPath) : [fullPath];
  });
}
