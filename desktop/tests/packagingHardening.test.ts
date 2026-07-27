import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import {
  assertPackagedDoctorResult,
  assertPortablePythonRuntime,
  createPackagedSmokeEnvironment,
  parseDoctorSmokeResultArtifact,
  parseDoctorSmokeOutput,
} from "../scripts/smoke-packaged-runtime.mjs";
import {
  assertPortablePythonTarget,
  assertRelativePythonLauncher,
  assertRuntimeProvenance,
  assertWindowsBinaryLauncher,
  createPortableRuntimeSmokeEnvironment,
  relativePythonLauncherContent,
  smokeRelocatedPortableRuntimeTree,
} from "../scripts/runtime-python-layout.mjs";
import {
  loadPythonLockConfiguration,
  PYTHON_LOCK_TARGETS,
  validateFullyHashedRequirements,
} from "../scripts/runtime-locks.mjs";
import {
  createBundledResourceIntegrityAnchor,
  createVerifiedBundleExecutionLease,
  verifyBundledResourceIntegrity,
} from "../src/main/bundledRuntimeIntegrity.ts";
import { writeBundledIntegrityAnchor } from "../scripts/prepare-bundled-integrity-anchor.mjs";

const desktopRoot = path.resolve(import.meta.dirname, "..");
const repoRoot = path.resolve(desktopRoot, "..");

test("Doctor reuses the packaged CLI launcher and never selects PATH node itself", async () => {
  const source = await fs.readFile(path.join(desktopRoot, "src/main/doctor.ts"), "utf8");
  const launcherSource = await fs.readFile(path.join(desktopRoot, "src/main/cliProcess.ts"), "utf8");
  assert.match(source, /createCliProcessSpec\(\{/u);
  assert.match(source, /isPackaged:\s*app\.isPackaged/u);
  assert.match(source, /electronExecutable:\s*process\.execPath/u);
  assert.match(launcherSource, /env\.ELECTRON_RUN_AS_NODE\s*=\s*"1"/u, "Doctor must use the shared launcher that enables Electron-as-Node.");
  assert.doesNotMatch(source, /const\s+nodeBinary\s*=/u);
});

test("CLI bundling refuses missing dependencies instead of running hidden npm ci", async () => {
  const source = await fs.readFile(path.join(desktopRoot, "scripts/prepare-cli-bundle.mjs"), "utf8");
  assert.match(source, /packaging never installs them automatically/u);
  assert.match(source, /pmg npm ci --ignore-scripts/u);
  assert.match(source, /runNode\(\[rootTsc, "-p", resolve\(root, "tsconfig\.json"\)\], root\)/u);
  assert.match(source, /spawnSync\(process\.execPath, args,/u);
  assert.doesNotMatch(source, /\["ci"\]/u);
  assert.doesNotMatch(source, /npm run build:core/u);
  assert.doesNotMatch(source, /ComSpec|cmd\.exe|commandArgs/u);
});

test("runtime assets include source-pinned portable Python for every release target", async () => {
  const manifestPath = path.join(desktopRoot, "scripts/runtime-asset-checksums.json");
  const manifest = JSON.parse(await fs.readFile(manifestPath, "utf8")) as {
    schemaVersion: number;
    assets: Array<{ tool: string; version: string; asset: string; url: string; sha256: string }>;
  };
  assert.equal(manifest.schemaVersion, 2);
  assert.equal(manifest.assets.length, 20);

  for (const asset of manifest.assets) {
    assert.match(asset.url, new RegExp(`/releases/download/${asset.version.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")}/`));
    assert.match(asset.sha256, /^[a-f0-9]{64}$/u);
    assert.equal(decodeURIComponent(new URL(asset.url).pathname).endsWith(`/${asset.asset}`), true);
  }

  const portablePython = manifest.assets.filter((asset) => asset.tool === "python-build-standalone");
  assert.deepEqual(
    portablePython.map((asset) => asset.asset).sort(),
    [
      "cpython-3.12.11+20250612-aarch64-apple-darwin-install_only_stripped.tar.gz",
      "cpython-3.12.11+20250612-x86_64-apple-darwin-install_only_stripped.tar.gz",
      "cpython-3.12.11+20250612-x86_64-pc-windows-msvc-install_only_stripped.tar.gz",
      "cpython-3.12.11+20250612-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz",
    ],
  );

  const source = await fs.readFile(path.join(desktopRoot, "scripts/prepare-runtime-tools.mjs"), "utf8");
  assert.match(source, /assertPinnedChecksum\(assetPath, pinnedAsset\)/u);
  assert.match(source, /assertPortablePythonTarget\(\)/u);
  assert.match(source, /Pinned SHA-256/u);
  assert.doesNotMatch(source, /checksumAsset/u);
  assert.doesNotMatch(source, /SHA256SUMS/u);
  assert.doesNotMatch(source, /checksums\.txt/u);
});

test("Python scanners install only from a fully hashed no-deps platform lock", async () => {
  const source = await fs.readFile(path.join(desktopRoot, "scripts/prepare-runtime-tools.mjs"), "utf8");
  const runtimeLayoutSource = await fs.readFile(path.join(desktopRoot, "scripts/runtime-python-layout.mjs"), "utf8");
  const launcherSource = await fs.readFile(path.join(desktopRoot, "scripts/portable-python-launcher.c"), "utf8");
  assert.match(source, /assertUvVersion\(uv\)/u);
  assert.match(source, /--system/u);
  assert.match(source, /--break-system-packages/u);
  assert.match(source, /--only-binary/u);
  assert.match(source, /--require-hashes/u);
  assert.match(source, /--no-deps/u);
  assert.match(source, /pythonLock\.lockPath/u);
  assert.match(source, /runtime-uv\.toml/u);
  assert.match(source, /UV_LINK_MODE:\s*"copy"/u);
  assert.match(source, /smokeRelocatedPortableRuntimeTree/u);
  assert.match(source, /relativePythonLauncherContent/u);
  assert.doesNotMatch(source, /UV_TOOL_DIR/u);
  assert.match(launcherSource, /CreateProcessW\(python/u);
  assert.match(launcherSource, /CreateProcessW\(python,\s*child_command,\s*NULL,\s*NULL,\s*FALSE/u);
  assert.match(launcherSource, /SetEnvironmentVariableW\(L"PYTHONDONTWRITEBYTECODE", L"1"\)/u);
  assert.match(launcherSource, /-I -B -m %ls/u);
  assert.match(runtimeLayoutSource, /\["-I", "-B", "-c"/u);
  assert.doesNotMatch(launcherSource, /cmd\.exe|powershell/iu);
});

test("every release target has a complete, exact, SHA-256 Python scanner graph", () => {
  for (const target of PYTHON_LOCK_TARGETS) {
    const lock = loadPythonLockConfiguration(path.join(desktopRoot, "scripts"), target);
    assert.ok(lock.packages.size >= 80, `${target} unexpectedly has only ${lock.packages.size} packages`);
    assert.equal(lock.packages.get("semgrep"), "1.167.0");
    assert.equal(lock.packages.get("bandit"), "1.9.4");
    assert.equal(lock.packages.get("pip-audit"), "2.10.1");
  }
});

test("hashed lock validation rejects missing hashes, ranges, and remote references", () => {
  assert.throws(() => validateFullyHashedRequirements("semgrep==1.167.0\n"));
  assert.throws(() => validateFullyHashedRequirements("semgrep>=1.167.0 --hash=sha256:".concat("a".repeat(64))));
  assert.throws(() => validateFullyHashedRequirements(
    `semgrep @ https://example.invalid/semgrep.whl --hash=sha256:${"a".repeat(64)}`,
  ));
  assert.doesNotThrow(() => validateFullyHashedRequirements(
    `semgrep==1.167.0 --hash=sha256:${"a".repeat(64)}`,
  ));
});

test("packaged smoke clears Node escape hatches and validates required scanner groups", async () => {
  const env = createPackagedSmokeEnvironment({
    platform: "win32",
    inheritedEnv: {
      PATH: "C:\\Program Files\\nodejs;C:\\Windows\\System32",
      SystemRoot: "C:\\Windows",
      ELECTRON_RUN_AS_NODE: "1",
      NODE_OPTIONS: "--inspect",
    },
  });
  assert.equal(env.PATH, "C:\\Windows\\System32;C:\\Windows");
  assert.equal(env.ELECTRON_RUN_AS_NODE, undefined);
  assert.equal(env.NODE_OPTIONS, undefined);
  assert.equal(env.HERMSEC_SMOKE_DOCTOR, "true");
  assert.equal(env.HERMSEC_SMOKE_RESULT_PATH, undefined);

  const doctor = packagedDoctorResult();
  assert.doesNotThrow(() => parseDoctorSmokeOutput(JSON.stringify(doctor)));
  assert.doesNotThrow(() => assertPackagedDoctorResult(doctor));
  assert.throws(() => assertPackagedDoctorResult({ ok: true, groups: [{ id: "required", status: "pass" }] }));
  assert.throws(() => parseDoctorSmokeResultArtifact({ schemaVersion: 1, kind: "wrong", result: doctor }));
  assert.deepEqual(
    parseDoctorSmokeResultArtifact(JSON.stringify({ schemaVersion: 1, kind: "hermsec-doctor-smoke", result: doctor })),
    doctor,
  );
  const resultEnv = createPackagedSmokeEnvironment({ smokeResultPath: "C:\\temp\\doctor-result.json" });
  assert.equal(resultEnv.HERMSEC_SMOKE_RESULT_PATH, "C:\\temp\\doctor-result.json");

  const smokeSource = await fs.readFile(path.join(desktopRoot, "scripts/smoke-packaged-runtime.mjs"), "utf8");
  assert.match(smokeSource, /runProcess\(executable, \["--smoke-doctor"\]/u);
  assert.match(smokeSource, /--portable-sfx/u);
  assert.match(smokeSource, /HERMSEC_SMOKE_RESULT_PATH/u);
  assert.match(smokeSource, /exited successfully without writing its result artifact/u);
  assert.doesNotMatch(smokeSource, /portable-sfx-doctor-exit-code/u);

  const indexSource = await fs.readFile(path.join(desktopRoot, "src/main/index.ts"), "utf8");
  assert.match(indexSource, /writeDoctorSmokeResultArtifact/u);
  assert.match(indexSource, /renameSync\(temporary, destination\)/u);

  const doctorSource = await fs.readFile(path.join(desktopRoot, "src/main/doctor.ts"), "utf8");
  assert.match(doctorSource, /createVerifiedBundledRuntimeExecutionLease/u);
  assert.match(doctorSource, /probeBundledScanner/u);
  assert.match(doctorSource, /BUNDLED_SCANNER_PROBE_TIMEOUT_MS/u);
  assert.match(doctorSource, /returned no version output/u);
});

test("relative Python launchers are confined to runtime-tools and reject build-machine paths", () => {
  for (const platform of ["darwin", "linux"]) {
    for (const tool of ["semgrep", "bandit", "pip-audit"]) {
      const content = relativePythonLauncherContent(tool, platform);
      assert.match(content, / -I -B -m /u);
      assert.match(content, /export PYTHONDONTWRITEBYTECODE=1/u);
      assert.doesNotThrow(() => assertRelativePythonLauncher(content, { tool, platform }));
      assert.throws(() => assertRelativePythonLauncher(`${content}\nC:\\build\\python.exe`, { tool, platform }));
    }
  }
  assert.throws(() => relativePythonLauncherContent("semgrep", "win32"));
  assert.throws(() => assertPortablePythonTarget("linux", "arm64"));
});

test("Windows scanner launcher verification rejects non-native and build-path-bearing shims", () => {
  const toolsRoot = path.resolve(desktopRoot, "release", "runtime-tools", "win32-x64");
  const input = {
    tool: "semgrep",
    toolsRoot,
    platform: "win32",
  };
  const valid = Buffer.alloc(2048);
  valid.write("MZ", 0, "ascii");
  assert.doesNotThrow(() => assertWindowsBinaryLauncher(valid, input));
  assert.throws(() => assertWindowsBinaryLauncher(Buffer.from("@echo off"), input));
  const leaked = Buffer.alloc(2048);
  leaked.write("MZ", 0, "ascii");
  Buffer.from(toolsRoot, "utf16le").copy(leaked, 256);
  assert.throws(() => assertWindowsBinaryLauncher(leaked, input));
});

test("bundled Windows scanner discovery cannot fall back to command or batch scripts", async () => {
  const source = await fs.readFile(path.join(desktopRoot, "src/main/runtimeBundle.ts"), "utf8");
  assert.match(source, /process\.platform === "win32" \? `\$\{command\}\.exe` : command/u);
  assert.doesNotMatch(source, /\.cmd|\.bat|\.com|executableSuffixes/u);
  assert.doesNotMatch(source, /python", command/u);

  const staging = await fs.readFile(path.join(desktopRoot, "scripts/prepare-runtime-tools.mjs"), "utf8");
  assert.doesNotMatch(staging, /pythonScriptLauncherPath/u);
  assert.match(staging, /HERMSEC_ALLOW_MINGW_LAUNCHER === "true"/u);
  assert.ok(staging.indexOf("findPortableLauncherCompiler({ allowMinGw })") > staging.indexOf("HERMSEC_ALLOW_MINGW_LAUNCHER"));
  assert.match(staging, /const suffixes = process\.platform === "win32" \? \["\.exe"\] : \[""\]/u);
  assert.match(staging, /buildPortablePythonLauncher/u);

  const launcherBuild = await fs.readFile(path.join(desktopRoot, "scripts/portable-python-launcher-build.mjs"), "utf8");
  assert.match(launcherBuild, /\/Brepro/u);
  assert.match(launcherBuild, /\/INCREMENTAL:NO/u);
  assert.match(launcherBuild, /SOURCE_DATE_EPOCH/u);
  assert.match(launcherBuild, /--no-insert-timestamp/u);

  const launcher = await fs.readFile(path.join(desktopRoot, "scripts/portable-python-launcher.c"), "utf8");
  assert.match(launcher, /int wmain\(void\)/u);
  assert.doesNotMatch(launcher, /wWinMain/u);
});

test("packaged runtime ignores inherited roots and scanner executable overrides", async () => {
  const runtimeSource = await fs.readFile(
    path.join(desktopRoot, "src/main/runtimeBundle.ts"),
    "utf8",
  );
  const configureStart = runtimeSource.indexOf("export function configureBundledRuntime");
  const clearOverrides = runtimeSource.indexOf("clearInheritedPackagedRuntimeOverrides()", configureStart);
  const toolsLookup = runtimeSource.indexOf("const toolsRoot = findBundledToolsRoot()", configureStart);
  assert.ok(clearOverrides > configureStart && clearOverrides < toolsLookup);
  assert.match(runtimeSource, /path\.join\(process\.resourcesPath,\s*"hermsec-cli"\)/u);
  assert.match(runtimeSource, /process\.resourcesPath,\s*"runtime-tools"/u);
  assert.match(runtimeSource, /\.\.\.bundledScannerOverrideEnvironmentNames\(\)/u);
  assert.match(runtimeSource, /delete process\.env\[key\]/u);

  const cliFunction = runtimeSource.slice(
    runtimeSource.indexOf("export function findBundledCliRoot"),
    runtimeSource.indexOf("export function findBundledToolsRoot"),
  );
  const toolsFunction = runtimeSource.slice(
    runtimeSource.indexOf("export function findBundledToolsRoot"),
    runtimeSource.indexOf("export function getBundledRuntimeIntegrityError"),
  );
  assert.ok(cliFunction.indexOf("if (app.isPackaged)") < cliFunction.indexOf("HERMSEC_CLI_ROOT"));
  assert.ok(toolsFunction.indexOf("if (app.isPackaged)") < toolsFunction.indexOf("HERMSEC_BUNDLED_TOOLS_DIR"));

  const scanSource = await fs.readFile(path.join(desktopRoot, "src/main/scan.ts"), "utf8");
  const runNodeCli = scanSource.indexOf("function runNodeCli");
  const leaseCreation = scanSource.indexOf("createVerifiedBundledRuntimeExecutionLease()", runNodeCli);
  const leaseGuard = scanSource.indexOf("runtimeLease?.assertIntact()", runNodeCli);
  const spawn = scanSource.indexOf("child = spawn(", runNodeCli);
  assert.ok(leaseCreation > runNodeCli && leaseCreation < spawn);
  assert.ok(leaseGuard > leaseCreation && leaseGuard < spawn);
  assert.match(scanSource.slice(runNodeCli, spawn), /trustedRuntime:/u);

  const doctorSource = await fs.readFile(path.join(desktopRoot, "src/main/doctor.ts"), "utf8");
  const probe = doctorSource.indexOf("function probeBundledScanner");
  const doctorProbeSpawn = doctorSource.indexOf("const child = spawn(", probe);
  assert.ok(doctorSource.indexOf("runtimeLease.assertIntact()", probe) < doctorProbeSpawn);
  assert.match(doctorSource, /createVerifiedBundledRuntimeExecutionLease\(\)/u);
});

test("runtime anchor binds the full staged tree and CLI without wall-clock metadata", async () => {
  const stagingSource = await fs.readFile(
    path.join(desktopRoot, "scripts/prepare-runtime-tools.mjs"),
    "utf8",
  );
  const integritySource = await fs.readFile(
    path.join(desktopRoot, "scripts/runtime-python-layout.mjs"),
    "utf8",
  );
  const runtimeSource = await fs.readFile(
    path.join(desktopRoot, "src/main/runtimeBundle.ts"),
    "utf8",
  );
  const anchorSource = await fs.readFile(
    path.join(desktopRoot, "scripts/prepare-bundled-integrity-anchor.mjs"),
    "utf8",
  );
  assert.match(stagingSource, /createRuntimeManifest\(\{/u);
  assert.doesNotMatch(stagingSource, /new Date\(\)\.toISOString\(\)/u);
  assert.match(integritySource, /schemaVersion:\s*"4\.0"/u);
  assert.match(integritySource, /buildRuntimeFileManifest/u);
  assert.match(integritySource, /treeSha256/u);
  assert.match(runtimeSource, /verifyBundledResourceIntegrity/u);
  assert.match(runtimeSource, /createVerifiedBundleExecutionLease/u);
  assert.match(anchorSource, /createBundledResourceIntegrityAnchor/u);
  assert.match(anchorSource, /Generated during packaging/u);
  assert.match(await fs.readFile(path.join(desktopRoot, "package.json"), "utf8"), /prepare:integrity-anchor/u);
});

test("immutable bundle anchor rejects CLI and manifest substitution", async () => {
  const resourcesRoot = await fs.mkdtemp(path.join(desktopRoot, ".tmp-integrity-anchor-"));
  try {
    const fixture = await writeBundledResourceFixture(resourcesRoot);
    const anchor = createBundledResourceIntegrityAnchor({
      resourcesRoot,
      platform: process.platform,
      arch: process.arch,
    });
    assert.doesNotThrow(() => verifyBundledResourceIntegrity({ resourcesRoot, anchor }));
    const generatedAnchorPath = path.join(resourcesRoot, "generated", "bundledIntegrity.ts");
    const generated = writeBundledIntegrityAnchor({ resourcesRoot, outputPath: generatedAnchorPath });
    assert.deepEqual(generated.anchor, anchor);
    const generatedSource = await fs.readFile(generatedAnchorPath, "utf8");
    assert.match(generatedSource, /BUNDLED_RESOURCE_INTEGRITY/u);
    assert.doesNotMatch(generatedSource, new RegExp(resourcesRoot.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"));

    await fs.writeFile(fixture.cliEntry, "export const compromised = true;", "utf8");
    assert.throws(
      () => verifyBundledResourceIntegrity({ resourcesRoot, anchor }),
      /immutable build integrity anchor/u,
    );

    await fs.writeFile(fixture.cliEntry, "export const safe = true;", "utf8");
    await fs.writeFile(fixture.manifest, "{\"schemaVersion\":\"forged\"}", "utf8");
    assert.throws(
      () => verifyBundledResourceIntegrity({ resourcesRoot, anchor }),
      /immutable build integrity anchor/u,
    );
  } finally {
    await fs.rm(resourcesRoot, { recursive: true, force: true });
  }
});

test("execution lease survives resource swaps and fails closed when its own snapshot changes", async () => {
  const resourcesRoot = await fs.mkdtemp(path.join(desktopRoot, ".tmp-integrity-source-"));
  const leaseParent = await fs.mkdtemp(path.join(desktopRoot, ".tmp-integrity-leases-"));
  let lease: ReturnType<typeof createVerifiedBundleExecutionLease> | undefined;
  try {
    const fixture = await writeBundledResourceFixture(resourcesRoot);
    const anchor = createBundledResourceIntegrityAnchor({
      resourcesRoot,
      platform: process.platform,
      arch: process.arch,
    });
    lease = createVerifiedBundleExecutionLease({ resourcesRoot, leaseParent, anchor });
    const leasedCli = await fs.readFile(lease.cliEntryPath, "utf8");
    assert.equal(leasedCli, "export const safe = true;");

    await fs.rename(fixture.cliEntry, `${fixture.cliEntry}.original`);
    await fs.writeFile(fixture.cliEntry, "export const swapped = true;", "utf8");
    assert.doesNotThrow(() => lease?.assertIntact());
    assert.equal(await fs.readFile(lease.cliEntryPath, "utf8"), "export const safe = true;");

    try {
      await fs.chmod(lease.cliEntryPath, 0o644);
      await fs.writeFile(lease.cliEntryPath, "export const leaseSwap = true;", "utf8");
      assert.throws(() => lease?.assertIntact(), /immutable build integrity anchor/u);
    } catch (error) {
      assert.match(String(error), /EPERM|EACCES|permission/u);
    }
  } finally {
    const leaseRoot = lease?.leaseRoot;
    if (lease) {
      await Promise.all([lease.release(), lease.release()]);
    }
    if (leaseRoot) {
      await assert.rejects(fs.access(leaseRoot));
    }
    await fs.rm(resourcesRoot, { recursive: true, force: true });
    await fs.rm(leaseParent, { recursive: true, force: true });
  }
});

test("portable runtime smoke clears system Python state and checks an actual staged tree when present", async (t) => {
  const env = createPortableRuntimeSmokeEnvironment({
    platform: "win32",
    inheritedEnv: {
      PATH: "C:\\Python312;C:\\Program Files\\nodejs;C:\\Windows\\System32",
      SystemRoot: "C:\\Windows",
      PYTHONHOME: "C:\\Python312",
      PYTHONPATH: "C:\\Python312\\Lib",
      PYTHONDONTWRITEBYTECODE: "0",
      VIRTUAL_ENV: "C:\\Python312\\venv",
      CONDA_PREFIX: "C:\\Conda",
    },
  });
  assert.equal(env.PATH, "C:\\Windows\\System32;C:\\Windows");
  assert.equal(env.PYTHONDONTWRITEBYTECODE, "1");
  assert.equal(env.PYTHONHOME, undefined);
  assert.equal(env.PYTHONPATH, undefined);
  assert.equal(env.VIRTUAL_ENV, undefined);
  assert.equal(env.CONDA_PREFIX, undefined);

  const stagedToolsRoot = path.join(desktopRoot, "resources", "runtime-tools", `${process.platform}-${process.arch}`);
  if (!await pathExists(stagedToolsRoot)) {
    t.skip("Portable runtime is prepared by the packaging stage, not the unit-test setup.");
    return;
  }
  const stagedManifest = JSON.parse(
    await fs.readFile(path.join(stagedToolsRoot, "manifest.json"), "utf8"),
  ) as { schemaVersion?: unknown };
  if (stagedManifest.schemaVersion !== "4.0") {
    t.skip("Prepared runtime predates the current full-tree manifest and will be regenerated by packaging.");
    return;
  }
  assert.doesNotThrow(() => assertPortablePythonRuntime({ toolsRoot: stagedToolsRoot }));
  assert.doesNotThrow(() => assertRuntimeProvenance(stagedToolsRoot));

  const relocatedToolsRoot = path.join(desktopRoot, ".tmp-packaging-relocated-runtime");
  try {
    assert.doesNotThrow(() => smokeRelocatedPortableRuntimeTree({
      toolsRoot: stagedToolsRoot,
      relocationPath: relocatedToolsRoot,
    }));
  } finally {
    await fs.rm(relocatedToolsRoot, { recursive: true, force: true });
  }
});

test("packaged smoke rejects a missing runtime-tools tree", async () => {
  const parent = await fs.mkdtemp(path.join(desktopRoot, ".tmp-packaging-hardening-"));
  try {
    assert.throws(() => assertPortablePythonRuntime({ toolsRoot: path.join(parent, "missing") }));
  } finally {
    await fs.rm(parent, { recursive: true, force: true });
  }
});

async function pathExists(candidate: string): Promise<boolean> {
  try {
    await fs.access(candidate);
    return true;
  } catch {
    return false;
  }
}

test("release workflows pin actions, use exact uv, verify tags, and block on packaged health", async () => {
  for (const workflow of ["windows-release.yml", "macos-release.yml"]) {
    const source = await fs.readFile(path.join(repoRoot, ".github/workflows", workflow), "utf8");
    assert.doesNotMatch(source, /continue-on-error:\s*true/u);
    assert.doesNotMatch(source, /pip install --upgrade uv/u);
    assert.match(source, /astral-sh\/setup-uv@[a-f0-9]{40}/u);
    assert.match(source, /version:\s*"0\.10\.12"/u);
    assert.match(source, /git rev-parse.*refs\/tags/u);
    assert.match(source, /smoke-packaged-runtime\.mjs/u);
    assert.match(source, /npm --prefix desktop test/u);
    assert.match(source, /unsigned development build/u);
    if (workflow === "windows-release.yml") {
      assert.match(source, /ilammy\/msvc-dev-cmd@[a-f0-9]{40}/u);
      assert.match(source, /Hermsec-Portable-Windows-x64\.exe/u);
      assert.match(source, /Hermsec-Setup-Windows-x64\.exe/u);
      assert.match(source, /\/S/u);
      assert.match(source, /Installed Hermsec executable was not found/u);
    }
    if (workflow === "macos-release.yml") {
      assert.match(source, /linux-runtime-gate/u);
      assert.match(source, /safedep\/pmg@[a-f0-9]{40}/u);
      assert.match(source, /hdiutil attach/u);
      assert.match(source, /Smoke released DMG artifact/u);
    }
    for (const action of ["actions/checkout", "actions/setup-node", "actions/setup-python", "actions/upload-artifact", "actions/download-artifact"]) {
      assert.match(source, new RegExp(`${action.replace("/", "\\/")}@[a-f0-9]{40}`));
    }
  }
});

async function writeBundledResourceFixture(resourcesRoot: string): Promise<{
  cliEntry: string;
  manifest: string;
}> {
  const cliEntry = path.join(resourcesRoot, "hermsec-cli", "dist", "src", "bin", "hermsec.js");
  const runtimeRoot = path.join(resourcesRoot, "runtime-tools", `${process.platform}-${process.arch}`);
  const manifest = path.join(runtimeRoot, "manifest.json");
  await Promise.all([
    fs.mkdir(path.dirname(cliEntry), { recursive: true }),
    fs.mkdir(path.join(runtimeRoot, "bin"), { recursive: true }),
    fs.mkdir(path.join(runtimeRoot, "python-runtime"), { recursive: true }),
  ]);
  await Promise.all([
    fs.writeFile(cliEntry, "export const safe = true;", "utf8"),
    fs.writeFile(manifest, "{\"schemaVersion\":\"4.0\"}", "utf8"),
    fs.writeFile(path.join(runtimeRoot, "bin", process.platform === "win32" ? "semgrep.exe" : "semgrep"), "scanner", "utf8"),
    fs.writeFile(path.join(runtimeRoot, "python-runtime", process.platform === "win32" ? "python.exe" : "python3"), "python", "utf8"),
  ]);
  return { cliEntry, manifest };
}

function packagedDoctorResult() {
  const scannerChecks = [
    "command-semgrep",
    "command-gitleaks",
    "command-bandit",
    "command-osv-scanner",
    "command-pip-audit",
    "command-pmg",
  ].map((id) => ({ id, status: "pass", message: "Bundled scanner executable verified: version" }));
  return {
    ok: true,
    checks: scannerChecks,
    groups: [
      { id: "required", status: "pass" },
      { id: "scanners", status: "pass" },
    ],
  };
}
