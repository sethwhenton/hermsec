import { createHash } from "node:crypto";
import {
  cpSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, relative, resolve, sep } from "node:path";
import {
  assertFreshSevenModeSummary,
  cliSourceConfigFingerprint,
  createSmokeChildEnvironment,
  createSmokeDesktopSettings,
  createUniqueSmokeReportRoot,
  spawnSmokeProcessInContainment,
  startSmokeScanProvider,
  terminateProcessTree,
  verifyCurrentCliBuild,
} from "./smoke-scan-provider.mjs";

const desktopRoot = resolve(import.meta.dirname, "..");
const repositoryRoot = resolve(desktopRoot, "..");
const electron = process.platform === "win32"
  ? resolve(desktopRoot, "node_modules/.bin/electron.exe")
  : resolve(desktopRoot, "node_modules/.bin/electron");
const electronFallback = process.platform === "win32"
  ? resolve(desktopRoot, "node_modules/electron/dist/electron.exe")
  : electron;
const preferredElectron = process.env.HERMSEC_ELECTRON_BINARY;
const electronBinary = preferredElectron && existsSync(preferredElectron)
  ? preferredElectron
  : existsSync(electron)
    ? electron
    : electronFallback;

if (!existsSync(electronBinary)) {
  throw new Error(`Electron binary not found: ${electronBinary}`);
}

const reportBaseDir = process.env.HERMSEC_SMOKE_SCAN_MODES_OUT
  ?? resolve(repositoryRoot, ".hermsec", "v3-scan-modes-smoke");
const reportDir = createUniqueSmokeReportRoot(reportBaseDir);
const projectPath = process.env.HERMSEC_SMOKE_PROJECT
  ?? resolve(repositoryRoot, "tests", "fixtures", "repos", "node-express-vulnerable");
const startedAt = Date.now();

let child;
let provider;
let smokeHome;
let cliSnapshotRoot;
let cliBuildProof;
let providerViolation;
let processTrackerViolation;
let processTracker;
let terminationPromise;
let primaryError;
let cleanupError;
let outcome;
let childEnvironment;

const requestTreeTermination = () => {
  if (!child) {
    return Promise.resolve();
  }
  terminationPromise ??= terminateProcessTree(child, {
    ...(processTracker ? { tracker: processTracker } : {}),
  });
  return terminationPromise;
};

try {
  smokeHome = mkdtempSync(join(tmpdir(), "hermsec-desktop-scan-smoke-"));
  cliBuildProof = await verifyCurrentCliBuild(repositoryRoot, {
    referenceParent: smokeHome,
  });
  cliSnapshotRoot = await createStableCliSnapshot(
    repositoryRoot,
    smokeHome,
    cliBuildProof,
  );
  writeFileSync(
    resolve(reportDir, "smoke-invocation.json"),
    JSON.stringify(
      {
        schemaVersion: "1.0",
        startedAt: new Date(startedAt).toISOString(),
        reportBaseDir: resolve(reportBaseDir),
        reportDir,
        projectPath,
        cliSnapshotRoot,
        cliBuildProof: {
          sourceConfigFingerprint: cliBuildProof.sourceConfigFingerprint,
          javascriptBuildFingerprint: cliBuildProof.javascriptBuildFingerprint,
          distFingerprint: cliBuildProof.distFingerprint,
        },
      },
      null,
      2,
    ),
    "utf8",
  );
  provider = await startSmokeScanProvider({
    onViolation(message) {
      providerViolation ??= message;
      void requestTreeTermination().catch(() => undefined);
    },
  });

  writeFileSync(
    join(smokeHome, "settings.json"),
    JSON.stringify(
      createSmokeDesktopSettings({
        baseUrl: provider.baseUrl,
        reportDir,
      }),
      null,
      2,
    ),
    "utf8",
  );

  childEnvironment = createSmokeChildEnvironment(process.env, {
    baseUrl: provider.baseUrl,
    homeDir: smokeHome,
    reportDir,
    projectPath,
    cliRoot: cliSnapshotRoot,
  });
  const launch = spawnSmokeProcessInContainment(electronBinary, [
    ".",
    "--smoke-scan-modes",
    "--disable-gpu",
    "--disable-gpu-compositing",
    "--disable-software-rasterizer",
    "--no-sandbox",
  ], {
    cwd: desktopRoot,
    env: childEnvironment,
    stdio: "inherit",
    containmentRoot: smokeHome,
    onError(message) {
      processTrackerViolation ??= message;
      void requestTreeTermination().catch(() => undefined);
    },
  });
  child = launch.processHandle;
  processTracker = launch.tracker;
  await processTracker.ready();

  outcome = await waitForChild(child, 900_000);
} catch (error) {
  primaryError = error;
}

try {
  if (child) {
    await requestTreeTermination();
  }
} catch (error) {
  cleanupError = error;
}
if (processTracker && !processTracker.snapshot().stopped) {
  cleanupError = combineError(
    cleanupError,
    new Error("Hermsec scan modes process lineage tracker did not stop during cleanup."),
  );
}

if (provider) {
  try {
    await provider.quiesce();
  } catch (error) {
    cleanupError = combineError(cleanupError, error);
  }
  try {
    await provider.close();
  } catch (error) {
    cleanupError = combineError(cleanupError, error);
  }
}

if (!primaryError && outcome?.code !== 0) {
  primaryError = new Error(
    providerViolation
      ? `Hermsec scan modes smoke provider rejected the canonical request: ${providerViolation}`
      : `Hermsec scan modes smoke test exited with code ${outcome?.code ?? "none"}${outcome?.signal ? ` (${outcome.signal})` : ""}.`,
  );
}
if (!primaryError && processTrackerViolation) {
  primaryError = new Error(
    `Hermsec scan modes process lineage tracker failed: ${processTrackerViolation}`,
  );
}

if (provider) {
  try {
    provider.assertCoverage();
  } catch (error) {
    primaryError = combineError(primaryError, error);
  }
}

if (!primaryError && !cleanupError) {
  try {
    const summaryPath = resolve(reportDir, "smoke-summary.json");
    assertFreshSevenModeSummary(summaryPath, startedAt);
    writeFileSync(
      resolve(reportDir, "smoke-provider-summary.json"),
      JSON.stringify(
        {
          ok: true,
          provider: "loopback-openai-compatible",
          model: childEnvironment.HERMSEC_MODEL,
          network: "127.0.0.1-only",
          projectPath,
          reportBaseDir: resolve(reportBaseDir),
          reportDir,
          cliBuildProof: {
            sourceConfigFingerprint: cliBuildProof.sourceConfigFingerprint,
            javascriptBuildFingerprint: cliBuildProof.javascriptBuildFingerprint,
            distFingerprint: cliBuildProof.distFingerprint,
          },
          processTracker: processTracker?.snapshot(),
          ...provider.snapshot(),
        },
        null,
        2,
      ),
      "utf8",
    );
    process.stdout.write(`Hermsec seven-mode smoke artifacts: ${reportDir}\n`);
  } catch (error) {
    primaryError = error;
  }
}

try {
  if (smokeHome) {
    removeTemporarySmokeHome(smokeHome);
  }
} catch (error) {
  cleanupError = combineError(cleanupError, error);
}

const errors = [primaryError, cleanupError].filter(Boolean);
if (errors.length > 1) {
  throw new AggregateError(
    errors,
    "Hermsec scan modes smoke failed and cleanup did not quiesce safely.",
  );
}
if (errors[0]) {
  throw errors[0];
}

function waitForChild(processHandle, timeoutMs) {
  if (processHandle.exitCode !== null || processHandle.signalCode !== null) {
    return Promise.resolve({
      code: processHandle.exitCode,
      signal: processHandle.signalCode,
    });
  }
  return new Promise((resolvePromise, reject) => {
    const timer = setTimeout(() => {
      reject(new Error("Hermsec scan modes smoke test timed out."));
    }, timeoutMs);
    processHandle.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    processHandle.once("exit", (code, signal) => {
      clearTimeout(timer);
      resolvePromise({ code, signal });
    });
  });
}

function removeTemporarySmokeHome(homeDir) {
  const resolvedHome = resolve(homeDir);
  const resolvedTemp = `${resolve(tmpdir())}${sep}`;
  if (
    !resolvedHome.startsWith(resolvedTemp)
    || !basename(resolvedHome).startsWith("hermsec-desktop-scan-smoke-")
  ) {
    throw new Error(`Refusing to remove unexpected smoke home: ${resolvedHome}`);
  }
  rmSync(resolvedHome, { recursive: true, force: true });
}

function delay(milliseconds) {
  return new Promise((resolvePromise) => {
    setTimeout(resolvePromise, milliseconds);
  });
}

async function createStableCliSnapshot(sourceRoot, temporaryHome, buildProof) {
  const sourceDist = resolve(sourceRoot, "dist");
  const sourcePackage = resolve(sourceRoot, "package.json");
  assertBuildProofCurrent(sourceRoot, sourceDist, buildProof);
  const deadline = Date.now() + 30_000;
  let attempt = 0;
  let lastError;

  while (Date.now() < deadline) {
    attempt += 1;
    try {
      const before = cliTreeStamp(sourceDist);
      if (!before) {
        throw new Error("The root Hermsec CLI build is not currently available.");
      }
      if (
        before !== buildProof.distFingerprint
        || cliSourceConfigFingerprint(sourceRoot) !== buildProof.sourceConfigFingerprint
      ) {
        throw new Error("The root Hermsec CLI build or its source/config inputs changed after freshness verification.");
      }
      await delay(200);
      const settled = cliTreeStamp(sourceDist);
      if (!settled || settled !== before) {
        throw new Error("The root Hermsec CLI build changed while waiting for a stable snapshot.");
      }

      const snapshotRoot = mkdtempSync(join(temporaryHome, "hermsec-cli-"));
      cpSync(sourceDist, resolve(snapshotRoot, "dist"), {
        recursive: true,
        errorOnExist: true,
        preserveTimestamps: true,
      });
      if (existsSync(sourcePackage)) {
        cpSync(sourcePackage, resolve(snapshotRoot, "package.json"));
      }

      const copied = cliTreeStamp(resolve(snapshotRoot, "dist"));
      const after = cliTreeStamp(sourceDist);
      if (
        copied === settled
        && after === settled
        && after === buildProof.distFingerprint
        && cliSourceConfigFingerprint(sourceRoot) === buildProof.sourceConfigFingerprint
        && existsSync(resolve(snapshotRoot, "dist", "src", "bin", "hermsec.js"))
      ) {
        return snapshotRoot;
      }
      throw new Error("The root Hermsec CLI build changed while it was being snapshotted.");
    } catch (error) {
      lastError = error;
      await delay(Math.min(1_000, attempt * 100));
    }
  }

  throw new Error(
    `Could not create a stable root Hermsec CLI snapshot: ${lastError instanceof Error ? lastError.message : String(lastError)}`,
  );
}

function assertBuildProofCurrent(sourceRoot, sourceDist, buildProof) {
  if (
    !buildProof
    || cliSourceConfigFingerprint(sourceRoot) !== buildProof.sourceConfigFingerprint
    || cliTreeStamp(sourceDist) !== buildProof.distFingerprint
  ) {
    throw new Error("The root Hermsec CLI build proof is stale before snapshot creation.");
  }
}

function combineError(existing, next) {
  if (!existing) {
    return next;
  }
  return new AggregateError([existing, next], "Multiple smoke finalization checks failed.");
}

function cliTreeStamp(root) {
  if (!existsSync(resolve(root, "src", "bin", "hermsec.js"))) {
    return undefined;
  }
  const pending = [root];
  const files = [];
  const digest = createHash("sha256");
  let bytes = 0;

  while (pending.length > 0) {
    const current = pending.pop();
    for (const entry of readdirSync(current, { withFileTypes: true }).sort((left, right) =>
      left.name.localeCompare(right.name)
    )) {
      const entryPath = resolve(current, entry.name);
      if (entry.isDirectory()) {
        pending.push(entryPath);
      } else if (entry.isFile()) {
        files.push(entryPath);
      }
    }
  }

  for (const filePath of files.sort((left, right) => left.localeCompare(right))) {
    const content = readFileSync(filePath);
    bytes += content.byteLength;
    digest.update(relative(root, filePath).replaceAll("\\", "/"));
    digest.update("\0");
    digest.update(content);
    digest.update("\0");
  }
  return `${files.length}:${bytes}:${digest.digest("hex")}`;
}
