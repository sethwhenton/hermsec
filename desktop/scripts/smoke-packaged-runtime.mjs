import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { smokePortableRuntimeTree } from "./runtime-python-layout.mjs";

const appRoot = path.resolve(import.meta.dirname, "..");
const DEFAULT_TIMEOUT_MS = 90_000;
const PORTABLE_SFX_TIMEOUT_MS = 180_000;
const SCANNER_CHECK_IDS = [
  "command-semgrep",
  "command-gitleaks",
  "command-bandit",
  "command-osv-scanner",
  "command-pip-audit",
  "command-pmg",
];

export function createPackagedSmokeEnvironment(input = {}) {
  const platform = input.platform ?? process.platform;
  const inheritedEnv = input.inheritedEnv ?? process.env;
  const env = { ...inheritedEnv };
  const systemRoot = env.SystemRoot ?? env.SYSTEMROOT ?? "C:\\Windows";

  // The child receives only operating-system locations. The running Hermsec
  // app prepends its staged runtime directories, so a PATH Node cannot mask a
  // bundled-CLI or scanner failure.
  const windowsSystemRoot = path.win32.normalize(systemRoot);
  env.PATH = platform === "win32"
    ? `${path.win32.join(windowsSystemRoot, "System32")};${windowsSystemRoot}`
    : "/usr/bin:/bin:/usr/sbin:/sbin";
  env.HERMSEC_SMOKE_DOCTOR = "true";
  env.HERMSEC_OPEN_DEVTOOLS = "false";
  if (input.smokeResultPath) {
    env.HERMSEC_SMOKE_RESULT_PATH = input.smokeResultPath;
  }
  delete env.ELECTRON_RUN_AS_NODE;
  delete env.NODE_OPTIONS;
  return env;
}

export function createPackagedSmokeArguments(platform = process.platform) {
  return platform === "linux"
    ? ["--no-sandbox", "--smoke-doctor"]
    : ["--smoke-doctor"];
}

export function formatPackagedProcessFailure(result) {
  const streams = [
    result.stderr?.trim()
      ? `stderr:\n${result.stderr.trim()}`
      : "",
    result.stdout?.trim()
      ? `stdout:\n${result.stdout.trim()}`
      : "",
  ].filter(Boolean);
  return streams.join("\n");
}

export function parseDoctorSmokeOutput(stdout) {
  const text = String(stdout ?? "").trim();
  const firstObject = text.indexOf("{");
  const lastObject = text.lastIndexOf("}");
  if (firstObject < 0 || lastObject <= firstObject) {
    throw new Error("Packaged Doctor emitted no JSON result.");
  }
  return JSON.parse(text.slice(firstObject, lastObject + 1));
}

export function assertPackagedDoctorResult(result) {
  if (!result?.ok) {
    throw new Error(`Packaged Doctor failed: ${result?.message ?? "no result message"}`);
  }
  const groups = Array.isArray(result.groups) ? result.groups : [];
  for (const id of ["required", "scanners"]) {
    const group = groups.find((item) => item?.id === id);
    if (group?.status !== "pass") {
      throw new Error(`Packaged Doctor did not pass ${id}: ${group?.message ?? "missing group"}`);
    }
  }
  const checks = Array.isArray(result.checks) ? result.checks : [];
  for (const id of SCANNER_CHECK_IDS) {
    const check = checks.find((item) => item?.id === id);
    if (check?.status !== "pass" || typeof check.message !== "string" || !check.message.trim()) {
      throw new Error(`Packaged Doctor did not verify ${id}: ${check?.message ?? "missing scanner check"}`);
    }
  }
}

export function parseDoctorSmokeResultArtifact(contents) {
  const artifact = typeof contents === "string" ? JSON.parse(contents) : contents;
  if (artifact?.schemaVersion !== 1 || artifact?.kind !== "hermsec-doctor-smoke" || !artifact.result) {
    throw new Error("Packaged Doctor did not write a valid app-authored result artifact.");
  }
  return artifact.result;
}

export function assertPortablePythonRuntime(input) {
  const toolsRoot = input.toolsRoot ?? packagedToolsRoot(input.executable, input.platform ?? process.platform, input.arch ?? process.arch);
  if (!toolsRoot || !existsSync(toolsRoot)) {
    throw new Error("Packaged runtime-tools directory was not found for Python relocatability verification.");
  }
  smokePortableRuntimeTree({ toolsRoot, platform: input.platform, inheritedEnv: input.inheritedEnv });
}

export async function smokePackagedRuntime(input) {
  const executable = path.resolve(input.executable);
  if (!existsSync(executable)) {
    throw new Error(`Packaged Hermsec executable was not found: ${executable}`);
  }

  const artifactDir = await mkdtemp(path.join(tmpdir(), "hermsec-packaged-doctor-"));
  const artifactPath = path.join(artifactDir, "doctor-result.json");
  try {
    const result = await runProcess(
      executable,
      createPackagedSmokeArguments(input.platform),
      {
        cwd: path.dirname(executable),
        env: createPackagedSmokeEnvironment({
          platform: input.platform,
          inheritedEnv: input.inheritedEnv,
          smokeResultPath: artifactPath,
        }),
        timeoutMs: input.timeoutMs ?? DEFAULT_TIMEOUT_MS,
      },
    );
    if (result.exitCode !== 0) {
      const detail = formatPackagedProcessFailure(result);
      throw new Error(
        `Packaged Doctor exited ${result.exitCode}${
          detail ? `:\n${detail}` : ""
        }`,
      );
    }

    let artifactContents;
    try {
      artifactContents = await readFile(artifactPath, "utf8");
    } catch {
      throw new Error("Packaged Doctor exited successfully without writing its result artifact.");
    }
    const doctor = parseDoctorSmokeResultArtifact(artifactContents);
    assertPackagedDoctorResult(doctor);

    if (result.stdout.trim()) {
      const stdoutDoctor = parseDoctorSmokeOutput(result.stdout);
      assertPackagedDoctorResult(stdoutDoctor);
    }
    if (input.verifyRuntimeTree !== false) {
      assertPortablePythonRuntime({
        executable,
        platform: input.platform,
        arch: input.arch,
        inheritedEnv: input.inheritedEnv,
      });
    }
    return doctor;
  } finally {
    await rm(artifactDir, { recursive: true, force: true });
  }
}

async function runProcess(executable, args, options) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, {
      cwd: options.cwd,
      env: options.env,
      shell: false,
      windowsHide: true,
    });
    let stdout = "";
    let stderr = "";
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill();
      reject(new Error(`Packaged Doctor timed out after ${options.timeoutMs} ms.`));
    }, options.timeoutMs);

    child.stdout.on("data", (chunk) => {
      stdout += String(chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderr += String(chunk);
    });
    child.on("error", (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(error);
    });
    child.on("close", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ exitCode: code ?? 1, stdout, stderr });
    });
  });
}

function defaultExecutable() {
  if (process.platform === "win32") {
    return path.join(appRoot, "release", "win-unpacked", "Hermsec.exe");
  }
  throw new Error("Pass --app <path> when running this smoke outside Windows.");
}

function packagedToolsRoot(executable, platform, arch) {
  const platformKey = `${platform}-${arch}`;
  if (platform === "darwin") {
    return path.resolve(path.dirname(executable), "..", "Resources", "runtime-tools", platformKey);
  }
  if (platform === "win32") {
    return path.resolve(path.dirname(executable), "resources", "runtime-tools", platformKey);
  }
  return path.resolve(path.dirname(executable), "resources", "runtime-tools", platformKey);
}

function parseArgs(args) {
  const appIndex = args.indexOf("--app");
  const portableSfx = args.includes("--portable-sfx");
  const verifyRuntimeTree = !args.includes("--app-only") && !portableSfx;
  if (appIndex >= 0 && args[appIndex + 1]) {
    return {
      executable: args[appIndex + 1],
      verifyRuntimeTree,
      portableSfx,
      ...(portableSfx ? { timeoutMs: PORTABLE_SFX_TIMEOUT_MS } : {}),
    };
  }
  return { executable: defaultExecutable(), verifyRuntimeTree, portableSfx };
}

async function main() {
  const doctor = await smokePackagedRuntime(parseArgs(process.argv.slice(2)));
  console.log(JSON.stringify({ ok: true, smoke: "packaged-runtime", doctor }, null, 2));
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (invokedPath === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.stack ?? error.message : String(error));
    process.exitCode = 1;
  });
}
