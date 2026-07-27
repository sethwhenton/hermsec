import { createHash } from "node:crypto";
import {
  cpSync,
  existsSync,
  lstatSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  rmSync,
} from "node:fs";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { verifyExtractedTree } from "./runtime-archive-safety.mjs";

export const PYTHON_SCANNER_MODULES = Object.freeze({
  // Semgrep deliberately makes `python -m semgrep` fail. Its supported console
  // entrypoint remains importable, so use that module while retaining a relative
  // embedded-Python launcher rather than the generated build-machine script.
  semgrep: "semgrep.console_scripts.entrypoint",
  bandit: "bandit",
  "pip-audit": "pip_audit",
});

export const SUPPORTED_PORTABLE_PYTHON_TARGETS = Object.freeze([
  "win32-x64",
  "darwin-x64",
  "darwin-arm64",
  "linux-x64",
]);

export function runtimePlatformKey(platform = process.platform, arch = process.arch) {
  return `${platform}-${arch}`;
}

export function assertPortablePythonTarget(platform = process.platform, arch = process.arch) {
  const key = runtimePlatformKey(platform, arch);
  if (!SUPPORTED_PORTABLE_PYTHON_TARGETS.includes(key)) {
    throw new Error(`No portable Python runtime is pinned for ${key}. Refusing to prepare a non-relocatable scanner bundle.`);
  }
  return key;
}

export function buildRuntimeFileManifest(toolsRoot) {
  const root = path.resolve(toolsRoot);
  const files = [];
  const stack = [root];
  while (stack.length > 0) {
    const directory = stack.pop();
    const entries = readdirSync(directory, { withFileTypes: true })
      .sort((left, right) => compareText(left.name, right.name));
    for (const entry of entries) {
      const filePath = path.join(directory, entry.name);
      const relativePath = path.relative(root, filePath).replaceAll("\\", "/");
      if (relativePath === "manifest.json") continue;
      if (entry.isDirectory()) {
        stack.push(filePath);
        continue;
      }
      if (entry.isSymbolicLink()) {
        const target = readlinkSync(filePath);
        assertConfinedRelativeLink(root, filePath, target);
        const bytes = Buffer.from(target, "utf8");
        files.push({
          path: relativePath,
          kind: "symlink",
          size: bytes.byteLength,
          sha256: createHash("sha256").update(bytes).digest("hex"),
        });
        continue;
      }
      const stat = lstatSync(filePath);
      if (!stat.isFile()) {
        throw new Error(`Runtime tree contains an unsupported entry: ${relativePath}`);
      }
      files.push({
        path: relativePath,
        kind: "file",
        size: stat.size,
        sha256: createHash("sha256").update(readFileSync(filePath)).digest("hex"),
      });
    }
  }
  return files.sort((left, right) => compareText(left.path, right.path));
}

export function createRuntimeManifest(input) {
  const files = buildRuntimeFileManifest(input.toolsRoot);
  return {
    schemaVersion: "4.0",
    platform: input.platform ?? process.platform,
    arch: input.arch ?? process.arch,
    provenance: input.provenance,
    portablePython: input.portablePython,
    tools: input.tools,
    files,
    treeSha256: createHash("sha256").update(JSON.stringify(files)).digest("hex"),
  };
}

export function portablePythonExecutable(toolsRoot, platform = process.platform) {
  return platform === "win32"
    ? path.join(toolsRoot, "python-runtime", "python.exe")
    : path.join(toolsRoot, "python-runtime", "bin", "python3");
}

export function pythonLauncherPath(toolsRoot, tool, platform = process.platform) {
  assertPythonTool(tool);
  return path.join(toolsRoot, "bin", platform === "win32" ? `${tool}.exe` : tool);
}

export function relativePythonLauncherContent(tool, platform = process.platform) {
  const moduleName = pythonModuleName(tool);
  if (platform === "darwin" || platform === "linux") {
    return [
      "#!/bin/sh",
      "set -eu",
      "export PYTHONDONTWRITEBYTECODE=1",
      "case \"$0\" in",
      "  */*)",
      "    SELF_DIR=${0%/*}",
      "    case \"$SELF_DIR\" in",
      "      \"\") SELF_DIR=/ ;;",
      "    esac",
      "    ;;",
      "  *) SELF_DIR=. ;;",
      "esac",
      "SELF_DIR=$(CDPATH= cd -- \"$SELF_DIR\" && pwd)",
      `exec \"$SELF_DIR/../python-runtime/bin/python3\" -I -B -m ${moduleName} \"$@\"`,
    ].join("\n") + "\n";
  }
  throw new Error(`No relative Python launcher format is configured for ${platform}.`);
}

export function assertPortableRuntimeTree(input) {
  const platform = input.platform ?? process.platform;
  const toolsRoot = path.resolve(input.toolsRoot);
  const python = portablePythonExecutable(toolsRoot, platform);
  if (!existsSync(python)) {
    throw new Error(`Portable Python executable is missing: ${python}`);
  }

  for (const tool of Object.keys(PYTHON_SCANNER_MODULES)) {
    const launcher = pythonLauncherPath(toolsRoot, tool, platform);
    if (!existsSync(launcher)) {
      throw new Error(`Portable Python launcher is missing: ${launcher}`);
    }
    if (platform === "win32") {
      assertWindowsBinaryLauncher(readFileSync(launcher), { tool, toolsRoot });
    } else {
      assertRelativePythonLauncher(readFileSync(launcher, "utf8"), { tool, platform });
    }
    if (platform === "win32") {
      const forbiddenScript = path.join(toolsRoot, "bin", `${tool}.cmd`);
      const forbiddenBatch = path.join(toolsRoot, "bin", `${tool}.bat`);
      if (existsSync(forbiddenScript) || existsSync(forbiddenBatch)) {
        throw new Error(`${tool} must use only its compiled .exe launcher on Windows.`);
      }
    }
  }

  assertRuntimeProvenance(toolsRoot);
  return { toolsRoot, python };
}

export function assertRelativePythonLauncher(content, input) {
  const platform = input.platform ?? process.platform;
  const tool = input.tool;
  const normalized = String(content).replace(/\r\n/g, "\n");
  const moduleName = pythonModuleName(tool);
  if (/[A-Za-z]:[\\/]/u.test(normalized)) {
    throw new Error(`${tool} launcher contains an absolute Windows path.`);
  }
  if (normalized.includes("/Users/") || normalized.includes("/home/") || normalized.includes("\\\\")) {
    throw new Error(`${tool} launcher contains a build-machine path.`);
  }
  if (
    normalized.includes("dirname")
    || !normalized.includes("SELF_DIR=${0%/*}")
    || !normalized.includes("SELF_DIR=$(CDPATH= cd -- \"$SELF_DIR\" && pwd)")
  ) {
    throw new Error(`${tool} ${platform} launcher depends on host path-resolution tools.`);
  }

  const expected = `exec \"$SELF_DIR/../python-runtime/bin/python3\" -I -B -m ${moduleName} \"$@\"`;
  if (!normalized.includes(expected)) {
    throw new Error(`${tool} ${platform} launcher is not a relative embedded-Python wrapper.`);
  }
}

export function assertWindowsBinaryLauncher(binary, input) {
  if (input.platform && input.platform !== "win32") {
    throw new Error("Windows binary launcher verification requires the win32 platform.");
  }
  const bytes = Buffer.from(binary);
  if (bytes.byteLength < 1024 || bytes.subarray(0, 2).toString("ascii") !== "MZ") {
    throw new Error(`${input.tool} Windows launcher is not a native executable.`);
  }
  const sourceRoot = path.resolve(input.toolsRoot);
  const absoluteUtf8 = Buffer.from(sourceRoot, "utf8");
  const absoluteUtf16 = Buffer.from(sourceRoot, "utf16le");
  if (bytes.includes(absoluteUtf8) || bytes.includes(absoluteUtf16)) {
    throw new Error(`${input.tool} Windows launcher contains a build-machine path.`);
  }
}

export function createPortableRuntimeSmokeEnvironment(input = {}) {
  const platform = input.platform ?? process.platform;
  const inheritedEnv = input.inheritedEnv ?? process.env;
  const env = { ...inheritedEnv };
  const systemRoot = env.SystemRoot ?? env.SYSTEMROOT ?? "C:\\Windows";
  const windowsSystemRoot = path.win32.normalize(systemRoot);
  env.PATH = platform === "win32"
    ? `${path.win32.join(windowsSystemRoot, "System32")};${windowsSystemRoot}`
    : "/usr/bin:/bin:/usr/sbin:/sbin";
  env.PYTHONDONTWRITEBYTECODE = "1";
  delete env.PYTHONHOME;
  delete env.PYTHONPATH;
  delete env.VIRTUAL_ENV;
  delete env.CONDA_PREFIX;
  return env;
}

export function smokePortableRuntimeTree(input) {
  const platform = input.platform ?? process.platform;
  const runtime = assertPortableRuntimeTree({ toolsRoot: input.toolsRoot, platform });
  const env = createPortableRuntimeSmokeEnvironment({ platform, inheritedEnv: input.inheritedEnv });
  const probe = run(runtime.python, ["-I", "-B", "-c", "import sys; print(sys.executable); print(sys.prefix)"], { env });
  assertRuntimePathsConfined(probe.stdout, runtime.toolsRoot);

  for (const tool of Object.keys(PYTHON_SCANNER_MODULES)) {
    const launcher = pythonLauncherPath(runtime.toolsRoot, tool, platform);
    runLauncher(launcher, ["--version"], { platform, env });
  }
}

export function smokeRelocatedPortableRuntimeTree(input) {
  const source = path.resolve(input.toolsRoot);
  const destination = path.resolve(input.relocationPath);
  const platform = input.platform ?? process.platform;
  if (source === destination) {
    throw new Error("Portable runtime relocation smoke requires a distinct destination.");
  }
  verifyExtractedTree(source, { allowSafeSymlinks: platform !== "win32" });
  rmSync(destination, { recursive: true, force: true });
  try {
    cpSync(source, destination, {
      recursive: true,
      force: true,
      dereference: false,
      verbatimSymlinks: true,
    });
    verifyExtractedTree(destination, { allowSafeSymlinks: platform !== "win32" });
    smokePortableRuntimeTree({
      toolsRoot: destination,
      platform,
      inheritedEnv: input.inheritedEnv,
    });
  } finally {
    rmSync(destination, { recursive: true, force: true });
  }
}

function runLauncher(launcher, args, input) {
  run(launcher, args, { env: input.env });
}

function assertRuntimePathsConfined(stdout, toolsRoot) {
  const root = path.resolve(toolsRoot);
  const paths = stdout.split(/\r?\n/u).map((value) => value.trim()).filter(Boolean);
  if (paths.length < 2 || paths.some((value) => {
    const relative = path.relative(root, path.resolve(value));
    return relative.startsWith("..") || path.isAbsolute(relative);
  })) {
    throw new Error("Portable Python probe resolved an executable or prefix outside runtime-tools.");
  }
}

export function assertRuntimeProvenance(toolsRoot) {
  const manifestPath = path.join(toolsRoot, "manifest.json");
  if (!existsSync(manifestPath)) {
    throw new Error(`Portable runtime manifest is missing: ${manifestPath}`);
  }
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  if (
    manifest?.schemaVersion !== "4.0"
    || !Array.isArray(manifest.provenance)
    || !Array.isArray(manifest.files)
    || !/^[a-f0-9]{64}$/u.test(manifest.treeSha256 ?? "")
  ) {
    throw new Error("Portable runtime manifest does not bind its provenance files.");
  }
  const required = new Set([
    "runtime-assets",
    "python-lock-provenance",
    "python-direct-requirements",
    "python-platform-lock",
  ]);
  for (const entry of manifest.provenance) {
    if (!entry || typeof entry.id !== "string" || typeof entry.path !== "string") {
      throw new Error("Portable runtime manifest contains malformed provenance.");
    }
    if (!/^[a-f0-9]{64}$/u.test(entry.sha256 ?? "")) {
      throw new Error(`Portable runtime provenance ${entry.id} has no valid SHA-256.`);
    }
    const filePath = path.resolve(toolsRoot, entry.path);
    const relative = path.relative(path.resolve(toolsRoot), filePath);
    if (!relative || relative.startsWith("..") || path.isAbsolute(relative) || !existsSync(filePath)) {
      throw new Error(`Portable runtime provenance ${entry.id} escapes or is missing.`);
    }
    const actual = createHash("sha256").update(readFileSync(filePath)).digest("hex");
    if (actual !== entry.sha256) {
      throw new Error(`Portable runtime provenance hash mismatch for ${entry.id}.`);
    }
    required.delete(entry.id);
  }
  if (required.size > 0) {
    throw new Error(`Portable runtime manifest is missing provenance: ${[...required].join(", ")}.`);
  }
  const actualFiles = buildRuntimeFileManifest(toolsRoot);
  if (JSON.stringify(actualFiles) !== JSON.stringify(manifest.files)) {
    throw new Error("Portable runtime file manifest does not match the staged runtime tree.");
  }
  const actualTreeSha256 = createHash("sha256")
    .update(JSON.stringify(actualFiles))
    .digest("hex");
  if (actualTreeSha256 !== manifest.treeSha256) {
    throw new Error("Portable runtime tree hash does not match its manifest.");
  }
}

function assertConfinedRelativeLink(root, linkPath, target) {
  if (path.isAbsolute(target)) {
    throw new Error(`Runtime tree contains an absolute symbolic link: ${linkPath}`);
  }
  const resolved = path.resolve(path.dirname(linkPath), target);
  const relative = path.relative(root, resolved);
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error(`Runtime tree symbolic link escapes the bundle: ${linkPath}`);
  }
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function run(command, args, input) {
  const result = spawnSync(command, args, {
    env: input.env,
    shell: false,
    encoding: "utf8",
    windowsHide: true,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed with exit code ${result.status}: ${(result.stderr ?? "").trim()}`);
  }
  return { stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
}

function assertPythonTool(tool) {
  if (!(tool in PYTHON_SCANNER_MODULES)) {
    throw new Error(`Unsupported portable Python scanner tool: ${tool}`);
  }
}

function pythonModuleName(tool) {
  assertPythonTool(tool);
  return PYTHON_SCANNER_MODULES[tool];
}
