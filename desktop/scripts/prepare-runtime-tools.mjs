import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { basename, extname, join, resolve } from "node:path";
import {
  preflightArchive,
  verifyExtractedTree,
} from "./runtime-archive-safety.mjs";
import {
  loadPythonLockConfiguration,
  sha256File,
} from "./runtime-locks.mjs";
import {
  assertPortablePythonTarget,
  createRuntimeManifest,
  portablePythonExecutable,
  pythonLauncherPath,
  relativePythonLauncherContent,
  smokePortableRuntimeTree,
  smokeRelocatedPortableRuntimeTree,
} from "./runtime-python-layout.mjs";
import {
  buildPortablePythonLauncher,
  findPortableLauncherCompiler,
} from "./portable-python-launcher-build.mjs";

const appRoot = resolve(import.meta.dirname, "..");
const platformKey = assertPortablePythonTarget();
const toolsRoot = resolve(appRoot, "resources/runtime-tools", platformKey);
const tempRoot = resolve(appRoot, ".runtime-tools-cache", platformKey);
const binDir = join(toolsRoot, "bin");
const pythonRuntimeRoot = join(toolsRoot, "python-runtime");
const pinnedAssetManifestPath = resolve(import.meta.dirname, "runtime-asset-checksums.json");
const pinnedAssetManifest = loadPinnedAssetManifest();
const pythonLock = loadPythonLockConfiguration(import.meta.dirname, platformKey);
const uvConfigPath = resolve(import.meta.dirname, "runtime-uv.toml");
const UV_VERSION = "0.10.12";

const nativeTools = [
  {
    id: "gitleaks",
    repo: "gitleaks/gitleaks",
    version: "v8.30.1",
    asset: ({ platform, arch }) => {
      const version = "8.30.1";
      const mapped = platformArch(platform, arch, {
        "win32-x64": "windows_x64.zip",
        "win32-arm64": "windows_arm64.zip",
        "linux-x64": "linux_x64.tar.gz",
        "linux-arm64": "linux_arm64.tar.gz",
        "darwin-x64": "darwin_x64.tar.gz",
        "darwin-arm64": "darwin_arm64.tar.gz",
      });
      return `gitleaks_${version}_${mapped}`;
    },
    executable: executableName("gitleaks"),
  },
  {
    id: "osv-scanner",
    repo: "google/osv-scanner",
    version: "v2.4.0",
    asset: ({ platform, arch }) => {
      const mapped = platformArch(platform, arch, {
        "win32-x64": "windows_amd64.exe",
        "win32-arm64": "windows_arm64.exe",
        "linux-x64": "linux_amd64",
        "linux-arm64": "linux_arm64",
        "darwin-x64": "darwin_amd64",
        "darwin-arm64": "darwin_arm64",
      });
      return `osv-scanner_${mapped}`;
    },
    executable: executableName("osv-scanner"),
  },
  {
    id: "pmg",
    repo: "safedep/pmg",
    version: "v0.19.1",
    asset: ({ platform, arch }) =>
      platformArch(platform, arch, {
        "win32-x64": "pmg_Windows_x86_64.zip",
        "linux-x64": "pmg_Linux_x86_64.tar.gz",
        "linux-arm64": "pmg_Linux_arm64.tar.gz",
        "darwin-x64": "pmg_Darwin_all.tar.gz",
        "darwin-arm64": "pmg_Darwin_all.tar.gz",
      }),
    executable: executableName("pmg"),
    smokeArgs: ["version"],
  },
];

const portablePython = {
  id: "python-build-standalone",
  repo: "astral-sh/python-build-standalone",
  version: "20250612",
  asset: ({ platform, arch }) =>
    platformArch(platform, arch, {
      "win32-x64": "cpython-3.12.11+20250612-x86_64-pc-windows-msvc-install_only_stripped.tar.gz",
      "darwin-x64": "cpython-3.12.11+20250612-x86_64-apple-darwin-install_only_stripped.tar.gz",
      "darwin-arm64": "cpython-3.12.11+20250612-aarch64-apple-darwin-install_only_stripped.tar.gz",
      "linux-x64": "cpython-3.12.11+20250612-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz",
    }),
};

const pythonTools = [
  { id: "semgrep", package: "semgrep", version: "1.167.0" },
  { id: "bandit", package: "bandit", version: "1.9.4" },
  { id: "pip-audit", package: "pip-audit", version: "2.10.1" },
];

rmSync(toolsRoot, { recursive: true, force: true });
mkdirSync(binDir, { recursive: true });
mkdirSync(tempRoot, { recursive: true });

for (const tool of nativeTools) {
  await installNativeTool(tool);
}

await installPortablePython();
installPythonTools();
writePythonLaunchers();
const stagedProvenance = stageRuntimeProvenance();
writeManifest(stagedProvenance);
smokeStagedRuntime();
console.log(`Hermsec runtime tools prepared at ${toolsRoot}`);

async function installNativeTool(tool) {
  const assetName = tool.asset({ platform: process.platform, arch: process.arch });
  const pinnedAsset = resolvePinnedAsset(tool, assetName);
  const assetPath = join(tempRoot, assetName);

  await downloadIfNeeded(pinnedAsset.url, assetPath);
  assertPinnedChecksum(assetPath, pinnedAsset);

  const extractDir = join(tempRoot, `${tool.id}-extract`);
  rmSync(extractDir, { recursive: true, force: true });
  mkdirSync(extractDir, { recursive: true });

  let executablePath = assetPath;
  if (assetName.endsWith(".zip")) {
    extractArchive(assetPath, extractDir, { allowSafeSymlinks: false });
    executablePath = findExecutable(extractDir, tool.executable);
  } else if (assetName.endsWith(".tar.gz")) {
    extractArchive(assetPath, extractDir, { allowSafeSymlinks: false });
    executablePath = findExecutable(extractDir, tool.executable);
  }

  const stagedExecutable = join(binDir, tool.executable);
  copyFileSync(executablePath, stagedExecutable);
  if (process.platform !== "win32") {
    chmodSync(stagedExecutable, 0o755);
  }
}

async function installPortablePython() {
  const assetName = portablePython.asset({ platform: process.platform, arch: process.arch });
  const pinnedAsset = resolvePinnedAsset(portablePython, assetName);
  const assetPath = join(tempRoot, assetName);
  await downloadIfNeeded(pinnedAsset.url, assetPath);
  assertPinnedChecksum(assetPath, pinnedAsset);

  const extractDir = join(tempRoot, "python-runtime-extract");
  rmSync(extractDir, { recursive: true, force: true });
  mkdirSync(extractDir, { recursive: true });
  extractArchive(assetPath, extractDir, { allowSafeSymlinks: process.platform !== "win32" });

  const extractedRuntime = findPortablePythonRoot(extractDir);
  rmSync(pythonRuntimeRoot, { recursive: true, force: true });
  renameSync(extractedRuntime, pythonRuntimeRoot);

  const python = portablePythonExecutable(toolsRoot);
  const version = runText(python, ["-I", "--version"]).trim();
  if (version !== "Python 3.12.11") {
    throw new Error(`Unexpected embedded Python version: ${version || "no version output"}.`);
  }
}

function installPythonTools() {
  const uv = commandPath("uv");
  if (!uv) {
    throw new Error(`uv ${UV_VERSION} is required to prepare bundled Python scanner tools.`);
  }
  assertUvVersion(uv);

  const python = portablePythonExecutable(toolsRoot);
  const environment = {
    ...process.env,
    UV_NO_PROGRESS: "1",
    UV_PYTHON_DOWNLOADS: "never",
    UV_LINK_MODE: "copy",
    UV_DEFAULT_INDEX: "https://pypi.org/simple",
  };
  for (const name of [
    "UV_INDEX",
    "UV_EXTRA_INDEX_URL",
    "UV_FIND_LINKS",
    "UV_INDEX_URL",
    "PIP_INDEX_URL",
    "PIP_EXTRA_INDEX_URL",
    "PIP_FIND_LINKS",
  ]) {
    delete environment[name];
  }
  run(uv, [
    "--config-file",
    uvConfigPath,
    "pip",
    "install",
    "--python",
    python,
    "--system",
    "--break-system-packages",
    "--strict",
    "--exact",
    "--require-hashes",
    "--no-deps",
    "--only-binary",
    ":all:",
    "--default-index",
    "https://pypi.org/simple",
    "--link-mode",
    "copy",
    "--requirement",
    pythonLock.lockPath,
  ], { env: environment });

  run(python, ["-I", "-c", "import bandit, pip_audit, semgrep; print('embedded Python scanners ready')"]);
}

function writePythonLaunchers() {
  if (process.platform === "win32") {
    writeWindowsNativeLaunchers();
    return;
  }
  for (const tool of pythonTools) {
    const launcher = pythonLauncherPath(toolsRoot, tool.id);
    writeFileSync(launcher, relativePythonLauncherContent(tool.id), "utf8");
    chmodSync(launcher, 0o755);
  }
}

function writeWindowsNativeLaunchers() {
  const source = resolve(import.meta.dirname, "portable-python-launcher.c");
  const compiledLauncher = join(binDir, "hermsec-python-launcher.exe");
  const allowMinGw = process.env.HERMSEC_ALLOW_MINGW_LAUNCHER === "true";
  const compiler = findPortableLauncherCompiler({ allowMinGw });
  if (!compiler) {
    throw new Error(
      "Windows portable scanner launchers require MSVC (cl.exe). "
      + "Install Visual C++ Build Tools, or deliberately opt into the tested MinGW fallback "
      + "with HERMSEC_ALLOW_MINGW_LAUNCHER=true.",
    );
  }
  buildPortablePythonLauncher({ sourcePath: source, outputPath: compiledLauncher, compiler, allowMinGw });

  for (const tool of pythonTools) {
    copyFileSync(compiledLauncher, pythonLauncherPath(toolsRoot, tool.id));
  }
  rmSync(compiledLauncher, { force: true });
}

function smokeStagedRuntime() {
  for (const tool of nativeTools) {
    run(join(binDir, tool.executable), tool.smokeArgs ?? ["--version"]);
  }

  smokePortableRuntimeTree({ toolsRoot });
  smokeRelocatedPortableRuntimeTree({
    toolsRoot,
    relocationPath: join(tempRoot, "relocated-runtime-tools"),
  });
}

function stageRuntimeProvenance() {
  const provenanceRoot = join(toolsRoot, "provenance");
  const lockRoot = join(provenanceRoot, "python-locks");
  mkdirSync(lockRoot, { recursive: true });
  const files = [
    {
      id: "runtime-assets",
      source: pinnedAssetManifestPath,
      destination: join(provenanceRoot, "runtime-asset-checksums.json"),
    },
    {
      id: "python-lock-provenance",
      source: pythonLock.provenancePath,
      destination: join(provenanceRoot, "python-lock-provenance.json"),
    },
    {
      id: "python-direct-requirements",
      source: pythonLock.sourceRequirementsPath,
      destination: join(provenanceRoot, "python-scanners.in"),
    },
    {
      id: "python-platform-lock",
      source: pythonLock.lockPath,
      destination: join(lockRoot, `${platformKey}.txt`),
    },
  ];
  return files.map((file) => {
    copyFileSync(file.source, file.destination);
    return {
      id: file.id,
      path: file.destination.slice(toolsRoot.length + 1).replaceAll("\\", "/"),
      sha256: sha256File(file.destination),
    };
  });
}

function writeManifest(provenanceFiles) {
  const portablePythonAsset = portablePython.asset({ platform: process.platform, arch: process.arch });
  const manifest = createRuntimeManifest({
    toolsRoot,
    platform: process.platform,
    arch: process.arch,
    provenance: provenanceFiles,
    portablePython: {
      version: "3.12.11",
      sourceRelease: portablePython.version,
      asset: portablePythonAsset,
      executable: process.platform === "win32" ? "python-runtime/python.exe" : "python-runtime/bin/python3",
      lockTarget: pythonLock.target.pythonPlatform,
      lockedPackageCount: pythonLock.packages.size,
    },
    tools: [
      ...nativeTools.map((tool) => ({ id: tool.id, version: tool.version, kind: "native" })),
      ...pythonTools.map((tool) => ({ id: tool.id, version: tool.version, kind: "python-module" })),
    ],
  });
  writeFileSync(join(toolsRoot, "manifest.json"), JSON.stringify(manifest, null, 2), "utf8");
}

function extractArchive(assetPath, extractDir, options) {
  preflightArchive(assetPath, options);
  run("tar", ["-xf", assetPath, "-C", extractDir]);
  verifyExtractedTree(extractDir, options);
}

async function downloadIfNeeded(url, destination) {
  if (existsSync(destination) && statSync(destination).size > 0) {
    return;
  }
  const response = await fetch(url, { headers: { "user-agent": "HermsecRuntimeBundler" } });
  if (!response.ok) {
    throw new Error(`Download failed (${response.status}) for ${url}`);
  }
  const temporaryDestination = `${destination}.partial`;
  const bytes = Buffer.from(await response.arrayBuffer());
  writeFileSync(temporaryDestination, bytes);
  renameSync(temporaryDestination, destination);
}

function loadPinnedAssetManifest() {
  const parsed = JSON.parse(readFileSync(pinnedAssetManifestPath, "utf8"));
  if (!parsed || parsed.schemaVersion !== 2 || !Array.isArray(parsed.assets)) {
    throw new Error(`Pinned runtime asset manifest is invalid: ${pinnedAssetManifestPath}`);
  }
  return parsed;
}

function resolvePinnedAsset(tool, assetName) {
  const expectedUrl = releaseAssetUrl(tool.repo, tool.version, assetName);
  const pinnedAsset = pinnedAssetManifest.assets.find((asset) =>
    asset.tool === tool.id && asset.version === tool.version && asset.asset === assetName,
  );
  if (!pinnedAsset) {
    throw new Error(`No source-pinned SHA-256 is configured for ${tool.id} ${tool.version} asset ${assetName}.`);
  }
  if (pinnedAsset.url !== expectedUrl) {
    throw new Error(`Pinned URL for ${assetName} does not match its exact official versioned release URL.`);
  }
  if (!/^[a-f0-9]{64}$/u.test(pinnedAsset.sha256)) {
    throw new Error(`Pinned SHA-256 for ${assetName} is invalid.`);
  }
  return pinnedAsset;
}

function releaseAssetUrl(repo, version, assetName) {
  return `https://github.com/${repo}/releases/download/${version}/${encodeURIComponent(assetName)}`;
}

function assertPinnedChecksum(filePath, pinnedAsset) {
  const actual = createHash("sha256").update(readFileSync(filePath)).digest("hex");
  if (pinnedAsset.sha256 !== actual) {
    throw new Error(`Checksum mismatch for ${pinnedAsset.asset}: expected ${pinnedAsset.sha256}, got ${actual}`);
  }
}

function findPortablePythonRoot(directory) {
  const roots = readdirSync(directory, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => join(directory, entry.name));
  const root = roots.find(isPortablePythonRoot);
  if (!root) {
    throw new Error(`Could not find the portable Python root under ${directory}.`);
  }
  return root;
}

function isPortablePythonRoot(directory) {
  const executable = process.platform === "win32"
    ? join(directory, "python.exe")
    : join(directory, "bin", "python3");
  return existsSync(executable);
}

function findExecutable(directory, name) {
  const entries = findFiles(directory);
  const match = entries.find((entry) => basename(entry).toLowerCase() === name.toLowerCase());
  if (!match) {
    throw new Error(`Could not find ${name} under ${directory}`);
  }
  return match;
}

function findFiles(directory) {
  const results = [];
  const stack = [directory];
  while (stack.length > 0) {
    const current = stack.pop();
    const entries = readDirectory(current);
    for (const entry of entries) {
      if (entry.type === "directory") {
        stack.push(entry.path);
      } else {
        results.push(entry.path);
      }
    }
  }
  return results;
}

function readDirectory(directory) {
  return readdirSync(directory, { withFileTypes: true }).map((entry) => ({
    path: join(directory, entry.name),
    type: entry.isDirectory() ? "directory" : "file",
  }));
}

function platformArch(platform, arch, values) {
  const value = values[`${platform}-${arch}`];
  if (!value) {
    throw new Error(`No bundled scanner asset configured for ${platform}-${arch}`);
  }
  return value;
}

function executableName(name) {
  return process.platform === "win32" && !extname(name) ? `${name}.exe` : name;
}

function commandPath(command) {
  // Build tools execute directly with shell:false. Windows command scripts are
  // intentionally never considered because they require a command interpreter.
  const suffixes = process.platform === "win32" ? [".exe"] : [""];
  for (const dir of (process.env.PATH ?? "").split(process.platform === "win32" ? ";" : ":")) {
    for (const suffix of suffixes) {
      const candidate = join(dir, `${command}${suffix}`);
      if (existsSync(candidate)) return candidate;
    }
  }
  return undefined;
}

function assertUvVersion(uv) {
  const version = runText(uv, ["--version"]).trim();
  if (!new RegExp(`^uv ${UV_VERSION.replace(/\./gu, "\\.")}(?:\\s|$)`, "u").test(version)) {
    throw new Error(`Expected uv ${UV_VERSION} for portable scanner staging, found ${version || "no version output"}.`);
  }
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd ?? appRoot,
    stdio: "inherit",
    shell: false,
    env: options.env ?? process.env,
    windowsHide: true,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed with exit code ${result.status}`);
  }
}

function runText(command, args) {
  const result = spawnSync(command, args, {
    cwd: appRoot,
    encoding: "utf8",
    shell: false,
    windowsHide: true,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed with exit code ${result.status}: ${(result.stderr ?? "").trim()}`);
  }
  return result.stdout ?? "";
}
