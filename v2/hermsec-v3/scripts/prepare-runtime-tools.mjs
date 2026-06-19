import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  copyFileSync,
  cpSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { basename, extname, join, resolve } from "node:path";

const appRoot = resolve(import.meta.dirname, "..");
const platformKey = `${process.platform}-${process.arch}`;
const toolsRoot = resolve(appRoot, "resources/runtime-tools", platformKey);
const tempRoot = resolve(appRoot, ".runtime-tools-cache", platformKey);
const binDir = join(toolsRoot, "bin");

const nativeTools = [
  {
    id: "gitleaks",
    repo: "gitleaks/gitleaks",
    version: "v8.30.1",
    checksumAsset: "gitleaks_8.30.1_checksums.txt",
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
    checksumAsset: "osv-scanner_SHA256SUMS",
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
    checksumAsset: "checksums.txt",
    asset: ({ platform, arch }) =>
      platformArch(platform, arch, {
        "win32-x64": "pmg_Windows_x86_64.zip",
        "linux-x64": "pmg_Linux_x86_64.tar.gz",
        "linux-arm64": "pmg_Linux_arm64.tar.gz",
        "darwin-x64": "pmg_Darwin_all.tar.gz",
        "darwin-arm64": "pmg_Darwin_all.tar.gz",
      }),
    executable: executableName("pmg"),
  },
];

const pythonTools = [
  { id: "semgrep", package: "semgrep", version: "1.167.0", executable: executableName("semgrep") },
  { id: "bandit", package: "bandit", version: "1.9.4", executable: executableName("bandit") },
  { id: "pip-audit", package: "pip-audit", version: "2.10.1", executable: executableName("pip-audit") },
];

rmSync(toolsRoot, { recursive: true, force: true });
mkdirSync(binDir, { recursive: true });
mkdirSync(tempRoot, { recursive: true });

for (const tool of nativeTools) {
  await installNativeTool(tool);
}

installPythonTools();
writeManifest();
console.log(`Hermsec runtime tools prepared at ${toolsRoot}`);

async function installNativeTool(tool) {
  const assetName = tool.asset({ platform: process.platform, arch: process.arch });
  const assetPath = join(tempRoot, assetName);
  const checksumPath = join(tempRoot, tool.checksumAsset);
  const releaseBase = `https://github.com/${tool.repo}/releases/download/${tool.version}`;

  await downloadIfNeeded(`${releaseBase}/${assetName}`, assetPath);
  await downloadIfNeeded(`${releaseBase}/${tool.checksumAsset}`, checksumPath);
  assertChecksum(assetPath, checksumPath, assetName);

  const extractDir = join(tempRoot, `${tool.id}-extract`);
  rmSync(extractDir, { recursive: true, force: true });
  mkdirSync(extractDir, { recursive: true });

  let executablePath = assetPath;
  if (assetName.endsWith(".zip")) {
    run("powershell.exe", ["-NoProfile", "-Command", `Expand-Archive -Path ${psQuote(assetPath)} -DestinationPath ${psQuote(extractDir)} -Force`]);
    executablePath = findExecutable(extractDir, tool.executable);
  } else if (assetName.endsWith(".tar.gz")) {
    run("tar", ["-xzf", assetPath, "-C", extractDir]);
    executablePath = findExecutable(extractDir, tool.executable);
  }

  copyFileSync(executablePath, join(binDir, tool.executable));
}

function installPythonTools() {
  const uv = commandPath("uv");
  if (!uv) {
    throw new Error("uv is required to prepare bundled Python scanner tools. Install uv, then rerun prepare:runtime-tools.");
  }

  for (const tool of pythonTools) {
    run(uv, ["tool", "install", "--force", `${tool.package}==${tool.version}`]);
  }

  const uvToolDir = runText(uv, ["tool", "dir"]).trim();
  const pythonRoot = join(toolsRoot, "python");
  mkdirSync(pythonRoot, { recursive: true });

  for (const tool of pythonTools) {
    const source = join(uvToolDir, tool.id);
    if (!existsSync(source)) {
      throw new Error(`uv tool environment not found for ${tool.id}: ${source}`);
    }
    const target = join(pythonRoot, tool.id);
    cpSync(source, target, { recursive: true });
    const executable = join(target, process.platform === "win32" ? "Scripts" : "bin", tool.executable);
    if (!existsSync(executable)) {
      throw new Error(`Bundled Python scanner executable not found: ${executable}`);
    }
  }
}

function writeManifest() {
  const manifest = {
    schemaVersion: "1.0",
    generatedAt: new Date().toISOString(),
    platform: process.platform,
    arch: process.arch,
    tools: [
      ...nativeTools.map((tool) => ({ id: tool.id, version: tool.version, kind: "native" })),
      ...pythonTools.map((tool) => ({ id: tool.id, version: tool.version, kind: "python" })),
    ],
  };
  writeFileSync(join(toolsRoot, "manifest.json"), JSON.stringify(manifest, null, 2), "utf8");
}

async function downloadIfNeeded(url, destination) {
  if (existsSync(destination) && statSync(destination).size > 0) {
    return;
  }
  const response = await fetch(url, { headers: { "user-agent": "HermsecRuntimeBundler" } });
  if (!response.ok) {
    throw new Error(`Download failed (${response.status}) for ${url}`);
  }
  const bytes = Buffer.from(await response.arrayBuffer());
  writeFileSync(destination, bytes);
}

function assertChecksum(filePath, checksumsPath, assetName) {
  const checksums = readFileSync(checksumsPath, "utf8").split(/\r?\n/u);
  const entry = checksums.find((line) => line.includes(assetName));
  if (!entry) {
    throw new Error(`Checksum entry not found for ${assetName}`);
  }
  const expected = entry.trim().split(/\s+/u)[0]?.toLowerCase();
  const actual = createHash("sha256").update(readFileSync(filePath)).digest("hex");
  if (expected !== actual) {
    throw new Error(`Checksum mismatch for ${assetName}: expected ${expected}, got ${actual}`);
  }
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
  const suffixes = process.platform === "win32" ? [".exe", ".cmd", ".bat", ""] : [""];
  for (const dir of (process.env.PATH ?? "").split(process.platform === "win32" ? ";" : ":")) {
    for (const suffix of suffixes) {
      const candidate = join(dir, `${command}${suffix}`);
      if (existsSync(candidate)) return candidate;
    }
  }
  return undefined;
}

function run(command, args, cwd = appRoot) {
  const result = spawnSync(command, args, { cwd, stdio: "inherit", shell: false });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed with exit code ${result.status}`);
  }
}

function runText(command, args, cwd = appRoot) {
  const result = spawnSync(command, args, { cwd, encoding: "utf8", shell: false });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed with exit code ${result.status}: ${result.stderr}`);
  }
  return result.stdout;
}

function psQuote(value) {
  return `'${String(value).replace(/'/g, "''")}'`;
}
