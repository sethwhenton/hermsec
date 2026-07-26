import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

export const PYTHON_LOCK_TARGETS = Object.freeze([
  "win32-x64",
  "darwin-x64",
  "darwin-arm64",
  "linux-x64",
]);

const EXPECTED_DIRECT_REQUIREMENTS = Object.freeze({
  semgrep: "1.167.0",
  bandit: "1.9.4",
  "pip-audit": "2.10.1",
});

export function loadPythonLockConfiguration(scriptsDirectory, platformKey) {
  const scriptsRoot = path.resolve(scriptsDirectory);
  const provenancePath = path.join(scriptsRoot, "python-lock-provenance.json");
  const provenance = JSON.parse(readFileSync(provenancePath, "utf8"));
  if (provenance?.schemaVersion !== 1 || provenance.uvVersion !== "0.10.12") {
    throw new Error("Python scanner lock provenance is missing or uses an unexpected uv version.");
  }
  if (provenance.defaultIndex !== "https://pypi.org/simple") {
    throw new Error("Python scanner locks must be sourced only from the official PyPI simple index.");
  }

  const configuredTargets = Object.keys(provenance.targets ?? {}).sort();
  if (JSON.stringify(configuredTargets) !== JSON.stringify([...PYTHON_LOCK_TARGETS].sort())) {
    throw new Error("Python scanner lock provenance does not cover every supported release target.");
  }

  const target = provenance.targets?.[platformKey];
  if (!target || typeof target.lock !== "string" || typeof target.pythonPlatform !== "string") {
    throw new Error(`No fully hashed Python scanner lock is configured for ${platformKey}.`);
  }
  const lockPath = confinedPath(scriptsRoot, target.lock, "Python scanner lock");
  if (!existsSync(lockPath)) {
    throw new Error(`Python scanner lock is missing: ${lockPath}`);
  }
  const content = readFileSync(lockPath, "utf8");
  const packages = validateFullyHashedRequirements(content);
  for (const [name, version] of Object.entries(EXPECTED_DIRECT_REQUIREMENTS)) {
    if (packages.get(name) !== version) {
      throw new Error(`Python scanner lock must contain ${name}==${version}.`);
    }
  }

  return {
    lockPath,
    lockRelativePath: path.relative(scriptsRoot, lockPath).replaceAll("\\", "/"),
    packages,
    provenance,
    provenancePath,
    sourceRequirementsPath: confinedPath(
      scriptsRoot,
      provenance.sourceRequirements,
      "Python scanner source requirements",
    ),
    target,
  };
}

export function validateFullyHashedRequirements(content) {
  const normalized = String(content).replace(/\r\n/g, "\n");
  if (/^\s*(?:--index-url|--extra-index-url|--find-links|-e\s)/mu.test(normalized)) {
    throw new Error("Python scanner lock contains an alternate package source or editable requirement.");
  }
  if (/(?:git\+|https?:\/\/|file:|@(?:\s|$))/iu.test(stripComments(normalized))) {
    throw new Error("Python scanner lock contains a URL, VCS, file, or direct-reference dependency.");
  }

  const requirements = logicalRequirementLines(normalized);
  if (requirements.length === 0) {
    throw new Error("Python scanner lock contains no requirements.");
  }

  const packages = new Map();
  for (const requirement of requirements) {
    const packageMatch = requirement.match(/^([A-Za-z0-9][A-Za-z0-9_.-]*)==([^\s\\;]+)(?:\s|$)/u);
    if (!packageMatch) {
      throw new Error(`Python scanner lock contains a non-exact requirement: ${requirement}`);
    }
    const hashes = [...requirement.matchAll(/--hash=sha256:([a-f0-9]{64})(?=\s|$)/gu)];
    if (hashes.length === 0) {
      throw new Error(`Python scanner lock requirement has no SHA-256: ${packageMatch[1]}`);
    }
    const residue = requirement
      .replace(packageMatch[0].trim(), "")
      .replace(/--hash=sha256:[a-f0-9]{64}/gu, "")
      .trim();
    if (residue) {
      throw new Error(`Python scanner lock requirement contains unsupported options: ${requirement}`);
    }

    const name = normalizePackageName(packageMatch[1]);
    if (packages.has(name)) {
      throw new Error(`Python scanner lock contains duplicate requirement ${name}.`);
    }
    packages.set(name, packageMatch[2]);
  }
  return packages;
}

export function sha256File(filePath) {
  return createHash("sha256").update(readFileSync(filePath)).digest("hex");
}

function logicalRequirementLines(content) {
  const result = [];
  let current = "";
  for (const rawLine of content.split("\n")) {
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const continued = trimmed.endsWith("\\");
    const part = continued ? trimmed.slice(0, -1).trim() : trimmed;
    current = current ? `${current} ${part}` : part;
    if (!continued) {
      result.push(current);
      current = "";
    }
  }
  if (current) {
    throw new Error("Python scanner lock ends with an incomplete continuation.");
  }
  return result;
}

function stripComments(content) {
  return content
    .split("\n")
    .filter((line) => !line.trimStart().startsWith("#"))
    .join("\n");
}

function confinedPath(root, relativePath, label) {
  if (typeof relativePath !== "string" || path.isAbsolute(relativePath)) {
    throw new Error(`${label} must be a relative path.`);
  }
  const resolved = path.resolve(root, relativePath);
  const relative = path.relative(root, resolved);
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error(`${label} escapes the packaging scripts directory.`);
  }
  return resolved;
}

function normalizePackageName(name) {
  return name.toLowerCase().replace(/[-_.]+/gu, "-");
}
