import path from "node:path";
import { stableId } from "../shared/text.js";
import type { Finding, FindingCategory } from "../shared/types.js";

export type FindingIdentityKind = "repository" | "dependency";

export type FindingLocationIdentity = {
  path: string;
  startLine?: number;
  endLine?: number;
};

export type FindingPackageIdentity = {
  ecosystem: string;
  name: string;
  installedVersion?: string;
  advisoryIds: string[];
};

export type StableFindingIdentity = {
  id: string;
  key: string;
  kind: FindingIdentityKind;
  category: FindingCategory;
  vulnerabilityClass: string;
  cwes: string[];
  mergeAnchor: string;
  groupAnchor: string;
  exactAnchors: string[];
  sinkAnchors: string[];
  location?: FindingLocationIdentity;
  dependency?: FindingPackageIdentity;
};

export type FindingIdentityOptions = {
  repoRoot?: string;
  vulnerabilityClass?: string;
  sinkAnchor?: string;
};

export type FindingCompatibilityOptions = {
  /** Retained for API compatibility; ranged physical sinks must overlap. */
  lineTolerance?: number;
};

const cweClassGroups: ReadonlyArray<readonly [string, readonly string[]]> = [
  ["sql-injection", ["CWE-89"]],
  ["command-injection", ["CWE-77", "CWE-78"]],
  ["cross-site-scripting", ["CWE-79"]],
  ["cross-site-request-forgery", ["CWE-352"]],
  ["server-side-request-forgery", ["CWE-918"]],
  ["path-traversal", ["CWE-22", "CWE-23", "CWE-36"]],
  ["code-injection", ["CWE-94", "CWE-95"]],
  ["unsafe-deserialization", ["CWE-502"]],
  ["xml-external-entity", ["CWE-611"]],
  ["open-redirect", ["CWE-601"]],
  ["unrestricted-upload", ["CWE-434"]],
  ["authentication", ["CWE-287", "CWE-306"]],
  ["authorization", ["CWE-862", "CWE-863"]],
  ["hardcoded-credential", ["CWE-259", "CWE-321", "CWE-798"]],
  ["sensitive-data-exposure", ["CWE-200", "CWE-312", "CWE-532"]],
  ["weak-cryptography", ["CWE-326", "CWE-327", "CWE-328"]],
  ["certificate-validation", ["CWE-295"]],
  ["cors-misconfiguration", ["CWE-942"]],
  ["debug-configuration", ["CWE-489"]],
  ["prototype-pollution", ["CWE-1321", "CWE-1333"]],
  ["resource-exhaustion", ["CWE-400", "CWE-770"]],
];

const semanticClassPatterns: ReadonlyArray<readonly [string, RegExp]> = [
  ["sql-injection", /\b(?:sql[-\s]?injection|sqli|raw[-\s]?query)\b/iu],
  ["command-injection", /\b(?:command|shell|os)[-\s]?injection\b|\b(?:child[_\s-]?process|exec|spawn|subprocess)\b/iu],
  ["cross-site-scripting", /\b(?:cross[-\s]?site[-\s]?scripting|xss|innerhtml|dangerouslysetinnerhtml)\b/iu],
  ["cross-site-request-forgery", /\b(?:cross[-\s]?site[-\s]?request[-\s]?forgery|csrf|xsrf)\b/iu],
  ["server-side-request-forgery", /\b(?:server[-\s]?side[-\s]?request[-\s]?forgery|ssrf)\b/iu],
  ["path-traversal", /\b(?:path|directory)[-\s]?traversal\b/iu],
  ["unsafe-deserialization", /\b(?:unsafe[-\s]?)?deseriali[sz]ation\b|\bpickle\b/iu],
  ["xml-external-entity", /\b(?:xml[-\s]?external[-\s]?entity|xxe)\b/iu],
  ["open-redirect", /\bopen[-\s]?redirect\b/iu],
  ["unrestricted-upload", /\bunrestricted[-\s]?(?:file[-\s]?)?upload\b/iu],
  ["authorization", /\b(?:authorization|authorisation|authz|access[-\s]?control)\b/iu],
  ["authentication", /\b(?:authentication|authn|missing[-\s]?auth)\b/iu],
  ["hardcoded-credential", /\b(?:hardcoded|embedded)[-\s]?(?:secret|credential|password|token|api[-\s]?key)\b/iu],
  ["sensitive-data-exposure", /\b(?:sensitive[-\s]?data|information[-\s]?exposure|secret[-\s]?log)\b/iu],
  ["weak-cryptography", /\b(?:weak|broken|insecure)[-\s]?(?:crypto|cryptography|hash|cipher)\b/iu],
  ["certificate-validation", /\b(?:certificate|tls)[-\s]?(?:validation|verification)\b/iu],
  ["cors-misconfiguration", /\bcors\b/iu],
  ["debug-configuration", /\bdebug[-\s]?(?:enabled|configuration|mode)\b/iu],
  ["prototype-pollution", /\bprototype[-\s]?pollution\b/iu],
  ["code-injection", /\b(?:code|expression|eval)[-\s]?injection\b|\bunsafe[-\s]?eval\b/iu],
];

const genericClasses = new Set([
  "code",
  "config",
  "dependency",
  "secret",
  "supply-chain",
  "security-finding",
]);

const ecosystemAliases = new Map<string, string>([
  ["cargo", "crates.io"],
  ["crate", "crates.io"],
  ["crates", "crates.io"],
  ["node", "npm"],
  ["nodejs", "npm"],
  ["pip", "pypi"],
  ["python", "pypi"],
]);

export function buildStableFindingIdentity(
  finding: Finding,
  options: FindingIdentityOptions = {},
): StableFindingIdentity {
  const cwes = normalizeCweList(finding.cwe);
  const vulnerabilityClass = normalizeVulnerabilityClass(
    options.vulnerabilityClass ?? inferVulnerabilityClass(finding, cwes),
  );
  const location = locationIdentity(finding, options.repoRoot);
  const dependency = finding.category === "dependency"
    ? packageIdentity(finding)
    : undefined;
  const exactAnchors = findingExactAnchors(
    finding,
    vulnerabilityClass,
    location,
    dependency,
  );
  const sinkAnchors = findingSinkAnchors(finding, options.sinkAnchor);

  if (finding.category === "dependency") {
    const mergeAnchor = dependency?.advisoryIds[0] !== undefined
      ? `advisory:${dependency.advisoryIds[0]}`
      : preferredExactAnchor(exactAnchors);
    const groupAnchor = [
      "dependency",
      finding.category,
      vulnerabilityClass,
      dependency ? packageKey(dependency) : "package:unknown",
      mergeAnchor,
    ].join("|");
    const key = [
      groupAnchor,
      `advisories:${dependency?.advisoryIds.join(",") ?? ""}`,
      `cwes:${cwes.join(",")}`,
    ].join("|");

    return {
      id: stableId(groupAnchor, "identity"),
      key,
      kind: "dependency",
      category: finding.category,
      vulnerabilityClass,
      cwes,
      mergeAnchor,
      groupAnchor,
      exactAnchors,
      sinkAnchors,
      ...(dependency ? { dependency } : {}),
    };
  }

  const locationAnchor = location?.startLine !== undefined
    ? `${location.path}:${location.startLine}-${location.endLine ?? location.startLine}`
    : location
      ? `${location.path}:unranged`
      : "unlocated";
  const mergeAnchor = location
    ? preferredSinkAnchor(sinkAnchors) ?? preferredExactAnchor(exactAnchors)
    : preferredExactAnchor(exactAnchors);
  const groupAnchor = [
    "repository",
    finding.category,
    vulnerabilityClass,
    locationAnchor,
    mergeAnchor,
  ].join("|");
  const key = [
    groupAnchor,
    `cwes:${cwes.join(",")}`,
    `exact:${exactAnchors.join(",")}`,
    `sink:${sinkAnchors.join(",")}`,
  ].join("|");

  return {
    id: stableId(groupAnchor, "identity"),
    key,
    kind: "repository",
    category: finding.category,
    vulnerabilityClass,
    cwes,
    mergeAnchor,
    groupAnchor,
    exactAnchors,
    sinkAnchors,
    ...(location ? { location } : {}),
  };
}

export function areFindingIdentitiesCompatible(
  left: StableFindingIdentity,
  right: StableFindingIdentity,
  _options: FindingCompatibilityOptions = {},
): boolean {
  if (
    left.kind !== right.kind ||
    left.category !== right.category ||
    left.vulnerabilityClass !== right.vulnerabilityClass
  ) {
    return false;
  }

  if (left.kind === "dependency" && right.kind === "dependency") {
    if (
      !isConcreteDependencyIdentity(left.dependency) ||
      !isConcreteDependencyIdentity(right.dependency)
    ) {
      return false;
    }
    if (packageKey(left.dependency) !== packageKey(right.dependency)) {
      return false;
    }
    const leftHasAdvisory = left.dependency.advisoryIds.length > 0;
    const rightHasAdvisory = right.dependency.advisoryIds.length > 0;
    if (!leftHasAdvisory || !rightHasAdvisory) {
      return false;
    }
    return hasOverlap(left.dependency.advisoryIds, right.dependency.advisoryIds);
  }

  if (!cwesAreCompatible(left.cwes, right.cwes, left.vulnerabilityClass)) {
    return false;
  }
  const sharedContent = hasAnchorOverlap(left.exactAnchors, right.exactAnchors, "content:");
  const sharedFingerprint = hasAnchorOverlap(
    left.exactAnchors,
    right.exactAnchors,
    "fingerprint:",
  );
  if (!left.location && !right.location) {
    return sharedContent || sharedFingerprint;
  }
  if (!left.location || !right.location || left.location.path !== right.location.path) {
    return false;
  }
  if (left.location.startLine === undefined || right.location.startLine === undefined) {
    return (
      sharedContent ||
      hasOverlap(left.sinkAnchors, right.sinkAnchors)
    ) &&
      left.location.startLine === undefined &&
      right.location.startLine === undefined;
  }

  const leftEnd = left.location.endLine ?? left.location.startLine;
  const rightEnd = right.location.endLine ?? right.location.startLine;
  const rangesOverlap = left.location.startLine <= rightEnd &&
    right.location.startLine <= leftEnd;
  return rangesOverlap && (
    sharedContent ||
    hasOverlap(left.sinkAnchors, right.sinkAnchors)
  );
}

export function inferVulnerabilityClass(
  finding: Finding,
  normalizedCwes: readonly string[] = normalizeCweList(finding.cwe),
): string {
  if (finding.category === "dependency") {
    return "dependency-advisory";
  }

  for (const [className, cwes] of cweClassGroups) {
    if (cwes.some((cwe) => normalizedCwes.includes(cwe))) {
      return className;
    }
  }

  const semanticText = `${finding.ruleId ?? ""} ${finding.title}`;
  for (const [className, pattern] of semanticClassPatterns) {
    if (pattern.test(semanticText)) {
      return className;
    }
  }

  if (normalizedCwes[0]) {
    return normalizedCwes[0].toLowerCase();
  }
  if (finding.category === "secret") {
    return "hardcoded-credential";
  }

  const ruleClass = normalizeVulnerabilityClass(finding.ruleId ?? "");
  if (ruleClass && !genericClasses.has(ruleClass)) {
    return `rule-${ruleClass}`;
  }
  return normalizeVulnerabilityClass(finding.category || "security-finding");
}

export function normalizeVulnerabilityClass(value: string): string {
  const normalized = value
    .normalize("NFKC")
    .toLowerCase()
    .replace(/[^a-z0-9]+/gu, "-")
    .replace(/^-+|-+$/gu, "");
  return normalized || "security-finding";
}

export function normalizeCweList(values: readonly string[] | undefined): string[] {
  const normalized = (values ?? []).flatMap((value) => {
    const match = value.trim().match(/^CWE[\s_-]*0*(\d{1,6})$/iu);
    return match?.[1] ? [`CWE-${Number.parseInt(match[1], 10)}`] : [];
  });
  return [...new Set(normalized)].sort(compareIdentifiers);
}

export function normalizeRepositoryPath(value: string, repoRoot?: string): string {
  const trimmed = value.trim();
  if (!trimmed) {
    return "";
  }

  if (repoRoot) {
    const windowsStyle = isWindowsPath(trimmed) || isWindowsPath(repoRoot);
    const pathApi = windowsStyle ? path.win32 : path.posix;
    const resolvedRoot = pathApi.resolve(repoRoot);
    const resolvedValue = pathApi.isAbsolute(trimmed)
      ? pathApi.resolve(trimmed)
      : pathApi.resolve(resolvedRoot, trimmed);
    const relative = pathApi.relative(resolvedRoot, resolvedValue);
    const outsideRoot = relative === ".." || relative.startsWith(`..${pathApi.sep}`);
    if (relative && !outsideRoot && !pathApi.isAbsolute(relative)) {
      return normalizeSlashPath(relative, windowsStyle);
    }
    if (relative === "") {
      return ".";
    }
  }

  return normalizeSlashPath(trimmed, isWindowsPath(trimmed));
}

export function normalizeAdvisoryIdentifier(value: string): string {
  const compact = value.trim().normalize("NFKC").toUpperCase().replace(/_/gu, "-");
  const cve = compact.match(/^CVE-(\d{4})-(\d{4,8})$/u);
  if (cve?.[1] && cve[2]) {
    return `CVE-${cve[1]}-${cve[2]}`;
  }
  return compact.replace(/\s+/gu, "");
}

export function advisoryIdentifiers(finding: Finding): string[] {
  return [
    ...(finding.identifiers?.cve ?? []),
    ...(finding.identifiers?.ghsa ?? []),
    ...(finding.identifiers?.osv ?? []),
  ]
    .map(normalizeAdvisoryIdentifier)
    .filter(Boolean)
    .filter((value, index, values) => values.indexOf(value) === index)
    .sort(compareIdentifiers);
}

function locationIdentity(
  finding: Finding,
  repoRoot: string | undefined,
): FindingLocationIdentity | undefined {
  if (!finding.location?.file) {
    return undefined;
  }
  const normalizedPath = normalizeRepositoryPath(finding.location.file, repoRoot);
  if (!normalizedPath) {
    return undefined;
  }

  const startLine = validLine(finding.location.startLine)
    ? finding.location.startLine
    : undefined;
  const rawEndLine = validLine(finding.location.endLine)
    ? finding.location.endLine
    : undefined;
  const endLine = startLine !== undefined && rawEndLine !== undefined
    ? Math.max(startLine, rawEndLine)
    : startLine;

  return {
    path: normalizedPath,
    ...(startLine !== undefined ? { startLine } : {}),
    ...(endLine !== undefined ? { endLine } : {}),
  };
}

function packageIdentity(finding: Finding): FindingPackageIdentity | undefined {
  if (!finding.package?.name || !finding.package.ecosystem) {
    return undefined;
  }
  const ecosystem = normalizeEcosystem(finding.package.ecosystem);
  const installedVersion = nonEmpty(finding.package.installedVersion);
  return {
    ecosystem,
    name: normalizePackageName(finding.package.name, ecosystem),
    ...(installedVersion ? { installedVersion } : {}),
    advisoryIds: advisoryIdentifiers(finding),
  };
}

function normalizeEcosystem(value: string): string {
  const normalized = value.trim().toLowerCase().replace(/\s+/gu, "");
  return ecosystemAliases.get(normalized) ?? normalized;
}

function normalizePackageName(value: string, ecosystem: string): string {
  const normalized = value.trim().normalize("NFKC").toLowerCase();
  return ecosystem === "pypi"
    ? normalized.replace(/[-_.]+/gu, "-")
    : normalized;
}

function packageKey(value: FindingPackageIdentity): string {
  return `${value.ecosystem}:${value.name}@${value.installedVersion ?? "<unknown>"}`;
}

function isConcreteDependencyIdentity(
  value: FindingPackageIdentity | undefined,
): value is FindingPackageIdentity & { installedVersion: string } {
  return Boolean(
    value?.ecosystem.trim() &&
    value.name.trim() &&
    value.installedVersion?.trim(),
  );
}

function cwesAreCompatible(
  left: readonly string[],
  right: readonly string[],
  vulnerabilityClass: string,
): boolean {
  if (left.length === 0 || right.length === 0) {
    return isSpecificClass(vulnerabilityClass);
  }
  if (hasOverlap(left, right)) {
    return true;
  }
  const leftFamilies = new Set(left.map(cweFamily));
  return right.some((cwe) => leftFamilies.has(cweFamily(cwe)));
}

function cweFamily(cwe: string): string {
  for (const [className, members] of cweClassGroups) {
    if (members.includes(cwe)) {
      return className;
    }
  }
  return cwe;
}

function isSpecificClass(value: string): boolean {
  return !genericClasses.has(value) && !value.startsWith("rule-hermsec-");
}

function hasOverlap(left: readonly string[], right: readonly string[]): boolean {
  if (left.length === 0 || right.length === 0) {
    return false;
  }
  const values = new Set(left);
  return right.some((value) => values.has(value));
}

function hasAnchorOverlap(
  left: readonly string[],
  right: readonly string[],
  prefix: string,
): boolean {
  return hasOverlap(
    left.filter((anchor) => anchor.startsWith(prefix)),
    right.filter((anchor) => anchor.startsWith(prefix)),
  );
}

function validLine(value: number | undefined): value is number {
  return value !== undefined && Number.isInteger(value) && value > 0;
}

function isWindowsPath(value: string): boolean {
  return /^[A-Za-z]:[\\/]/u.test(value) || /^\\\\/u.test(value) || value.includes("\\");
}

function normalizeSlashPath(value: string, caseInsensitive: boolean): string {
  const slashed = value.replace(/\\/gu, "/");
  const driveMatch = slashed.match(/^([A-Za-z]):\/(.*)$/u);
  if (driveMatch?.[1] !== undefined && driveMatch[2] !== undefined) {
    const rest = path.posix.normalize(`/${driveMatch[2]}`).replace(/^\/+/u, "");
    const normalized = `${driveMatch[1]}:/${rest}`;
    return caseInsensitive ? normalized.toLowerCase() : normalized;
  }
  const normalized = path.posix.normalize(slashed);
  const relative = normalized.replace(/^(?:\.\/)+/u, "");
  return caseInsensitive ? relative.toLowerCase() : relative;
}

function compareIdentifiers(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function findingExactAnchors(
  finding: Finding,
  vulnerabilityClass: string,
  location: FindingLocationIdentity | undefined,
  dependency: FindingPackageIdentity | undefined,
): string[] {
  const fingerprint = nonEmpty(finding.fingerprint);
  const content = JSON.stringify({
    category: finding.category,
    vulnerabilityClass,
    title: normalizeAnchorText(finding.title),
    description: normalizeAnchorText(finding.description),
    evidence: normalizeAnchorText(finding.evidence),
    remediation: normalizeAnchorText(finding.remediation),
    ruleId: normalizeAnchorText(finding.ruleId ?? ""),
    location,
    package: dependency
      ? {
          ecosystem: dependency.ecosystem,
          name: dependency.name,
          installedVersion: dependency.installedVersion ?? null,
        }
      : null,
  });
  return uniqueSorted([
    ...(fingerprint ? [`fingerprint:${normalizeAnchorText(fingerprint)}`] : []),
    `content:${stableId(content, "anchor")}`,
  ]);
}

function findingSinkAnchors(finding: Finding, explicitAnchor: string | undefined): string[] {
  const anchors: string[] = [];
  const normalizedExplicit = normalizeAnchorText(explicitAnchor ?? "");
  if (normalizedExplicit) {
    anchors.push(`sink-explicit:${stableId(normalizedExplicit, "anchor")}`);
  }

  const evidence = finding.evidence.normalize("NFKC");
  const callPattern = /[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*){0,4}\s*\([^;\r\n]{0,180}\)/gu;
  for (const match of evidence.matchAll(callPattern)) {
    const normalized = normalizeAnchorText(match[0]);
    if (normalized) {
      anchors.push(`sink-code:${stableId(normalized, "anchor")}`);
    }
  }

  const assignmentPattern = /[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*){1,4}\s*=\s*[^;\r\n]{1,160}/gu;
  for (const match of evidence.matchAll(assignmentPattern)) {
    const normalized = normalizeAnchorText(match[0]);
    if (normalized) {
      anchors.push(`sink-code:${stableId(normalized, "anchor")}`);
    }
  }

  const quotedCodePattern = /`([^`\r\n]{3,180})`/gu;
  for (const match of evidence.matchAll(quotedCodePattern)) {
    const normalized = normalizeAnchorText(match[1] ?? "");
    if (normalized) {
      anchors.push(`sink-code:${stableId(normalized, "anchor")}`);
    }
  }
  return uniqueSorted(anchors);
}

function preferredSinkAnchor(anchors: readonly string[]): string | undefined {
  return anchors.find((anchor) => anchor.startsWith("sink-explicit:")) ??
    anchors.find((anchor) => anchor.startsWith("sink-code:")) ??
    anchors[0];
}

function preferredExactAnchor(anchors: readonly string[]): string {
  return anchors.find((anchor) => anchor.startsWith("content:")) ??
    anchors[0] ??
    "exact:unknown";
}

function normalizeAnchorText(value: string): string {
  return value
    .normalize("NFKC")
    .toLowerCase()
    .replace(/\s+/gu, " ")
    .replace(/\s*([()[\]{},.;:=+\-*/])\s*/gu, "$1")
    .trim();
}

function uniqueSorted(values: readonly string[]): string[] {
  return [...new Set(values)].sort(compareIdentifiers);
}

function nonEmpty(value: string | undefined): string | undefined {
  const normalized = value?.trim();
  return normalized || undefined;
}
