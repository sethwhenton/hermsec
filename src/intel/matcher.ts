import type { IntelRelevance, SecurityIntelItem, WorkspaceInventory } from "./schema.js";
import type { Finding } from "../shared/types.js";

function normalizeName(value: string): string {
  return value.toLowerCase();
}

function normalizeEcosystem(value: string): string {
  const normalized = normalizeName(value.trim());
  if (normalized === "python" || normalized === "pypi" || normalized === "pip") return "pypi";
  if (normalized === "node" || normalized === "javascript") return "npm";
  if (normalized === "cargo" || normalized === "crates") return "crates.io";
  if (normalized === "composer") return "packagist";
  if (normalized === "ruby") return "rubygems";
  return normalized;
}

function normalizeIdentifier(value: string): string {
  const normalized = value.trim().toUpperCase().replace(/_/g, "-");
  if (/^CVE-\d{4}-\d{4,}$/.test(normalized)) {
    return normalized;
  }
  if (/^GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(normalized)) {
    return normalized.toLowerCase();
  }
  return normalized;
}

function itemIdentifiers(item: SecurityIntelItem): Set<string> {
  return new Set(
    [...item.identifiers.cve, ...item.identifiers.ghsa, ...item.identifiers.osv]
      .map(normalizeIdentifier),
  );
}

function numericVersion(version: string): number[] {
  return version
    .replace(/^[^\d]*/, "")
    .split(/[.-]/)
    .map((part) => Number.parseInt(part, 10))
    .filter((part) => Number.isFinite(part));
}

function compareVersions(left: string, right: string): number {
  const a = numericVersion(left);
  const b = numericVersion(right);
  const length = Math.max(a.length, b.length);
  for (let index = 0; index < length; index += 1) {
    const av = a[index] ?? 0;
    const bv = b[index] ?? 0;
    if (av !== bv) {
      return av > bv ? 1 : -1;
    }
  }
  return 0;
}

function versionSatisfies(version: string, range: string): boolean {
  const chunks = range
    .replace(/[(),]/g, " ")
    .split(/\s+/)
    .filter(Boolean);
  if (chunks.length === 0 || range === "*" || range.toLowerCase() === "unknown") {
    return true;
  }

  for (let index = 0; index < chunks.length; index += 1) {
    const token = chunks[index] ?? "";
    const next = chunks[index + 1] ?? "";
    const expression = /^(<=|>=|<|>|=)?(.+)$/.exec(token);
    const operator = expression?.[1];
    const inlineVersion = expression?.[2];
    const comparisonVersion = operator ? inlineVersion : next && /^[0-9v]/i.test(next) ? next : inlineVersion;
    if (!comparisonVersion || !/[0-9]/.test(comparisonVersion)) {
      continue;
    }
    const comparison = compareVersions(version, comparisonVersion);
    const op = operator ?? (token === comparisonVersion ? "=" : token);
    if (op === "<" && !(comparison < 0)) return false;
    if (op === "<=" && !(comparison <= 0)) return false;
    if (op === ">" && !(comparison > 0)) return false;
    if (op === ">=" && !(comparison >= 0)) return false;
    if ((op === "=" || /^[0-9v]/i.test(op)) && comparison !== 0) return false;
  }

  return true;
}

function findingPackageAffected(
  findingPackage: NonNullable<Finding["package"]>,
  intelPackage: SecurityIntelItem["packages"][number],
): boolean {
  return packageAffected(
    {
      ecosystem: findingPackage.ecosystem,
      name: findingPackage.name,
      ...(findingPackage.installedVersion ? { version: findingPackage.installedVersion } : {}),
      direct: true,
      files: [],
    },
    intelPackage,
  );
}

export function packageAffected(
  inventoryPackage: WorkspaceInventory["packages"][number],
  intelPackage: SecurityIntelItem["packages"][number],
): boolean {
  if (normalizeEcosystem(inventoryPackage.ecosystem) !== normalizeEcosystem(intelPackage.ecosystem)) {
    return false;
  }
  if (normalizeName(inventoryPackage.name) !== normalizeName(intelPackage.name)) {
    return false;
  }
  if (!inventoryPackage.version || !intelPackage.affectedRange) {
    return true;
  }
  return versionSatisfies(inventoryPackage.version, intelPackage.affectedRange);
}

export function scoreIntelRelevance(item: SecurityIntelItem, inventory: WorkspaceInventory): IntelRelevance | undefined {
  let score = 0;
  const reasons: string[] = [];
  const matchedPackages: string[] = [];
  let matchedRuntime: string | undefined;

  for (const candidate of item.packages) {
    const matched = inventory.packages.filter((pkg) => packageAffected(pkg, candidate));
    for (const pkg of matched) {
      score += 70;
      if (pkg.direct) {
        score += 15;
      } else {
        score += 8;
      }
      const packageLabel = `${pkg.ecosystem}:${pkg.name}${pkg.version ? `@${pkg.version}` : ""}`;
      matchedPackages.push(packageLabel);
      reasons.push(
        `${pkg.direct ? "Direct" : "Transitive"} ${pkg.ecosystem} dependency ${pkg.name}${
          pkg.version ? `@${pkg.version}` : ""
        } matches ${candidate.affectedRange ?? "an affected package record"}`,
      );
    }
  }

  for (const runtime of inventory.runtimes) {
    const runtimeName = normalizeName(runtime.name);
    if (item.tags.includes("eol") && item.ecosystems.map(normalizeName).includes(runtimeName)) {
      score += 45;
      matchedRuntime = runtime.name;
      reasons.push(`${runtime.name}${runtime.version ? ` ${runtime.version}` : ""} matches an end-of-life notice`);
    }
  }

  const identifiers = [...item.identifiers.cve, ...item.identifiers.ghsa, ...item.identifiers.osv];
  const normalizedPreviousFindingIds = new Set(inventory.previousFindingIds.map(normalizeIdentifier));
  if (identifiers.some((identifier) => normalizedPreviousFindingIds.has(normalizeIdentifier(identifier)))) {
    score += 25;
    reasons.push("A previous finding referenced the same advisory identifier");
  }

  if (item.cisaKev?.knownExploited) {
    score += 25;
    reasons.push("CISA KEV marks this CVE as known exploited");
  }

  if (item.epss && item.epss.percentile >= 0.95) {
    score += 15;
    reasons.push(`EPSS percentile is ${item.epss.percentile}`);
  }

  if (score === 0 && item.ecosystems.some((ecosystem) => inventory.ecosystems.map(normalizeName).includes(normalizeName(ecosystem)))) {
    score += 5;
    reasons.push("Item matches one ecosystem used by this workspace");
  }

  if (score === 0) {
    return undefined;
  }

  const priority = score >= 95 || item.cisaKev?.knownExploited
    ? "urgent"
    : score >= 70
      ? "high"
      : score >= 25
        ? "normal"
        : "watch";

  return {
    itemId: item.id,
    workspaceId: inventory.workspaceId,
    score,
    reasons,
    matchedPackages: [...new Set(matchedPackages)],
    ...(matchedRuntime ? { matchedRuntime } : {}),
    priority,
  };
}

export function matchIntelToWorkspace(
  items: SecurityIntelItem[],
  inventory: WorkspaceInventory,
): IntelRelevance[] {
  return items
    .map((item) => scoreIntelRelevance(item, inventory))
    .filter((item): item is IntelRelevance => Boolean(item))
    .sort((a, b) => b.score - a.score || a.itemId.localeCompare(b.itemId));
}

export function buildWorkspaceInventoryFromFindings(
  workspaceId: string,
  findings: readonly Finding[],
  capturedAt = new Date().toISOString(),
): WorkspaceInventory {
  const packages = findings
    .map((finding) => finding.package)
    .filter((pkg): pkg is NonNullable<Finding["package"]> => Boolean(pkg))
    .map((pkg) => ({
      ecosystem: pkg.ecosystem,
      name: pkg.name,
      ...(pkg.installedVersion ? { version: pkg.installedVersion } : {}),
      direct: true,
      files: [],
    }))
    .filter(
      (pkg, index, all) =>
        all.findIndex(
          (candidate) =>
            normalizeName(candidate.ecosystem) === normalizeName(pkg.ecosystem) &&
            normalizeName(candidate.name) === normalizeName(pkg.name) &&
            candidate.version === pkg.version,
        ) === index,
    );
  const previousFindingIds = [
    ...new Set(
      findings.flatMap((finding) => [
        finding.id,
        finding.fingerprint,
        ...(finding.identifiers?.cve ?? []),
        ...(finding.identifiers?.ghsa ?? []),
        ...(finding.identifiers?.osv ?? []),
      ]),
    ),
  ];

  return {
    workspaceId,
    capturedAt,
    ecosystems: [...new Set(packages.map((pkg) => pkg.ecosystem))],
    packages,
    runtimes: [],
    frameworks: [],
    ciTools: [],
    dockerImages: [],
    previousFindingIds,
  };
}

export function matchIntelToFindings(
  items: SecurityIntelItem[],
  findings: readonly Finding[],
  workspaceId = "findings",
): IntelRelevance[] {
  return items
    .map((item) => scoreIntelAgainstFindings(item, findings, workspaceId))
    .filter((item): item is IntelRelevance => Boolean(item))
    .sort((a, b) => b.score - a.score || a.itemId.localeCompare(b.itemId));
}

export function scoreIntelAgainstFindings(
  item: SecurityIntelItem,
  findings: readonly Finding[],
  workspaceId = "findings",
): IntelRelevance | undefined {
  let score = 0;
  const reasons: string[] = [];
  const matchedPackages: string[] = [];
  const identifiers = itemIdentifiers(item);

  for (const finding of findings) {
    const findingIdentifiers = [
      ...(finding.identifiers?.cve ?? []),
      ...(finding.identifiers?.ghsa ?? []),
      ...(finding.identifiers?.osv ?? []),
    ].map(normalizeIdentifier);
    const identifierMatches = findingIdentifiers.filter((identifier) => identifiers.has(identifier));
    if (identifierMatches.length > 0) {
      score += 80;
      reasons.push(`Finding ${finding.id} references ${identifierMatches.join(", ")}`);
    }

    const findingPackage = finding.package;
    if (findingPackage) {
      const affectedPackage = item.packages.find((pkg) => findingPackageAffected(findingPackage, pkg));
      if (affectedPackage) {
        score += 70;
        const packageLabel = `${findingPackage.ecosystem}:${findingPackage.name}${
          findingPackage.installedVersion ? `@${findingPackage.installedVersion}` : ""
        }`;
        matchedPackages.push(packageLabel);
        reasons.push(`Finding ${finding.id} package ${packageLabel} matches ${affectedPackage.affectedRange ?? "an affected range"}`);
      }
    }

    const cweMatches = (finding.cwe ?? []).filter((cwe) => item.identifiers.cwe.includes(cwe.toUpperCase()));
    if (cweMatches.length > 0) {
      score += 10;
      reasons.push(`Finding ${finding.id} shares ${cweMatches.join(", ")}`);
    }
  }

  if (score === 0) {
    return undefined;
  }

  if (item.cisaKev?.knownExploited) {
    score += 25;
    reasons.push("CISA KEV marks this CVE as known exploited");
  }

  const priority = score >= 95 || item.cisaKev?.knownExploited
    ? "urgent"
    : score >= 70
      ? "high"
      : score >= 25
        ? "normal"
        : "watch";

  return {
    itemId: item.id,
    workspaceId,
    score,
    reasons,
    matchedPackages: [...new Set(matchedPackages)],
    priority,
  };
}
