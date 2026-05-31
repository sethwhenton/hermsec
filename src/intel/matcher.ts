import type { IntelRelevance, SecurityIntelItem, WorkspaceInventory } from "./schema.js";

function normalizeName(value: string): string {
  return value.toLowerCase();
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

export function packageAffected(
  inventoryPackage: WorkspaceInventory["packages"][number],
  intelPackage: SecurityIntelItem["packages"][number],
): boolean {
  if (normalizeName(inventoryPackage.ecosystem) !== normalizeName(intelPackage.ecosystem)) {
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
  if (identifiers.some((identifier) => inventory.previousFindingIds.includes(identifier))) {
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
