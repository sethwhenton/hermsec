import fs from "node:fs/promises";
import path from "node:path";
import { walkSourceTree } from "../core/files.js";
import type { ReportIntelligenceItem } from "../reports/schema.js";
import type { Finding } from "../shared/types.js";
import { toPosixPath } from "../shared/paths.js";
import {
  matchIntelToFindings,
  matchIntelToWorkspace,
  packageAffected,
} from "./matcher.js";
import type {
  IntelFetcher,
  IntelFetchResult,
  IntelRelevance,
  IntelSource,
  SecurityIntelItem,
  WorkspaceInventory,
} from "./schema.js";
import { updateIntelCache } from "./updater.js";

export type VulnerabilityIntelligenceInput = {
  target: string;
  workspaceId: string;
  findings: readonly Finding[];
  mode: "auto" | "online" | "offline";
  now?: string;
  fetchers?: IntelFetcher[];
  sources?: IntelSource[];
};

export type VulnerabilityIntelligenceResult = {
  inventory: WorkspaceInventory;
  results: IntelFetchResult[];
  items: ReportIntelligenceItem[];
  status: "completed" | "skipped" | "failed";
  message: string;
};

type InventoryPackage = WorkspaceInventory["packages"][number];

const ecosystemLabels: Record<string, string> = {
  npm: "npm",
  pypi: "PyPI",
  pip: "PyPI",
  maven: "Maven",
  go: "Go",
  "crates.io": "crates.io",
  cargo: "crates.io",
  packagist: "Packagist",
  composer: "Packagist",
  rubygems: "RubyGems",
  ruby: "RubyGems",
};

export async function buildVulnerabilityIntelligence(
  input: VulnerabilityIntelligenceInput,
): Promise<VulnerabilityIntelligenceResult> {
  const capturedAt = input.now ?? new Date().toISOString();
  const inventory = await buildProjectInventory(input.target, input.workspaceId, input.findings, capturedAt);

  if (input.mode === "offline" && inventory.previousFindingIds.length === 0 && inventory.packages.length === 0) {
    return {
      inventory,
      results: [],
      items: [],
      status: "skipped",
      message: "No dependency inventory or advisory identifiers were available for offline intelligence matching.",
    };
  }

  const summary = await updateIntelCache({
    mode: input.mode,
    now: capturedAt,
    inventory,
    ...(input.fetchers ? { fetchers: input.fetchers } : {}),
    ...(input.sources ? { sources: input.sources } : {}),
  });
  const relevance = mergeRelevance([
    ...matchIntelToWorkspace(summary.items, inventory),
    ...matchIntelToFindings(summary.items, input.findings, input.workspaceId),
  ]);
  const itemsById = new Map(summary.items.map((item) => [item.id, item]));
  const reportItems = relevance
    .map((match) => {
      const item = itemsById.get(match.itemId);
      return item ? toReportIntelligenceItem(item, match, inventory, input.findings) : undefined;
    })
    .filter((item): item is ReportIntelligenceItem => Boolean(item))
    .filter((item, index, all) => all.findIndex((candidate) => candidate.id === item.id) === index)
    .sort(compareReportIntel);

  const sourceFailures = summary.results.filter((result) => result.status === "failed");
  const status = reportItems.length === 0 && sourceFailures.length === summary.results.length && summary.results.length > 0
    ? "failed"
    : "completed";
  const packageCount = inventory.packages.length;
  const message = reportItems.length > 0
    ? `Matched ${reportItems.length} advisory item(s) against ${packageCount} inventoried package(s).`
    : `No KEV or advisory matches were found against ${packageCount} inventoried package(s).`;

  return {
    inventory,
    results: summary.results,
    items: reportItems,
    status,
    message,
  };
}

export async function buildProjectInventory(
  target: string,
  workspaceId: string,
  findings: readonly Finding[],
  capturedAt = new Date().toISOString(),
): Promise<WorkspaceInventory> {
  const packages: InventoryPackage[] = [];
  for (const finding of findings) {
    if (!finding.package) {
      continue;
    }
    addPackage(packages, {
      ecosystem: normalizeEcosystem(finding.package.ecosystem),
      name: finding.package.name,
      ...(finding.package.installedVersion ? { version: finding.package.installedVersion } : {}),
      direct: true,
      files: [],
    });
  }

  const targetStats = await safeStat(target);
  if (targetStats?.isDirectory()) {
    const tree = await walkSourceTree(target, {
      maxFiles: 25_000,
      maxLockfileBytes: 10_000_000,
      maxTextFileBytes: 2_000_000,
    });
    for (const file of tree.files) {
      if (file.kind !== "manifest" && file.kind !== "lockfile" && file.kind !== "config") {
        continue;
      }
      const discovered = await parseDependencyFile(file.absolutePath, file.relativePath);
      for (const pkg of discovered) {
        addPackage(packages, pkg);
      }
    }
  }

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
    ecosystems: [...new Set(packages.map((pkg) => normalizeEcosystem(pkg.ecosystem)))],
    packages: packages.sort(compareInventoryPackages),
    runtimes: [],
    frameworks: [],
    ciTools: [],
    dockerImages: [],
    previousFindingIds,
  };
}

async function parseDependencyFile(absolutePath: string, relativePath: string): Promise<InventoryPackage[]> {
  const baseName = path.basename(absolutePath);
  try {
    const content = await fs.readFile(absolutePath, "utf8");
    if (baseName === "package-lock.json" || baseName === "npm-shrinkwrap.json") {
      return parsePackageLock(content, relativePath);
    }
    if (baseName === "package.json") {
      return parsePackageJson(content, relativePath);
    }
    if (/^requirements(?:[-\w]*)?\.txt$/i.test(baseName)) {
      return parseRequirementsTxt(content, relativePath);
    }
    if (baseName === "go.mod") {
      return parseGoMod(content, relativePath);
    }
    if (baseName === "Cargo.lock") {
      return parseCargoLock(content, relativePath);
    }
    if (baseName === "composer.lock") {
      return parseComposerLock(content, relativePath);
    }
    if (baseName === "Gemfile.lock") {
      return parseGemfileLock(content, relativePath);
    }
    if (baseName === "pom.xml") {
      return parsePomXml(content, relativePath);
    }
  } catch {
    return [];
  }
  return [];
}

function parsePackageLock(content: string, relativePath: string): InventoryPackage[] {
  const parsed = JSON.parse(content) as {
    packages?: Record<string, { version?: string; dependencies?: Record<string, string>; devDependencies?: Record<string, string>; optionalDependencies?: Record<string, string>; peerDependencies?: Record<string, string> }>;
    dependencies?: Record<string, { version?: string; dependencies?: Record<string, unknown> }>;
  };
  const packages: InventoryPackage[] = [];
  const root = parsed.packages?.[""];
  const direct = new Set([
    ...Object.keys(root?.dependencies ?? {}),
    ...Object.keys(root?.devDependencies ?? {}),
    ...Object.keys(root?.optionalDependencies ?? {}),
    ...Object.keys(root?.peerDependencies ?? {}),
  ]);

  if (parsed.packages) {
    for (const [entryPath, entry] of Object.entries(parsed.packages)) {
      if (!entryPath || !entry.version) {
        continue;
      }
      const name = packageNameFromNodeModulesPath(entryPath);
      if (!name) {
        continue;
      }
      addPackage(packages, {
        ecosystem: "npm",
        name,
        version: entry.version,
        direct: direct.has(name),
        files: [relativePath],
      });
    }
  }

  if (packages.length === 0 && parsed.dependencies) {
    for (const [name, entry] of Object.entries(parsed.dependencies)) {
      if (!entry.version) {
        continue;
      }
      addPackage(packages, {
        ecosystem: "npm",
        name,
        version: entry.version,
        direct: true,
        files: [relativePath],
      });
    }
  }

  return packages;
}

function parsePackageJson(content: string, relativePath: string): InventoryPackage[] {
  const parsed = JSON.parse(content) as {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
    optionalDependencies?: Record<string, string>;
    peerDependencies?: Record<string, string>;
  };
  const packages: InventoryPackage[] = [];
  for (const dependencies of [
    parsed.dependencies,
    parsed.devDependencies,
    parsed.optionalDependencies,
    parsed.peerDependencies,
  ]) {
    for (const [name, range] of Object.entries(dependencies ?? {})) {
      const version = exactVersion(range);
      if (!version) {
        continue;
      }
      addPackage(packages, {
        ecosystem: "npm",
        name,
        version,
        direct: true,
        files: [relativePath],
      });
    }
  }
  return packages;
}

function parseRequirementsTxt(content: string, relativePath: string): InventoryPackage[] {
  const packages: InventoryPackage[] = [];
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.replace(/#.*/, "").trim();
    const match = /^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*={2,3}\s*([A-Za-z0-9_.!+-]+)/.exec(line);
    if (!match?.[1] || !match[2]) {
      continue;
    }
    addPackage(packages, {
      ecosystem: "pypi",
      name: match[1],
      version: match[2],
      direct: true,
      files: [relativePath],
    });
  }
  return packages;
}

function parseGoMod(content: string, relativePath: string): InventoryPackage[] {
  const packages: InventoryPackage[] = [];
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.replace(/\/\/.*/, "").trim();
    const match = /^(?:require\s+)?([^\s()]+)\s+(v[0-9][^\s]+)/.exec(line);
    if (!match?.[1] || !match[2] || match[1] === "module") {
      continue;
    }
    addPackage(packages, {
      ecosystem: "go",
      name: match[1],
      version: match[2],
      direct: true,
      files: [relativePath],
    });
  }
  return packages;
}

function parseCargoLock(content: string, relativePath: string): InventoryPackage[] {
  const packages: InventoryPackage[] = [];
  const blocks = content.split(/\n\[\[package\]\]\r?\n/);
  for (const block of blocks) {
    const name = /^name\s*=\s*"([^"]+)"/m.exec(block)?.[1];
    const version = /^version\s*=\s*"([^"]+)"/m.exec(block)?.[1];
    if (!name || !version) {
      continue;
    }
    addPackage(packages, {
      ecosystem: "crates.io",
      name,
      version,
      direct: true,
      files: [relativePath],
    });
  }
  return packages;
}

function parseComposerLock(content: string, relativePath: string): InventoryPackage[] {
  const parsed = JSON.parse(content) as { packages?: Array<{ name?: string; version?: string }>; "packages-dev"?: Array<{ name?: string; version?: string }> };
  const packages: InventoryPackage[] = [];
  for (const entry of [...(parsed.packages ?? []), ...(parsed["packages-dev"] ?? [])]) {
    if (!entry.name || !entry.version) {
      continue;
    }
    addPackage(packages, {
      ecosystem: "packagist",
      name: entry.name,
      version: entry.version.replace(/^v/i, ""),
      direct: true,
      files: [relativePath],
    });
  }
  return packages;
}

function parseGemfileLock(content: string, relativePath: string): InventoryPackage[] {
  const packages: InventoryPackage[] = [];
  for (const rawLine of content.split(/\r?\n/)) {
    const match = /^\s{4}([A-Za-z0-9_.-]+)\s+\(([^)]+)\)/.exec(rawLine);
    if (!match?.[1] || !match[2]) {
      continue;
    }
    addPackage(packages, {
      ecosystem: "rubygems",
      name: match[1],
      version: match[2].split(/\s/)[0] ?? match[2],
      direct: true,
      files: [relativePath],
    });
  }
  return packages;
}

function parsePomXml(content: string, relativePath: string): InventoryPackage[] {
  const packages: InventoryPackage[] = [];
  const dependencyBlocks = content.match(/<dependency>[\s\S]*?<\/dependency>/g) ?? [];
  for (const block of dependencyBlocks) {
    const groupId = /<groupId>\s*([^<]+)\s*<\/groupId>/.exec(block)?.[1]?.trim();
    const artifactId = /<artifactId>\s*([^<]+)\s*<\/artifactId>/.exec(block)?.[1]?.trim();
    const version = /<version>\s*([^<${}]+)\s*<\/version>/.exec(block)?.[1]?.trim();
    if (!groupId || !artifactId || !version) {
      continue;
    }
    addPackage(packages, {
      ecosystem: "maven",
      name: `${groupId}:${artifactId}`,
      version,
      direct: true,
      files: [relativePath],
    });
  }
  return packages;
}

function toReportIntelligenceItem(
  item: SecurityIntelItem,
  relevance: IntelRelevance,
  inventory: WorkspaceInventory,
  findings: readonly Finding[],
): ReportIntelligenceItem | undefined {
  const findingIds = findingIdsForItem(item, findings);
  if (!isActionableRelevance(relevance, findingIds)) {
    return undefined;
  }
  const matchedPackage = bestMatchedPackage(item, relevance, inventory);
  const matchedIntelPackage = matchedPackage
    ? item.packages.find((candidate) => packageAffected(matchedPackage, candidate))
    : undefined;
  const identifiers = {
    cve: [...new Set(item.identifiers.cve)],
    ghsa: [...new Set(item.identifiers.ghsa)],
    osv: [...new Set(item.identifiers.osv)],
    cwe: [...new Set(item.identifiers.cwe)],
  };
  const packageLabel = matchedPackage
    ? `${displayEcosystem(matchedPackage.ecosystem)}:${matchedPackage.name}${matchedPackage.version ? `@${matchedPackage.version}` : ""}`
    : relevance.matchedPackages[0] ?? (item.packages[0] ? `${displayEcosystem(item.packages[0].ecosystem)}:${item.packages[0].name}` : "Scanner evidence");
  const severity = item.severity === "unknown" ? "unknown" : item.severity;
  const result: ReportIntelligenceItem = {
    id: item.id,
    title: item.title,
    source: sourceLabel(item),
    severity,
    knownExploited: Boolean(item.cisaKev?.knownExploited),
    ecosystem: matchedPackage ? displayEcosystem(matchedPackage.ecosystem) : displayEcosystem(item.ecosystems[0] ?? item.packages[0]?.ecosystem ?? "project"),
    packageLabel,
    identifiers,
    url: item.url,
    whyItMatters: item.summary ?? relevance.reasons[0] ?? "Trusted vulnerability intelligence matched this scan run.",
    matchedPackages: [...new Set(relevance.matchedPackages)],
    findingIds,
    reasons: [...new Set(relevance.reasons)],
    priority: relevance.priority,
    ...(matchedPackage ? { packageName: matchedPackage.name } : {}),
    ...(matchedPackage?.version ? { installedVersion: matchedPackage.version } : {}),
    ...(identifiers.cve[0] ? { cve: identifiers.cve[0] } : {}),
    ...(item.publishedAt ? { publishedAt: item.publishedAt } : {}),
    ...(item.modifiedAt ? { modifiedAt: item.modifiedAt } : {}),
    ...(matchedIntelPackage?.fixedVersion ? { fixVersion: matchedIntelPackage.fixedVersion } : {}),
  };
  return result;
}

function isActionableRelevance(relevance: IntelRelevance, findingIds: readonly string[]): boolean {
  return relevance.score >= 70 || relevance.matchedPackages.length > 0 || findingIds.length > 0;
}

function findingIdsForItem(item: SecurityIntelItem, findings: readonly Finding[]): string[] {
  const identifiers = new Set([
    ...item.identifiers.cve.map(normalizeIdentifier),
    ...item.identifiers.ghsa.map(normalizeIdentifier),
    ...item.identifiers.osv.map(normalizeIdentifier),
  ]);
  const ids: string[] = [];
  for (const finding of findings) {
    const findingIdentifiers = [
      ...(finding.identifiers?.cve ?? []),
      ...(finding.identifiers?.ghsa ?? []),
      ...(finding.identifiers?.osv ?? []),
    ].map(normalizeIdentifier);
    const identifierMatch = findingIdentifiers.some((identifier) => identifiers.has(identifier));
    const packageMatch = finding.package
      ? item.packages.some((candidate) => packageAffected({
          ecosystem: normalizeEcosystem(finding.package?.ecosystem ?? ""),
          name: finding.package?.name ?? "",
          ...(finding.package?.installedVersion ? { version: finding.package.installedVersion } : {}),
          direct: true,
          files: [],
        }, candidate))
      : false;
    if (identifierMatch || packageMatch) {
      ids.push(finding.id);
    }
  }
  return [...new Set(ids)].sort();
}

function bestMatchedPackage(
  item: SecurityIntelItem,
  relevance: IntelRelevance,
  inventory: WorkspaceInventory,
): InventoryPackage | undefined {
  const matchedLabels = new Set(relevance.matchedPackages.map((label) => label.toLowerCase()));
  return inventory.packages.find((pkg) => {
    const label = `${pkg.ecosystem}:${pkg.name}${pkg.version ? `@${pkg.version}` : ""}`.toLowerCase();
    return matchedLabels.has(label) && item.packages.some((candidate) => packageAffected(pkg, candidate));
  }) ?? inventory.packages.find((pkg) => item.packages.some((candidate) => packageAffected(pkg, candidate)));
}

function mergeRelevance(matches: readonly IntelRelevance[]): IntelRelevance[] {
  const byId = new Map<string, IntelRelevance>();
  for (const match of matches) {
    const previous = byId.get(match.itemId);
    if (!previous) {
      byId.set(match.itemId, { ...match, reasons: [...match.reasons], matchedPackages: [...match.matchedPackages] });
      continue;
    }
    const matchedRuntime = previous.matchedRuntime ?? match.matchedRuntime;
    byId.set(match.itemId, {
      ...previous,
      score: Math.max(previous.score, match.score),
      reasons: [...new Set([...previous.reasons, ...match.reasons])],
      matchedPackages: [...new Set([...previous.matchedPackages, ...match.matchedPackages])],
      priority: higherPriority(previous.priority, match.priority),
      ...(matchedRuntime ? { matchedRuntime } : {}),
    });
  }
  return [...byId.values()].sort((left, right) => right.score - left.score || left.itemId.localeCompare(right.itemId));
}

function higherPriority(
  left: IntelRelevance["priority"],
  right: IntelRelevance["priority"],
): IntelRelevance["priority"] {
  const rank: Record<IntelRelevance["priority"], number> = { urgent: 4, high: 3, normal: 2, watch: 1 };
  return rank[right] > rank[left] ? right : left;
}

function compareReportIntel(left: ReportIntelligenceItem, right: ReportIntelligenceItem): number {
  const priorityRank: Record<ReportIntelligenceItem["priority"], number> = { urgent: 0, high: 1, normal: 2, watch: 3 };
  const severityRank: Record<ReportIntelligenceItem["severity"], number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
    unknown: 5,
  };
  return (
    priorityRank[left.priority] - priorityRank[right.priority] ||
    Number(right.knownExploited) - Number(left.knownExploited) ||
    severityRank[left.severity] - severityRank[right.severity] ||
    left.title.localeCompare(right.title)
  );
}

function addPackage(packages: InventoryPackage[], candidate: InventoryPackage): void {
  const normalized: InventoryPackage = {
    ecosystem: normalizeEcosystem(candidate.ecosystem),
    name: candidate.name,
    ...(candidate.version ? { version: cleanVersion(candidate.version) } : {}),
    direct: candidate.direct,
    files: candidate.files.map(toPosixPath),
  };
  if (!normalized.name || normalized.name.startsWith("$")) {
    return;
  }
  const existing = packages.find(
    (pkg) =>
      normalizeEcosystem(pkg.ecosystem) === normalized.ecosystem &&
      pkg.name.toLowerCase() === normalized.name.toLowerCase() &&
      (pkg.version ?? "") === (normalized.version ?? ""),
  );
  if (!existing) {
    packages.push(normalized);
    return;
  }
  existing.direct = existing.direct || normalized.direct;
  existing.files = [...new Set([...existing.files, ...normalized.files])].sort();
}

function packageNameFromNodeModulesPath(entryPath: string): string | undefined {
  const parts = toPosixPath(entryPath).split("/");
  const nodeModulesIndex = parts.lastIndexOf("node_modules");
  const first = parts[nodeModulesIndex + 1];
  if (nodeModulesIndex < 0 || !first) {
    return undefined;
  }
  if (first.startsWith("@")) {
    const second = parts[nodeModulesIndex + 2];
    return second ? `${first}/${second}` : undefined;
  }
  return first;
}

function exactVersion(value: string): string | undefined {
  const trimmed = value.trim();
  const candidate = trimmed.replace(/^[=v]/i, "");
  return /^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9_.-]+)?$/.test(candidate) ? candidate : undefined;
}

function cleanVersion(value: string): string {
  return value.trim().replace(/^=+/, "");
}

function normalizeIdentifier(value: string): string {
  return value.trim().toUpperCase().replace(/_/g, "-");
}

function normalizeEcosystem(value: string): string {
  const normalized = value.trim().toLowerCase();
  if (normalized === "python" || normalized === "pypi" || normalized === "pip") return "pypi";
  if (normalized === "node" || normalized === "javascript") return "npm";
  if (normalized === "cargo" || normalized === "crates") return "crates.io";
  if (normalized === "composer") return "packagist";
  if (normalized === "ruby") return "rubygems";
  return normalized;
}

function displayEcosystem(value: string): string {
  const normalized = normalizeEcosystem(value);
  return ecosystemLabels[normalized] ?? value;
}

function sourceLabel(item: SecurityIntelItem): string {
  const labels: Record<SecurityIntelItem["source"], string> = {
    "cisa-kev": "CISA KEV",
    osv: "OSV",
    "github-advisory": "GitHub Advisory",
    nvd: "NVD",
    epss: "FIRST EPSS",
    "npm-audit": "npm audit",
    "deps-dev": "deps.dev",
    "openssf-scorecard": "OpenSSF Scorecard",
    endoflife: "endoflife.date",
    rss: "Security RSS",
    socket: "Socket",
    phylum: "Phylum",
    vendor: "HermSec",
  };
  const sources = item.provenance.normalizedFrom.length > 0 ? item.provenance.normalizedFrom : [item.source];
  return [...new Set(sources.map((source) => labels[source] ?? source))].join(", ");
}

function compareInventoryPackages(left: InventoryPackage, right: InventoryPackage): number {
  return (
    left.ecosystem.localeCompare(right.ecosystem) ||
    left.name.localeCompare(right.name) ||
    (left.version ?? "").localeCompare(right.version ?? "")
  );
}

async function safeStat(filePath: string): Promise<Awaited<ReturnType<typeof fs.stat>> | undefined> {
  try {
    return await fs.stat(filePath);
  } catch {
    return undefined;
  }
}
