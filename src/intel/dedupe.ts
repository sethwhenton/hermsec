import crypto from "node:crypto";
import type { IntelSeverity, IntelSource, SecurityIntelItem } from "./schema.js";

const severityRank: Record<IntelSeverity, number> = {
  unknown: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

function unique(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))].sort();
}

function canonicalKey(item: SecurityIntelItem): string {
  const cves = unique(item.identifiers.cve);
  if (cves.length > 0) {
    return `cve:${cves.join(",")}`;
  }
  const ghsa = unique(item.identifiers.ghsa);
  if (ghsa.length > 0) {
    return `ghsa:${ghsa[0] ?? ""}`;
  }
  const osv = unique(item.identifiers.osv);
  if (osv.length > 0) {
    return `osv:${osv[0] ?? ""}`;
  }
  const packageKey = item.packages
    .map((pkg) => `${pkg.ecosystem}:${pkg.name}:${pkg.affectedRange ?? ""}`)
    .sort()[0];
  if (packageKey) {
    return `package:${packageKey}`;
  }
  return `url:${crypto.createHash("sha256").update(item.url).digest("hex")}`;
}

function pickSeverity(a: IntelSeverity, b: IntelSeverity): IntelSeverity {
  return severityRank[b] > severityRank[a] ? b : a;
}

function mergeSources(a: IntelSource[], b: IntelSource[]): IntelSource[] {
  return [...new Set([...a, ...b])].sort() as IntelSource[];
}

export function mergeIntelItems(a: SecurityIntelItem, b: SecurityIntelItem): SecurityIntelItem {
  const severity = pickSeverity(a.severity, b.severity);
  const modifiedAt = [a.modifiedAt, b.modifiedAt]
    .filter((value): value is string => Boolean(value))
    .sort()
    .at(-1);
  const cvss = a.cvss?.score && b.cvss?.score
    ? a.cvss.score >= b.cvss.score
      ? a.cvss
      : b.cvss
    : a.cvss ?? b.cvss;
  const epss = a.epss?.percentile && b.epss?.percentile
    ? a.epss.percentile >= b.epss.percentile
      ? a.epss
      : b.epss
    : a.epss ?? b.epss;
  const cisaKev = a.cisaKev ?? b.cisaKev;
  const rawSnapshotPath = a.provenance.rawSnapshotPath ?? b.provenance.rawSnapshotPath;
  const summary = a.summary ?? b.summary;
  const publishedAt = a.publishedAt ?? b.publishedAt;
  return {
    ...a,
    sourceIds: unique([...a.sourceIds, ...b.sourceIds]),
    title: a.title.length >= b.title.length ? a.title : b.title,
    ...(summary ? { summary } : {}),
    url: a.url || b.url,
    ...(publishedAt ? { publishedAt } : {}),
    ...(modifiedAt ? { modifiedAt } : {}),
    identifiers: {
      cve: unique([...a.identifiers.cve, ...b.identifiers.cve]),
      ghsa: unique([...a.identifiers.ghsa, ...b.identifiers.ghsa]),
      osv: unique([...a.identifiers.osv, ...b.identifiers.osv]),
      cwe: unique([...a.identifiers.cwe, ...b.identifiers.cwe]),
    },
    ecosystems: unique([...a.ecosystems, ...b.ecosystems]),
    packages: [...a.packages, ...b.packages].filter(
      (pkg, index, all) =>
        all.findIndex(
          (candidate) =>
            candidate.ecosystem === pkg.ecosystem &&
            candidate.name === pkg.name &&
            candidate.affectedRange === pkg.affectedRange &&
            candidate.fixedVersion === pkg.fixedVersion,
        ) === index,
    ),
    severity,
    ...(cvss ? { cvss } : {}),
    ...(epss ? { epss } : {}),
    ...(cisaKev ? { cisaKev } : {}),
    tags: unique([...a.tags, ...b.tags]),
    provenance: {
      fetchedAt: [a.provenance.fetchedAt, b.provenance.fetchedAt].sort().at(-1) ?? a.provenance.fetchedAt,
      ...(rawSnapshotPath ? { rawSnapshotPath } : {}),
      normalizedFrom: mergeSources(a.provenance.normalizedFrom, b.provenance.normalizedFrom),
    },
  };
}

export function dedupeIntelItems(items: SecurityIntelItem[]): SecurityIntelItem[] {
  const byKey = new Map<string, SecurityIntelItem>();
  for (const item of items) {
    const key = canonicalKey(item);
    const existing = byKey.get(key);
    byKey.set(key, existing ? mergeIntelItems(existing, item) : item);
  }
  return [...byKey.values()].sort((a, b) => b.provenance.fetchedAt.localeCompare(a.provenance.fetchedAt));
}
