import type { IntelFetcher, IntelFetchResult, IntelSeverity, SecurityIntelItem, WorkspaceInventory } from "../schema.js";

const osvQueryBatchUrl = "https://api.osv.dev/v1/querybatch";

type OsvVulnerability = {
  id?: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  modified?: string;
  published?: string;
  severity?: { type?: string; score?: string }[];
  database_specific?: { severity?: string };
  affected?: {
    package?: { ecosystem?: string; name?: string };
    ranges?: { events?: { introduced?: string; fixed?: string; last_affected?: string }[] }[];
  }[];
  references?: { type?: string; url?: string }[];
};

function osvEcosystem(ecosystem: string): string {
  const normalized = ecosystem.toLowerCase();
  if (normalized === "pypi" || normalized === "python") return "PyPI";
  if (normalized === "npm" || normalized === "node") return "npm";
  if (normalized === "maven") return "Maven";
  if (normalized === "go") return "Go";
  if (normalized === "crates.io" || normalized === "cargo") return "crates.io";
  return ecosystem;
}

function severityFromOsv(vuln: OsvVulnerability): IntelSeverity {
  const databaseSeverity = vuln.database_specific?.severity?.toLowerCase();
  if (databaseSeverity === "critical" || databaseSeverity === "high" || databaseSeverity === "medium" || databaseSeverity === "low") {
    return databaseSeverity;
  }
  const cvss = vuln.severity?.find((item) => item.score?.startsWith("CVSS:"));
  if (!cvss?.score) {
    return "unknown";
  }
  const score = /\/AV:/.test(cvss.score) ? undefined : Number(cvss.score);
  if (score === undefined || Number.isNaN(score)) {
    return "unknown";
  }
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  return "low";
}

function identifiers(vuln: OsvVulnerability): SecurityIntelItem["identifiers"] {
  const aliases = vuln.aliases ?? [];
  return {
    cve: aliases.filter((alias) => alias.startsWith("CVE-")),
    ghsa: aliases.filter((alias) => alias.startsWith("GHSA-")),
    osv: [vuln.id ?? "", ...aliases.filter((alias) => !alias.startsWith("CVE-") && !alias.startsWith("GHSA-"))]
      .filter(Boolean),
    cwe: [],
  };
}

function affectedPackages(vuln: OsvVulnerability): SecurityIntelItem["packages"] {
  const packages: SecurityIntelItem["packages"] = [];
  for (const affected of vuln.affected ?? []) {
    const ecosystem = affected.package?.ecosystem;
    const name = affected.package?.name;
    if (!ecosystem || !name) {
      continue;
    }
    const fixedVersion = affected.ranges
      ?.flatMap((range) => range.events ?? [])
      .find((event) => event.fixed)?.fixed;
    const introduced = affected.ranges
      ?.flatMap((range) => range.events ?? [])
      .find((event) => event.introduced)?.introduced;
    const affectedRange = fixedVersion
      ? `>=${introduced ?? "0"} <${fixedVersion}`
      : introduced
        ? `>=${introduced}`
        : undefined;
    packages.push({
      ecosystem: ecosystem.toLowerCase(),
      name,
      ...(affectedRange ? { affectedRange } : {}),
      ...(fixedVersion ? { fixedVersion } : {}),
    });
  }
  return packages;
}

function normalizeOsv(vuln: OsvVulnerability, fetchedAt: string): SecurityIntelItem | undefined {
  if (!vuln.id) {
    return undefined;
  }
  const packages = affectedPackages(vuln);
  return {
    id: `osv:${vuln.id}`,
    source: "osv",
    sourceIds: [vuln.id],
    title: vuln.summary ?? vuln.id,
    ...(vuln.details ? { summary: vuln.details.slice(0, 500) } : {}),
    url: `https://osv.dev/vulnerability/${encodeURIComponent(vuln.id)}`,
    ...(vuln.published ? { publishedAt: vuln.published } : {}),
    ...(vuln.modified ? { modifiedAt: vuln.modified } : {}),
    identifiers: identifiers(vuln),
    ecosystems: [...new Set(packages.map((pkg) => pkg.ecosystem))],
    packages,
    severity: severityFromOsv(vuln),
    tags: ["osv", "dependency"],
    provenance: { fetchedAt, normalizedFrom: ["osv"] },
  };
}

function queries(inventory?: WorkspaceInventory): { package: { ecosystem: string; name: string }; version?: string }[] {
  return (inventory?.packages ?? [])
    .filter((pkg) => pkg.version)
    .slice(0, 100)
    .map((pkg) => ({
      package: { ecosystem: osvEcosystem(pkg.ecosystem), name: pkg.name },
      ...(pkg.version ? { version: pkg.version } : {}),
    }));
}

export const osvFetcher: IntelFetcher = {
  source: "osv",
  priority: "P0",
  onlineRequired: true,
  ttlMs: 6 * 60 * 60 * 1000,
  async fetch(input): Promise<IntelFetchResult> {
    const body = { queries: queries(input.inventory) };
    if (input.mode === "offline" || body.queries.length === 0) {
      return {
        source: "osv",
        fetchedAt: input.now,
        status: body.queries.length === 0 ? "skipped" : "cached",
        items: [],
      };
    }

    const response = await fetch(osvQueryBatchUrl, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify(body),
    });
    if (!response.ok) {
      return {
        source: "osv",
        fetchedAt: input.now,
        status: "failed",
        items: [],
        error: { code: "osv-http", message: `OSV returned HTTP ${response.status}` },
      };
    }
    const raw = (await response.json()) as { results?: { vulns?: OsvVulnerability[] }[] };
    const items = (raw.results ?? [])
      .flatMap((result) => result.vulns ?? [])
      .map((vuln) => normalizeOsv(vuln, input.now))
      .filter((item): item is SecurityIntelItem => Boolean(item));
    return {
      source: "osv",
      fetchedAt: input.now,
      status: "fresh",
      raw,
      items,
    };
  },
};
