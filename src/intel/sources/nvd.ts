import { fetchIntelJson } from "../http.js";
import type { IntelFetcher, IntelFetchResult, IntelSeverity, SecurityIntelItem, WorkspaceInventory } from "../schema.js";
import { getIntelSourceDefinition } from "../sourceRegistry.js";

const nvdUrl = getIntelSourceDefinition("nvd")?.endpoints[0] ?? "https://services.nvd.nist.gov/rest/json/cves/2.0";

type NvdResponse = {
  vulnerabilities?: NvdVulnerability[];
};

type NvdVulnerability = {
  cve?: {
    id?: string;
    published?: string;
    lastModified?: string;
    vulnStatus?: string;
    descriptions?: { lang?: string; value?: string }[];
    metrics?: {
      cvssMetricV40?: NvdMetric[];
      cvssMetricV31?: NvdMetric[];
      cvssMetricV30?: NvdMetric[];
      cvssMetricV2?: NvdMetric[];
    };
    weaknesses?: { description?: { lang?: string; value?: string }[] }[];
    references?: { url?: string }[];
    cisaExploitAdd?: string;
    cisaActionDue?: string;
    cisaRequiredAction?: string;
    cisaVulnerabilityName?: string;
  };
};

type NvdMetric = {
  type?: string;
  cvssData?: {
    version?: string;
    vectorString?: string;
    baseScore?: number;
    baseSeverity?: string;
  };
};

type NvdMetrics = NonNullable<NonNullable<NvdVulnerability["cve"]>["metrics"]>;

function cveIds(inventory?: WorkspaceInventory): string[] {
  return [
    ...new Set(
      (inventory?.previousFindingIds ?? [])
        .map((identifier) => identifier.toUpperCase())
        .filter((identifier) => /^CVE-\d{4}-\d{4,}$/.test(identifier)),
    ),
  ].slice(0, 30);
}

function nvdQueries(input: { now: string; since?: string; inventory?: WorkspaceInventory }): URL[] {
  const identifiers = cveIds(input.inventory);
  if (identifiers.length > 0) {
    return identifiers.map((id) => {
      const url = new URL(nvdUrl);
      url.searchParams.set("cveId", id);
      url.searchParams.set("noRejected", "");
      return url;
    });
  }

  const end = new Date(input.now);
  const since = input.since ? new Date(input.since) : new Date(end.getTime() - 24 * 60 * 60 * 1000);
  const start = Number.isNaN(since.getTime()) ? new Date(end.getTime() - 24 * 60 * 60 * 1000) : clampDateRange(since, end);
  const url = new URL(nvdUrl);
  url.searchParams.set("lastModStartDate", start.toISOString());
  url.searchParams.set("lastModEndDate", end.toISOString());
  url.searchParams.set("resultsPerPage", "50");
  url.searchParams.set("noRejected", "");
  return [url];
}

function clampDateRange(start: Date, end: Date): Date {
  const maxRangeMs = 119 * 24 * 60 * 60 * 1000;
  if (end.getTime() - start.getTime() <= maxRangeMs) {
    return start;
  }
  return new Date(end.getTime() - maxRangeMs);
}

function normalizeNvd(entry: NvdVulnerability, fetchedAt: string): SecurityIntelItem | undefined {
  const cve = entry.cve;
  const id = cve?.id;
  if (!id) {
    return undefined;
  }

  const description = cve?.descriptions?.find((item) => item.lang === "en")?.value
    ?? cve?.descriptions?.find((item) => item.value)?.value;
  const metric = bestMetric(cve?.metrics);
  const cwes = [
    ...new Set(
      (cve?.weaknesses ?? [])
        .flatMap((weakness) => weakness.description ?? [])
        .map((descriptionItem) => descriptionItem.value ?? "")
        .filter((value) => /^CWE-\d+$/i.test(value)),
    ),
  ];
  const isKev = Boolean(cve?.cisaExploitAdd || cve?.cisaActionDue || cve?.cisaVulnerabilityName);

  return {
    id: `nvd:${id}`,
    source: "nvd",
    sourceIds: [id],
    title: cve?.cisaVulnerabilityName ?? id,
    ...(description ? { summary: description.slice(0, 500) } : {}),
    url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}`,
    ...(cve?.published ? { publishedAt: cve.published } : {}),
    ...(cve?.lastModified ? { modifiedAt: cve.lastModified } : {}),
    identifiers: { cve: [id], ghsa: [], osv: [], cwe: cwes },
    ecosystems: [],
    packages: [],
    severity: metric?.severity ?? "unknown",
    ...(metric?.score
      ? { cvss: { score: metric.score, ...(metric.vector ? { vector: metric.vector } : {}), ...(metric.version ? { version: metric.version } : {}) } }
      : {}),
    ...(isKev
      ? {
          cisaKev: {
            knownExploited: true,
            ...(cve?.cisaExploitAdd ? { addedAt: cve.cisaExploitAdd } : {}),
            ...(cve?.cisaActionDue ? { dueDate: cve.cisaActionDue } : {}),
          },
        }
      : {}),
    tags: ["nvd", "cve", ...(isKev ? ["known-exploited"] : [])],
    provenance: { fetchedAt, normalizedFrom: ["nvd"] },
  };
}

function bestMetric(metrics: NvdMetrics | undefined): {
  score?: number;
  vector?: string;
  version?: "3" | "4";
  severity?: IntelSeverity;
} | undefined {
  const candidates = [
    ...(metrics?.cvssMetricV40 ?? []),
    ...(metrics?.cvssMetricV31 ?? []),
    ...(metrics?.cvssMetricV30 ?? []),
    ...(metrics?.cvssMetricV2 ?? []),
  ].filter((metric) => metric.cvssData?.baseScore !== undefined);
  const best = candidates.sort((left, right) => (left.cvssData?.baseScore ?? 0) - (right.cvssData?.baseScore ?? 0)).at(-1);
  if (!best?.cvssData) {
    return undefined;
  }
  const version = best.cvssData.version?.startsWith("4") ? "4" : best.cvssData.version?.startsWith("3") ? "3" : undefined;
  const score = best.cvssData.baseScore;
  return {
    ...(score !== undefined ? { score } : {}),
    ...(best.cvssData.vectorString ? { vector: best.cvssData.vectorString } : {}),
    ...(version ? { version } : {}),
    severity: normalizeSeverity(best.cvssData.baseSeverity),
  };
}

function normalizeSeverity(value?: string): IntelSeverity {
  const normalized = value?.toLowerCase();
  if (normalized === "critical" || normalized === "high" || normalized === "medium" || normalized === "low") {
    return normalized;
  }
  return "unknown";
}

export const nvdFetcher: IntelFetcher = {
  source: "nvd",
  priority: "P1",
  onlineRequired: true,
  ttlMs: 12 * 60 * 60 * 1000,
  async fetch(input): Promise<IntelFetchResult> {
    const urls = nvdQueries({
      now: input.now,
      ...(input.since ? { since: input.since } : {}),
      ...(input.inventory ? { inventory: input.inventory } : {}),
    });
    if (input.mode === "offline") {
      return { source: "nvd", fetchedAt: input.now, status: "skipped", items: [] };
    }

    const raw: NvdResponse[] = [];
    for (const url of urls) {
      const response = await fetchIntelJson<NvdResponse>("nvd", url, {
        headers: { "user-agent": "hermsec-local-intel" },
        ...(urls.length === 1 && input.cache ? { cache: input.cache } : {}),
        ...(input.signal ? { signal: input.signal } : {}),
      });
      if (!response.ok) {
        return {
          source: "nvd",
          fetchedAt: input.now,
          status: "failed",
          items: [],
          error: response.error,
        };
      }
      if (response.status === "not-modified") {
        return {
          source: "nvd",
          fetchedAt: input.now,
          status: "cached",
          items: [],
          ...(response.etag ? { etag: response.etag } : {}),
          ...(response.lastModified ? { lastModified: response.lastModified } : {}),
        };
      }
      raw.push(response.data ?? {});
    }

    const items = raw
      .flatMap((response) => response.vulnerabilities ?? [])
      .map((entry) => normalizeNvd(entry, input.now))
      .filter((item): item is SecurityIntelItem => Boolean(item));
    return {
      source: "nvd",
      fetchedAt: input.now,
      status: "fresh",
      raw,
      items,
    };
  },
};
