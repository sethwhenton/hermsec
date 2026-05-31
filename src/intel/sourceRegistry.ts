import type { IntelFetcher, IntelPriority, IntelSource, SecurityIntelItem } from "./schema.js";

export type IntelSourceConfig = {
  source: IntelSource;
  priority: IntelPriority;
  onlineRequired: boolean;
  ttlMs: number;
  enabledByDefault: boolean;
};

export type IntelSourceDefinition = IntelSourceConfig & {
  displayName: string;
  trust: "official" | "vendor" | "third-party";
  officialUrl: string;
  endpoints: readonly string[];
  requestKind: "feed" | "package-query" | "advisory-query" | "cve-api" | "scorecard" | "rss";
  requiresInventory: boolean;
};

const hour = 60 * 60 * 1000;
const day = 24 * hour;

export const intelSourceRegistry: IntelSourceDefinition[] = [
  {
    source: "cisa-kev",
    displayName: "CISA Known Exploited Vulnerabilities",
    trust: "official",
    priority: "P0",
    onlineRequired: true,
    ttlMs: hour,
    enabledByDefault: true,
    officialUrl: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    endpoints: ["https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"],
    requestKind: "feed",
    requiresInventory: false,
  },
  {
    source: "osv",
    displayName: "OSV.dev",
    trust: "official",
    priority: "P0",
    onlineRequired: true,
    ttlMs: 6 * hour,
    enabledByDefault: true,
    officialUrl: "https://osv.dev/",
    endpoints: ["https://api.osv.dev/v1/querybatch", "https://api.osv.dev/v1/vulns/{id}"],
    requestKind: "package-query",
    requiresInventory: true,
  },
  {
    source: "github-advisory",
    displayName: "GitHub Advisory Database",
    trust: "official",
    priority: "P0",
    onlineRequired: true,
    ttlMs: 6 * hour,
    enabledByDefault: true,
    officialUrl: "https://github.com/advisories",
    endpoints: ["https://api.github.com/advisories"],
    requestKind: "advisory-query",
    requiresInventory: false,
  },
  {
    source: "nvd",
    displayName: "NVD CVE API",
    trust: "official",
    priority: "P1",
    onlineRequired: true,
    ttlMs: 12 * hour,
    enabledByDefault: true,
    officialUrl: "https://nvd.nist.gov/vuln",
    endpoints: ["https://services.nvd.nist.gov/rest/json/cves/2.0"],
    requestKind: "cve-api",
    requiresInventory: false,
  },
  {
    source: "epss",
    displayName: "FIRST EPSS",
    trust: "official",
    priority: "P1",
    onlineRequired: true,
    ttlMs: day,
    enabledByDefault: false,
    officialUrl: "https://www.first.org/epss/",
    endpoints: ["https://api.first.org/data/v1/epss"],
    requestKind: "cve-api",
    requiresInventory: true,
  },
  {
    source: "deps-dev",
    displayName: "deps.dev",
    trust: "official",
    priority: "P2",
    onlineRequired: true,
    ttlMs: 7 * day,
    enabledByDefault: false,
    officialUrl: "https://deps.dev/",
    endpoints: ["https://api.deps.dev/v3"],
    requestKind: "package-query",
    requiresInventory: true,
  },
  {
    source: "endoflife",
    displayName: "endoflife.date",
    trust: "third-party",
    priority: "P2",
    onlineRequired: true,
    ttlMs: 7 * day,
    enabledByDefault: false,
    officialUrl: "https://endoflife.date/",
    endpoints: ["https://endoflife.date/api"],
    requestKind: "feed",
    requiresInventory: true,
  },
  {
    source: "openssf-scorecard",
    displayName: "OpenSSF Scorecard",
    trust: "official",
    priority: "P2",
    onlineRequired: true,
    ttlMs: 7 * day,
    enabledByDefault: false,
    officialUrl: "https://scorecard.dev/",
    endpoints: ["https://api.securityscorecards.dev/projects/github.com/{owner}/{repo}"],
    requestKind: "scorecard",
    requiresInventory: true,
  },
  {
    source: "npm-audit",
    displayName: "npm audit",
    trust: "official",
    priority: "P1",
    onlineRequired: true,
    ttlMs: day,
    enabledByDefault: false,
    officialUrl: "https://docs.npmjs.com/cli/commands/npm-audit",
    endpoints: ["https://registry.npmjs.org/-/npm/v1/security/advisories/bulk"],
    requestKind: "package-query",
    requiresInventory: true,
  },
  {
    source: "rss",
    displayName: "Security RSS Feeds",
    trust: "vendor",
    priority: "P3",
    onlineRequired: true,
    ttlMs: 6 * hour,
    enabledByDefault: false,
    officialUrl: "https://www.cisa.gov/news-events/cybersecurity-advisories",
    endpoints: ["https://www.cisa.gov/news.xml"],
    requestKind: "rss",
    requiresInventory: false,
  },
  {
    source: "socket",
    displayName: "Socket",
    trust: "third-party",
    priority: "P2",
    onlineRequired: true,
    ttlMs: day,
    enabledByDefault: false,
    officialUrl: "https://socket.dev/",
    endpoints: ["https://api.socket.dev"],
    requestKind: "package-query",
    requiresInventory: true,
  },
  {
    source: "phylum",
    displayName: "Phylum",
    trust: "third-party",
    priority: "P2",
    onlineRequired: true,
    ttlMs: day,
    enabledByDefault: false,
    officialUrl: "https://phylum.io/",
    endpoints: ["https://api.phylum.io"],
    requestKind: "package-query",
    requiresInventory: true,
  },
  {
    source: "vendor",
    displayName: "Hermsec Vendor Fallback",
    trust: "vendor",
    priority: "P3",
    onlineRequired: false,
    ttlMs: day,
    enabledByDefault: false,
    officialUrl: "https://github.com/",
    endpoints: [],
    requestKind: "feed",
    requiresInventory: false,
  },
];

export const defaultIntelSources: IntelSourceConfig[] = intelSourceRegistry.map(
  ({ source, priority, onlineRequired, ttlMs, enabledByDefault }) => ({
    source,
    priority,
    onlineRequired,
    ttlMs,
    enabledByDefault,
  }),
);

const sourceAliases = new Map<string, IntelSource>([
  ["kev", "cisa-kev"],
  ["cisa", "cisa-kev"],
  ["cisa-kev", "cisa-kev"],
  ["ghsa", "github-advisory"],
  ["github", "github-advisory"],
  ["github-advisories", "github-advisory"],
  ["github-advisory", "github-advisory"],
]);

export function getIntelSourceDefinition(source: IntelSource): IntelSourceDefinition | undefined {
  return intelSourceRegistry.find((definition) => definition.source === source);
}

export function normalizeIntelSource(value: string): IntelSource | undefined {
  const normalized = value.trim().toLowerCase();
  return sourceAliases.get(normalized) ?? intelSourceRegistry.find((definition) => definition.source === normalized)?.source;
}

export function parseIntelSources(values: string[]): { sources: IntelSource[]; invalid: string[] } {
  const sources: IntelSource[] = [];
  const invalid: string[] = [];
  for (const value of values) {
    const source = normalizeIntelSource(value);
    if (!source) {
      invalid.push(value);
      continue;
    }
    if (!sources.includes(source)) {
      sources.push(source);
    }
  }
  return { sources, invalid };
}

export function ttlForSource(source: IntelSource): number | undefined {
  return getIntelSourceDefinition(source)?.ttlMs;
}

export function enabledSourceNames(fetchers: IntelFetcher[], requested?: IntelSource[]): IntelSource[] {
  const requestedSet = requested ? new Set(requested) : undefined;
  return fetchers
    .filter((fetcher) => !requestedSet || requestedSet.has(fetcher.source))
    .map((fetcher) => fetcher.source);
}

export function offlineFallbackFeedItems(now = new Date().toISOString()): SecurityIntelItem[] {
  return [
    {
      id: "offline-fallback:cache-stale",
      source: "vendor",
      sourceIds: ["offline-fallback"],
      title: "Security intelligence cache is offline",
      summary:
        "Hermsec can continue local scans with cached advisories. Refresh the feed when network access is available.",
      url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
      identifiers: { cve: [], ghsa: [], osv: [], cwe: [] },
      ecosystems: [],
      packages: [],
      severity: "unknown",
      tags: ["offline", "cache", "fallback"],
      provenance: { fetchedAt: now, normalizedFrom: ["vendor"] },
    },
    {
      id: "offline-fallback:lockfiles",
      source: "vendor",
      sourceIds: ["offline-lockfile-guidance"],
      title: "Review dependency and lockfile changes closely",
      summary:
        "Dependency manifest or lockfile changes should trigger dependency scanners and cached advisory matching.",
      url: "https://osv.dev/",
      identifiers: { cve: [], ghsa: [], osv: [], cwe: [] },
      ecosystems: ["npm", "pypi"],
      packages: [],
      severity: "unknown",
      tags: ["offline", "dependency", "guidance"],
      provenance: { fetchedAt: now, normalizedFrom: ["vendor"] },
    },
  ];
}
