import type { IntelFetcher, IntelPriority, IntelSource, SecurityIntelItem } from "./schema.js";

export type IntelSourceConfig = {
  source: IntelSource;
  priority: IntelPriority;
  onlineRequired: boolean;
  ttlMs: number;
  enabledByDefault: boolean;
};

export const defaultIntelSources: IntelSourceConfig[] = [
  { source: "cisa-kev", priority: "P0", onlineRequired: true, ttlMs: 60 * 60 * 1000, enabledByDefault: true },
  { source: "osv", priority: "P0", onlineRequired: true, ttlMs: 6 * 60 * 60 * 1000, enabledByDefault: true },
  {
    source: "github-advisory",
    priority: "P0",
    onlineRequired: true,
    ttlMs: 6 * 60 * 60 * 1000,
    enabledByDefault: true,
  },
  { source: "epss", priority: "P1", onlineRequired: true, ttlMs: 24 * 60 * 60 * 1000, enabledByDefault: false },
  { source: "nvd", priority: "P1", onlineRequired: true, ttlMs: 12 * 60 * 60 * 1000, enabledByDefault: false },
  { source: "deps-dev", priority: "P2", onlineRequired: true, ttlMs: 7 * 24 * 60 * 60 * 1000, enabledByDefault: false },
  {
    source: "endoflife",
    priority: "P2",
    onlineRequired: true,
    ttlMs: 7 * 24 * 60 * 60 * 1000,
    enabledByDefault: false,
  },
  { source: "rss", priority: "P3", onlineRequired: true, ttlMs: 6 * 60 * 60 * 1000, enabledByDefault: false },
];

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
