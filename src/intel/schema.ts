import type { WorkspaceProfile } from "../storage/workspaceStore.js";

export const intelSources = [
  "osv",
  "github-advisory",
  "nvd",
  "cisa-kev",
  "epss",
  "npm-audit",
  "deps-dev",
  "openssf-scorecard",
  "endoflife",
  "rss",
  "socket",
  "phylum",
  "vendor",
] as const;
export type IntelSource = (typeof intelSources)[number];

export const intelPriorities = ["P0", "P1", "P2", "P3"] as const;
export type IntelPriority = (typeof intelPriorities)[number];

export const intelSeverities = ["critical", "high", "medium", "low", "unknown"] as const;
export type IntelSeverity = (typeof intelSeverities)[number];

export type HermsecError = {
  code: string;
  message: string;
  remediation?: string;
};

export type SecurityIntelItem = {
  id: string;
  source: IntelSource;
  sourceIds: string[];
  title: string;
  summary?: string;
  url: string;
  publishedAt?: string;
  modifiedAt?: string;
  identifiers: { cve: string[]; ghsa: string[]; osv: string[]; cwe: string[] };
  ecosystems: string[];
  packages: { ecosystem: string; name: string; affectedRange?: string; fixedVersion?: string }[];
  severity: IntelSeverity;
  cvss?: { score: number; vector?: string; version?: "3" | "4" };
  epss?: { score: number; percentile: number; date?: string };
  cisaKev?: { knownExploited: true; addedAt?: string; dueDate?: string; ransomwareUse?: boolean };
  tags: string[];
  provenance: { fetchedAt: string; rawSnapshotPath?: string; normalizedFrom: IntelSource[] };
};

export type WorkspaceInventory = {
  workspaceId: string;
  capturedAt: string;
  ecosystems: string[];
  packages: { ecosystem: string; name: string; version?: string; direct: boolean; files: string[] }[];
  runtimes: { name: string; version?: string; source: string }[];
  frameworks: string[];
  ciTools: string[];
  dockerImages: string[];
  previousFindingIds: string[];
};

export type IntelFetchCache = {
  etag?: string;
  lastModified?: string;
};

export type IntelRelevance = {
  itemId: string;
  workspaceId: string;
  score: number;
  reasons: string[];
  matchedPackages: string[];
  matchedRuntime?: string;
  priority: "urgent" | "high" | "normal" | "watch";
};

export type IntelFetchInput = {
  mode: "online" | "offline" | "auto";
  workspace?: WorkspaceProfile;
  inventory?: WorkspaceInventory;
  since?: string;
  cache?: IntelFetchCache;
  now: string;
  signal?: AbortSignal;
};

export type IntelFetchResult = {
  source: IntelSource;
  fetchedAt: string;
  status: "fresh" | "cached" | "skipped" | "failed";
  raw?: unknown;
  rawSnapshotPath?: string;
  items: SecurityIntelItem[];
  error?: HermsecError;
  etag?: string;
  lastModified?: string;
};

export type IntelFetcher = {
  source: IntelSource;
  priority: IntelPriority;
  onlineRequired: boolean;
  ttlMs: number;
  fetch(input: IntelFetchInput): Promise<IntelFetchResult>;
};

export type IntelFeedItem = {
  item: SecurityIntelItem;
  relevance?: IntelRelevance;
  whyShown: string[];
  cacheStatus: "fresh" | "cached" | "fallback";
};
