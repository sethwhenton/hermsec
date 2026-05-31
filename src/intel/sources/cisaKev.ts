import type { IntelFetcher, IntelFetchResult, SecurityIntelItem } from "../schema.js";

const cisaKevUrl = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

type CisaKevVulnerability = {
  cveID?: string;
  vendorProject?: string;
  product?: string;
  vulnerabilityName?: string;
  dateAdded?: string;
  shortDescription?: string;
  requiredAction?: string;
  dueDate?: string;
  knownRansomwareCampaignUse?: string;
};

function normalizeKev(raw: CisaKevVulnerability, fetchedAt: string): SecurityIntelItem | undefined {
  if (!raw.cveID) {
    return undefined;
  }
  const title = raw.vulnerabilityName ?? `${raw.cveID} known exploited vulnerability`;
  const ecosystems = [raw.vendorProject, raw.product].filter((value): value is string => Boolean(value));
  return {
    id: `cisa-kev:${raw.cveID}`,
    source: "cisa-kev",
    sourceIds: [raw.cveID],
    title,
    ...(raw.shortDescription ? { summary: raw.shortDescription } : {}),
    url: cisaKevUrl,
    ...(raw.dateAdded ? { publishedAt: raw.dateAdded } : {}),
    identifiers: { cve: [raw.cveID], ghsa: [], osv: [], cwe: [] },
    ecosystems,
    packages: [],
    severity: "high",
    cisaKev: {
      knownExploited: true,
      ...(raw.dateAdded ? { addedAt: raw.dateAdded } : {}),
      ...(raw.dueDate ? { dueDate: raw.dueDate } : {}),
      ...(raw.knownRansomwareCampaignUse
        ? { ransomwareUse: raw.knownRansomwareCampaignUse.toLowerCase() === "known" }
        : {}),
    },
    tags: ["known-exploited", "cisa-kev"],
    provenance: { fetchedAt, normalizedFrom: ["cisa-kev"] },
  };
}

export const cisaKevFetcher: IntelFetcher = {
  source: "cisa-kev",
  priority: "P0",
  onlineRequired: true,
  ttlMs: 60 * 60 * 1000,
  async fetch(input): Promise<IntelFetchResult> {
    if (input.mode === "offline") {
      return { source: "cisa-kev", fetchedAt: input.now, status: "skipped", items: [] };
    }
    const response = await fetch(cisaKevUrl, { headers: { accept: "application/json" } });
    if (!response.ok) {
      return {
        source: "cisa-kev",
        fetchedAt: input.now,
        status: "failed",
        items: [],
        error: { code: "cisa-kev-http", message: `CISA KEV returned HTTP ${response.status}` },
      };
    }
    const raw = (await response.json()) as { vulnerabilities?: CisaKevVulnerability[] };
    const items = (raw.vulnerabilities ?? [])
      .map((item) => normalizeKev(item, input.now))
      .filter((item): item is SecurityIntelItem => Boolean(item));
    const etag = response.headers.get("etag") ?? undefined;
    const lastModified = response.headers.get("last-modified") ?? undefined;
    return {
      source: "cisa-kev",
      fetchedAt: input.now,
      status: "fresh",
      raw,
      items,
      ...(etag ? { etag } : {}),
      ...(lastModified ? { lastModified } : {}),
    };
  },
};
