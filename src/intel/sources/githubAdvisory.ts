import type { IntelFetcher, IntelFetchResult, IntelSeverity, SecurityIntelItem, WorkspaceInventory } from "../schema.js";
import { fetchIntelJson } from "../http.js";
import { getIntelSourceDefinition } from "../sourceRegistry.js";

const githubAdvisoryUrl = getIntelSourceDefinition("github-advisory")?.endpoints[0] ?? "https://api.github.com/advisories";

type GitHubAdvisory = {
  ghsa_id?: string;
  cve_id?: string | null;
  url?: string;
  html_url?: string;
  summary?: string;
  description?: string;
  severity?: string;
  published_at?: string;
  updated_at?: string;
  identifiers?: { type?: string; value?: string }[];
  cwes?: { cwe_id?: string }[];
  vulnerabilities?: {
    package?: { ecosystem?: string; name?: string };
    vulnerable_version_range?: string;
    first_patched_version?: string | { identifier?: string } | null;
  }[];
  cvss?: { score?: number; vector_string?: string };
};

type GitHubAdvisoryVulnerability = NonNullable<GitHubAdvisory["vulnerabilities"]>[number];

function githubEcosystem(ecosystem: string): string | undefined {
  const normalized = ecosystem.toLowerCase();
  if (normalized === "npm" || normalized === "node") return "npm";
  if (normalized === "pypi" || normalized === "python") return "pip";
  if (normalized === "maven") return "maven";
  if (normalized === "go") return "go";
  if (normalized === "rubygems") return "rubygems";
  return undefined;
}

function normalizeSeverity(value?: string): IntelSeverity {
  const normalized = value?.toLowerCase();
  if (normalized === "critical" || normalized === "high" || normalized === "medium" || normalized === "low") {
    return normalized;
  }
  return "unknown";
}

function normalizeGithubAdvisory(advisory: GitHubAdvisory, fetchedAt: string): SecurityIntelItem | undefined {
  const ghsa = advisory.ghsa_id;
  if (!ghsa) {
    return undefined;
  }
  const vulnerabilities = advisory.vulnerabilities ?? [];
  const packages = vulnerabilities
    .filter((vuln) => vuln.package?.ecosystem && vuln.package.name)
    .map((vuln) => {
      const fixedVersion = firstPatchedVersion(vuln.first_patched_version);
      return {
        ecosystem: String(vuln.package?.ecosystem).toLowerCase(),
        name: String(vuln.package?.name),
        ...(vuln.vulnerable_version_range ? { affectedRange: vuln.vulnerable_version_range } : {}),
        ...(fixedVersion ? { fixedVersion } : {}),
      };
    });
  const cves = [
    advisory.cve_id ?? "",
    ...(advisory.identifiers ?? [])
      .filter((identifier) => identifier.type === "CVE")
      .map((identifier) => identifier.value ?? ""),
  ].filter(Boolean);

  return {
    id: `github-advisory:${ghsa}`,
    source: "github-advisory",
    sourceIds: [ghsa],
    title: advisory.summary ?? ghsa,
    ...(advisory.description ? { summary: advisory.description.slice(0, 500) } : {}),
    url: advisory.html_url ?? advisory.url ?? `https://github.com/advisories/${ghsa}`,
    ...(advisory.published_at ? { publishedAt: advisory.published_at } : {}),
    ...(advisory.updated_at ? { modifiedAt: advisory.updated_at } : {}),
    identifiers: {
      cve: [...new Set(cves)],
      ghsa: [ghsa],
      osv: [],
      cwe: (advisory.cwes ?? []).map((cwe) => cwe.cwe_id ?? "").filter(Boolean),
    },
    ecosystems: [...new Set(packages.map((pkg) => pkg.ecosystem))],
    packages,
    severity: normalizeSeverity(advisory.severity),
    ...(advisory.cvss?.score
      ? { cvss: { score: advisory.cvss.score, ...(advisory.cvss.vector_string ? { vector: advisory.cvss.vector_string } : {}) } }
      : {}),
    tags: ["github-advisory", "dependency"],
    provenance: { fetchedAt, normalizedFrom: ["github-advisory"] },
  };
}

function firstPatchedVersion(value: GitHubAdvisoryVulnerability["first_patched_version"]): string | undefined {
  if (typeof value === "string" && value.length > 0) {
    return value;
  }
  if (typeof value !== "object" || value === null) {
    return undefined;
  }
  return value?.identifier;
}

function advisoryQueries(inventory: WorkspaceInventory | undefined, since: string | undefined): URL[] {
  const packageUrls = (inventory?.packages ?? [])
    .slice(0, 30)
    .flatMap((pkg) => {
      const ecosystem = githubEcosystem(pkg.ecosystem);
      if (!ecosystem || !pkg.version) {
        return [];
      }
      const url = new URL(githubAdvisoryUrl);
      url.searchParams.set("ecosystem", ecosystem);
      url.searchParams.set("affects", `${pkg.name}@${pkg.version}`);
      url.searchParams.set("per_page", "100");
      return [url];
    });
  if (packageUrls.length > 0) {
    return packageUrls;
  }

  const url = new URL(githubAdvisoryUrl);
  url.searchParams.set("type", "reviewed");
  url.searchParams.set("sort", "updated");
  url.searchParams.set("direction", "desc");
  url.searchParams.set("per_page", "30");
  if (since) {
    url.searchParams.set("modified", `>=${since.slice(0, 10)}`);
  }
  return [url];
}

export const githubAdvisoryFetcher: IntelFetcher = {
  source: "github-advisory",
  priority: "P0",
  onlineRequired: true,
  ttlMs: 6 * 60 * 60 * 1000,
  async fetch(input): Promise<IntelFetchResult> {
    const urls = advisoryQueries(input.inventory, input.since);
    if (input.mode === "offline" || urls.length === 0) {
      return {
        source: "github-advisory",
        fetchedAt: input.now,
        status: urls.length === 0 ? "skipped" : "cached",
        items: [],
      };
    }

    const raw: GitHubAdvisory[] = [];
    for (const url of urls) {
      const response = await fetchIntelJson<GitHubAdvisory[]>("github-advisory", url, {
        headers: {
          accept: "application/vnd.github+json",
          "user-agent": "hermsec-local-intel",
        },
        ...(input.signal ? { signal: input.signal } : {}),
        ...(urls.length === 1 && input.cache ? { cache: input.cache } : {}),
      });
      if (!response.ok) {
        return {
          source: "github-advisory",
          fetchedAt: input.now,
          status: "failed",
          items: [],
          error: response.error,
        };
      }
      if (response.status === "not-modified") {
        return {
          source: "github-advisory",
          fetchedAt: input.now,
          status: "cached",
          items: [],
          ...(response.etag ? { etag: response.etag } : {}),
          ...(response.lastModified ? { lastModified: response.lastModified } : {}),
        };
      }
      raw.push(...(response.data ?? []));
    }

    const items = raw
      .map((advisory) => normalizeGithubAdvisory(advisory, input.now))
      .filter((item): item is SecurityIntelItem => Boolean(item));
    return {
      source: "github-advisory",
      fetchedAt: input.now,
      status: "fresh",
      raw,
      items,
    };
  },
};
