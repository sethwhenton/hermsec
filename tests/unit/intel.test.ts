import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test, { type TestContext } from "node:test";
import {
  buildWorkspaceInventoryFromFindings,
  cisaKevFetcher,
  githubAdvisoryFetcher,
  matchIntelToFindings,
  matchIntelToWorkspace,
  nvdFetcher,
  osvFetcher,
  updateIntelCache,
  writeCachedIntelItems,
  type SecurityIntelItem,
  type WorkspaceInventory,
} from "../../src/intel/index.js";
import type { Finding } from "../../src/shared/types.js";

const now = "2026-05-31T12:00:00.000Z";

test("OSV fetcher resolves querybatch ids into full advisory records", async (t) => {
  const calls = installFetchMock(t, async (url, init) => {
    if (url.endsWith("/v1/querybatch")) {
      assert.equal(init?.method, "POST");
      assert.match(String(init?.body), /lodash/);
      return jsonResponse({
        results: [{ vulns: [{ id: "GHSA-35jh-r3h4-6jhm", modified: now }] }],
      });
    }
    if (url.endsWith("/v1/vulns/GHSA-35jh-r3h4-6jhm")) {
      return jsonResponse({
        id: "GHSA-35jh-r3h4-6jhm",
        aliases: ["CVE-2021-23337"],
        summary: "Command injection in lodash",
        details: "A fixture advisory with package ranges.",
        published: "2021-02-15T00:00:00Z",
        modified: now,
        database_specific: { severity: "HIGH" },
        affected: [
          {
            package: { ecosystem: "npm", name: "lodash" },
            ranges: [{ events: [{ introduced: "0" }, { fixed: "4.17.21" }] }],
          },
        ],
      });
    }
    throw new Error(`Unexpected URL ${url}`);
  });

  const result = await osvFetcher.fetch({
    mode: "online",
    now,
    inventory: makeInventory(),
  });

  assert.equal(result.status, "fresh");
  assert.equal(calls.length, 2);
  assert.equal(result.items[0]?.identifiers.cve[0], "CVE-2021-23337");
  assert.equal(result.items[0]?.packages[0]?.affectedRange, ">=0 <4.17.21");
  assert.equal(result.items[0]?.packages[0]?.fixedVersion, "4.17.21");
  assert.equal(result.items[0]?.severity, "high");
});

test("NVD fetcher normalizes CVSS, CWE, and KEV metadata", async (t) => {
  installFetchMock(t, async (url) => {
    assert.match(url, /cveId=CVE-2024-12345/);
    return jsonResponse({
      vulnerabilities: [
        {
          cve: {
            id: "CVE-2024-12345",
            published: "2024-01-01T00:00:00.000",
            lastModified: "2024-01-02T00:00:00.000",
            descriptions: [{ lang: "en", value: "Acme package SQL injection." }],
            metrics: {
              cvssMetricV31: [
                {
                  cvssData: {
                    version: "3.1",
                    vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    baseScore: 9.8,
                    baseSeverity: "CRITICAL",
                  },
                },
              ],
            },
            weaknesses: [{ description: [{ lang: "en", value: "CWE-89" }] }],
            cisaExploitAdd: "2024-01-03",
            cisaActionDue: "2024-02-01",
            cisaVulnerabilityName: "Acme SQL Injection Vulnerability",
          },
        },
      ],
    });
  });

  const result = await nvdFetcher.fetch({
    mode: "online",
    now,
    inventory: { ...makeInventory(), previousFindingIds: ["CVE-2024-12345"] },
  });

  assert.equal(result.status, "fresh");
  assert.equal(result.items[0]?.severity, "critical");
  assert.equal(result.items[0]?.cvss?.score, 9.8);
  assert.equal(result.items[0]?.cvss?.version, "3");
  assert.equal(result.items[0]?.identifiers.cwe[0], "CWE-89");
  assert.equal(result.items[0]?.cisaKev?.knownExploited, true);
});

test("intel updater reuses fresh cache in auto mode", async (t) => {
  await withTempHermsecHome(t);
  const calls = installFetchMock(t, async () => jsonResponse({
    vulnerabilities: [
      {
        cveID: "CVE-2024-0001",
        vulnerabilityName: "Fixture exploited vulnerability",
        shortDescription: "Fixture KEV item.",
        dateAdded: "2024-01-01",
      },
    ],
  }, 200, { etag: "\"kev-fixture\"" }));

  const first = await updateIntelCache({
    mode: "online",
    now,
    fetchers: [cisaKevFetcher],
  });
  const second = await updateIntelCache({
    mode: "auto",
    now: "2026-05-31T12:10:00.000Z",
    fetchers: [cisaKevFetcher],
  });

  assert.equal(first.results[0]?.status, "fresh");
  assert.equal(second.results[0]?.status, "cached");
  assert.equal(second.items.some((item) => item.id === "cisa-kev:CVE-2024-0001"), true);
  assert.equal(calls.length, 1);
});

test("intel updater preserves cached advisories when a live source fails", async (t) => {
  await withTempHermsecHome(t);
  await writeCachedIntelItems([makeIntelItem()]);
  installFetchMock(t, async () => {
    throw new Error("simulated offline network");
  });

  const summary = await updateIntelCache({
    mode: "online",
    now,
    fetchers: [githubAdvisoryFetcher],
    inventory: makeInventory(),
  });

  assert.equal(summary.results[0]?.status, "failed");
  assert.equal(summary.items.some((item) => item.id === "github-advisory:GHSA-35jh-r3h4-6jhm"), true);
});

test("matcher scores package and finding identifier matches", () => {
  const finding = makeDependencyFinding();
  const item = makeIntelItem();
  const inventory = buildWorkspaceInventoryFromFindings("workspace-test", [finding], now);

  const workspaceMatches = matchIntelToWorkspace([item], inventory);
  const findingMatches = matchIntelToFindings([item], [finding], "workspace-test");

  assert.equal(workspaceMatches[0]?.priority, "urgent");
  assert.equal(workspaceMatches[0]?.matchedPackages[0], "npm:lodash@4.17.20");
  assert.equal(findingMatches[0]?.priority, "urgent");
  assert.equal(findingMatches[0]?.reasons.some((reason) => /ghsa-35jh-r3h4-6jhm/i.test(reason)), true);
});

function makeInventory(): WorkspaceInventory {
  return {
    workspaceId: "workspace-test",
    capturedAt: now,
    ecosystems: ["npm"],
    packages: [{ ecosystem: "npm", name: "lodash", version: "4.17.20", direct: true, files: ["package-lock.json"] }],
    runtimes: [],
    frameworks: [],
    ciTools: [],
    dockerImages: [],
    previousFindingIds: [],
  };
}

function makeIntelItem(): SecurityIntelItem {
  return {
    id: "github-advisory:GHSA-35jh-r3h4-6jhm",
    source: "github-advisory",
    sourceIds: ["GHSA-35jh-r3h4-6jhm"],
    title: "Known vulnerable lodash version",
    summary: "Fixture advisory.",
    url: "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
    identifiers: { cve: ["CVE-2021-23337"], ghsa: ["GHSA-35jh-r3h4-6jhm"], osv: [], cwe: ["CWE-79"] },
    ecosystems: ["npm"],
    packages: [{ ecosystem: "npm", name: "lodash", affectedRange: "<4.17.21", fixedVersion: "4.17.21" }],
    severity: "high",
    tags: ["dependency"],
    provenance: { fetchedAt: now, normalizedFrom: ["github-advisory"] },
  };
}

function makeDependencyFinding(): Finding {
  return {
    id: "finding-lodash",
    title: "Known vulnerable lodash version",
    category: "dependency",
    severity: "high",
    confidence: "high",
    description: "Fixture dependency finding.",
    evidence: "package-lock.json pins lodash@4.17.20.",
    remediation: "Upgrade lodash.",
    tool: "hermsec-offline",
    identifiers: { ghsa: ["GHSA-35jh-r3h4-6jhm"] },
    package: { ecosystem: "npm", name: "lodash", installedVersion: "4.17.20" },
    fingerprint: "fp-lodash",
  };
}

function installFetchMock(
  t: TestContext,
  handler: (url: string, init: Parameters<typeof fetch>[1]) => Promise<Response>,
): string[] {
  const originalFetch = globalThis.fetch;
  const calls: string[] = [];
  globalThis.fetch = (async (input: string | URL | Request, init?: Parameters<typeof fetch>[1]) => {
    const url = typeof input === "string" || input instanceof URL ? String(input) : input.url;
    calls.push(url);
    return handler(url, init);
  }) as typeof fetch;
  t.after(() => {
    globalThis.fetch = originalFetch;
  });
  return calls;
}

function jsonResponse(data: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

async function withTempHermsecHome(t: TestContext): Promise<string> {
  const previous = process.env.HERMSEC_HOME;
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-intel-"));
  process.env.HERMSEC_HOME = directory;
  t.after(async () => {
    if (previous === undefined) {
      delete process.env.HERMSEC_HOME;
    } else {
      process.env.HERMSEC_HOME = previous;
    }
    await fs.rm(directory, { recursive: true, force: true });
  });
  return directory;
}
