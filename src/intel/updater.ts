import { recordIntelFetchResult, readCachedIntelItems, upsertIntelItems } from "./cache.js";
import { defaultIntelFetchers } from "./fetchers.js";
import type { IntelFetchInput, IntelFetchResult, IntelFetcher, IntelSource, SecurityIntelItem } from "./schema.js";
import { offlineFallbackFeedItems } from "./sourceRegistry.js";

export type UpdateIntelOptions = Omit<IntelFetchInput, "now"> & {
  sources?: IntelSource[];
  now?: string;
  fetchers?: IntelFetcher[];
};

export type IntelUpdateSummary = {
  updatedAt: string;
  mode: IntelFetchInput["mode"];
  results: IntelFetchResult[];
  items: SecurityIntelItem[];
};

export async function updateIntelCache(options: UpdateIntelOptions = { mode: "auto" }): Promise<IntelUpdateSummary> {
  const now = options.now ?? new Date().toISOString();
  const mode = options.mode;
  const fetchers = options.fetchers ?? defaultIntelFetchers();
  const requested = options.sources ? new Set(options.sources) : undefined;
  const selected = fetchers.filter((fetcher) => !requested || requested.has(fetcher.source));

  const input: IntelFetchInput = {
    mode,
    now,
    ...(options.workspace ? { workspace: options.workspace } : {}),
    ...(options.inventory ? { inventory: options.inventory } : {}),
    ...(options.since ? { since: options.since } : {}),
  };

  const results: IntelFetchResult[] = [];
  if (mode !== "offline") {
    for (const fetcher of selected) {
      try {
        results.push(await recordIntelFetchResult(await fetcher.fetch(input)));
      } catch (error) {
        results.push(
          await recordIntelFetchResult({
            source: fetcher.source,
            fetchedAt: now,
            status: "failed",
            items: [],
            error: {
              code: "intel-fetch-failed",
              message: error instanceof Error ? error.message : String(error),
            },
          }),
        );
      }
    }
  }

  let items = await readCachedIntelItems();
  if (items.length === 0) {
    items = await upsertIntelItems(offlineFallbackFeedItems(now));
  }

  if (mode === "offline") {
    results.push({
      source: "vendor",
      fetchedAt: now,
      status: "cached",
      items: offlineFallbackFeedItems(now),
    });
  }

  return {
    updatedAt: now,
    mode,
    results,
    items,
  };
}
