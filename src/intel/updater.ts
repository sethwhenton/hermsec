import {
  recordIntelFetchResult,
  readCachedIntelItems,
  readCachedIntelItemsForSource,
  readIntelSourceState,
  sourceCacheFresh,
  upsertIntelItems,
} from "./cache.js";
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
  if (mode === "offline") {
    const cached = await readCachedIntelItems();
    if (cached.length > 0) {
      results.push({
        source: "vendor",
        fetchedAt: now,
        status: "cached",
        items: cached,
      });
    }
  } else {
    for (const fetcher of selected) {
      results.push(await runFetcher(fetcher, input));
    }
  }

  let items = await readCachedIntelItems();
  if (items.length === 0) {
    items = await upsertIntelItems(offlineFallbackFeedItems(now));
  }

  if (mode === "offline" && results.length === 0) {
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

async function runFetcher(fetcher: IntelFetcher, input: IntelFetchInput): Promise<IntelFetchResult> {
  const now = new Date(input.now);
  const state = await readIntelSourceState(fetcher.source);
  const cachedItems = await readCachedIntelItemsForSource(fetcher.source);

  if (input.mode === "auto" && cachedItems.length > 0 && sourceCacheFresh(state, fetcher.ttlMs, now)) {
    return {
      source: fetcher.source,
      fetchedAt: input.now,
      status: "cached",
      items: cachedItems,
      ...(state?.etag ? { etag: state.etag } : {}),
      ...(state?.lastModified ? { lastModified: state.lastModified } : {}),
    };
  }

  const fetchInput: IntelFetchInput = {
    ...input,
    ...(state?.etag || state?.lastModified
      ? { cache: { ...(state.etag ? { etag: state.etag } : {}), ...(state.lastModified ? { lastModified: state.lastModified } : {}) } }
      : {}),
  };

  try {
    const result = await fetcher.fetch(fetchInput);
    const hydratedResult = result.status === "cached" && result.items.length === 0 && cachedItems.length > 0
      ? { ...result, items: cachedItems }
      : result;
    return recordIntelFetchResult(hydratedResult);
  } catch (error) {
    return recordIntelFetchResult({
      source: fetcher.source,
      fetchedAt: input.now,
      status: "failed",
      items: [],
      error: {
        code: "intel-fetch-failed",
        message: error instanceof Error ? error.message : String(error),
      },
    });
  }
}
