import { cacheAgeMs, readCachedIntelItems } from "./cache.js";
import { dedupeIntelItems } from "./dedupe.js";
import { matchIntelToWorkspace } from "./matcher.js";
import { offlineFallbackFeedItems } from "./sourceRegistry.js";
import type { IntelFeedItem, SecurityIntelItem, WorkspaceInventory } from "./schema.js";

export type IntelFeedOptions = {
  inventory?: WorkspaceInventory;
  limit?: number;
  urgentOnly?: boolean;
  includeFallback?: boolean;
};

function defaultWhyShown(item: SecurityIntelItem): string[] {
  if (item.cisaKev?.knownExploited) {
    return ["CISA KEV marks this item as known exploited"];
  }
  if (item.tags.includes("offline")) {
    return [item.summary ?? "Offline fallback guidance"];
  }
  return ["General security intelligence from a trusted source"];
}

export async function getIntelFeed(options: IntelFeedOptions = {}): Promise<IntelFeedItem[]> {
  const cached = await readCachedIntelItems();
  const age = await cacheAgeMs();
  const fallback = cached.length === 0 || options.includeFallback ? offlineFallbackFeedItems() : [];
  const items = dedupeIntelItems([...cached, ...fallback]);
  const relevance = options.inventory ? matchIntelToWorkspace(items, options.inventory) : [];
  const relevanceById = new Map(relevance.map((item) => [item.itemId, item]));

  return items
    .map((item) => {
      const itemRelevance = relevanceById.get(item.id);
      return {
        item,
        ...(itemRelevance ? { relevance: itemRelevance } : {}),
        whyShown: itemRelevance?.reasons ?? defaultWhyShown(item),
        cacheStatus: item.tags.includes("offline") ? "fallback" : age === undefined ? "cached" : "fresh",
      } satisfies IntelFeedItem;
    })
    .filter((feedItem) => {
      if (options.urgentOnly) {
        return feedItem.relevance?.priority === "urgent" || feedItem.item.cisaKev?.knownExploited;
      }
      if (!options.inventory) {
        return true;
      }
      return Boolean(feedItem.relevance) || feedItem.item.tags.includes("offline");
    })
    .sort((a, b) => {
      const scoreA = a.relevance?.score ?? (a.item.cisaKev?.knownExploited ? 25 : 0);
      const scoreB = b.relevance?.score ?? (b.item.cisaKev?.knownExploited ? 25 : 0);
      return scoreB - scoreA || b.item.provenance.fetchedAt.localeCompare(a.item.provenance.fetchedAt);
    })
    .slice(0, options.limit ?? 20);
}
