import type { CommandResult } from "../shared/types.js";
import { getIntelFeed } from "./feed.js";
import { updateIntelCache } from "./updater.js";
import type { IntelSource } from "./schema.js";

export async function updateIntel(options: {
  cwd: string;
  workspaceId?: string;
  sources?: string[];
  offline: boolean;
}): Promise<CommandResult> {
  const summary = await updateIntelCache({
    mode: options.offline ? "offline" : "auto",
    ...(options.sources ? { sources: options.sources as IntelSource[] } : {}),
  });
  const feed = await getIntelFeed({ limit: 10, includeFallback: true });
  return {
    ok: true,
    message: `Security intelligence updated: ${summary.items.length} cached item(s), ${summary.results.length} source result(s).`,
    data: {
      summary,
      feed: feed.map((item) => ({
        id: item.item.id,
        title: item.item.title,
        source: item.item.source,
        whyShown: item.whyShown,
      })),
    },
  };
}
