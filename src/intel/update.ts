import type { CommandResult } from "../shared/types.js";
import { getIntelFeed } from "./feed.js";
import { updateIntelCache } from "./updater.js";
import { parseIntelSources } from "./sourceRegistry.js";

export async function updateIntel(options: {
  cwd: string;
  workspaceId?: string;
  sources?: string[];
  offline: boolean;
}): Promise<CommandResult> {
  const requested = parseIntelSources(options.sources ?? []);
  if (requested.invalid.length > 0) {
    return {
      ok: false,
      errorCode: "INTEL_SOURCE_UNKNOWN",
      message: `Unknown security intelligence source(s): ${requested.invalid.join(", ")}.`,
      remediation: "Use one of: cisa-kev, kev, osv, github-advisory, ghsa, nvd.",
    };
  }
  const summary = await updateIntelCache({
    mode: options.offline ? "offline" : "auto",
    ...(requested.sources.length > 0 ? { sources: requested.sources } : {}),
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
