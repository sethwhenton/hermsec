import type { IntelFeedItem, SecurityIntelItem } from "./schema.js";

function identifiers(item: SecurityIntelItem): string {
  const ids = [
    ...item.identifiers.cve,
    ...item.identifiers.ghsa,
    ...item.identifiers.osv,
  ];
  return ids.length > 0 ? ids.join(", ") : item.id;
}

export function summarizeIntelItem(item: SecurityIntelItem): string {
  const packageText = item.packages.length > 0
    ? ` Affected packages: ${item.packages
        .map((pkg) => `${pkg.ecosystem}:${pkg.name}${pkg.affectedRange ? ` ${pkg.affectedRange}` : ""}`)
        .join("; ")}.`
    : "";
  const kevText = item.cisaKev?.knownExploited ? " CISA KEV marks it as known exploited." : "";
  return `${item.title} (${identifiers(item)}). Severity: ${item.severity}.${packageText}${kevText}`;
}

export function summarizeIntelFeed(items: IntelFeedItem[], limit = 5): string {
  if (items.length === 0) {
    return "No cached security intelligence items are currently relevant to this workspace.";
  }
  return items
    .slice(0, limit)
    .map((entry, index) => {
      const why = entry.whyShown.length > 0 ? ` Why shown: ${entry.whyShown.join(" ")}` : "";
      return `${index + 1}. ${summarizeIntelItem(entry.item)}${why} [${entry.item.id}]`;
    })
    .join("\n");
}
