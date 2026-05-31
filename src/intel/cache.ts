import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { ensureHermsecAppData, getAppDataLayout } from "../storage/appData.js";
import { ensureDirectory, pathExists, writeJsonFileAtomic } from "../storage/jsonStore.js";
import { dedupeIntelItems } from "./dedupe.js";
import type { IntelFetchResult, IntelSource, SecurityIntelItem } from "./schema.js";

export type IntelSourceState = {
  source: IntelSource;
  lastFetchedAt?: string;
  status?: IntelFetchResult["status"];
  itemIds: string[];
  etag?: string;
  lastModified?: string;
  rawSnapshotPath?: string;
  error?: string;
};

export type IntelCacheIndex = {
  schemaVersion: 1;
  updatedAt: string;
  itemCount: number;
  sources: Record<string, IntelSourceState>;
};

function intelDir(): string {
  return getAppDataLayout().intelDir;
}

function indexPath(): string {
  return path.join(intelDir(), "index.json");
}

function itemsPath(): string {
  return path.join(intelDir(), "items.jsonl");
}

function sourceStatePath(source: IntelSource): string {
  return path.join(intelDir(), "sources", source, "state.json");
}

export async function ensureIntelCacheLayout(): Promise<void> {
  const layout = await ensureHermsecAppData();
  await Promise.all([
    ensureDirectory(layout.intelDir),
    ensureDirectory(path.join(layout.intelDir, "sources")),
    ensureDirectory(path.join(layout.intelDir, "relevance")),
    ensureDirectory(path.join(layout.intelDir, "offline-queue")),
  ]);
}

export function defaultIntelCacheIndex(): IntelCacheIndex {
  return {
    schemaVersion: 1,
    updatedAt: new Date(0).toISOString(),
    itemCount: 0,
    sources: {},
  };
}

export async function readIntelIndex(): Promise<IntelCacheIndex> {
  await ensureIntelCacheLayout();
  if (!(await pathExists(indexPath()))) {
    return defaultIntelCacheIndex();
  }
  const raw = await fs.readFile(indexPath(), "utf8");
  return JSON.parse(raw) as IntelCacheIndex;
}

export async function readIntelSourceState(source: IntelSource): Promise<IntelSourceState | undefined> {
  await ensureIntelCacheLayout();
  if (await pathExists(sourceStatePath(source))) {
    const raw = await fs.readFile(sourceStatePath(source), "utf8");
    return JSON.parse(raw) as IntelSourceState;
  }
  const index = await readIntelIndex();
  return index.sources[source];
}

export async function writeRawSnapshot(source: IntelSource, fetchedAt: string, raw: unknown): Promise<string> {
  await ensureIntelCacheLayout();
  const timestamp = fetchedAt.replace(/[:.]/g, "-");
  const directory = path.join(intelDir(), "sources", source);
  await ensureDirectory(directory);
  const serialized = JSON.stringify(raw, null, 2);
  const digest = crypto.createHash("sha256").update(serialized).digest("hex").slice(0, 16);
  const filePath = path.join(directory, `${timestamp}.${digest}.raw.json`);
  await fs.writeFile(filePath, `${serialized}\n`, { encoding: "utf8", mode: 0o600 });
  return filePath;
}

export async function readCachedIntelItems(): Promise<SecurityIntelItem[]> {
  await ensureIntelCacheLayout();
  if (!(await pathExists(itemsPath()))) {
    return [];
  }
  const raw = await fs.readFile(itemsPath(), "utf8");
  return raw
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => JSON.parse(line) as SecurityIntelItem);
}

export async function readCachedIntelItemsForSource(source: IntelSource): Promise<SecurityIntelItem[]> {
  const items = await readCachedIntelItems();
  return items.filter((item) => item.source === source || item.provenance.normalizedFrom.includes(source));
}

export async function writeCachedIntelItems(items: SecurityIntelItem[]): Promise<SecurityIntelItem[]> {
  await ensureIntelCacheLayout();
  const deduped = dedupeIntelItems(items);
  const payload = deduped.map((item) => JSON.stringify(item)).join("\n");
  await fs.writeFile(itemsPath(), payload ? `${payload}\n` : "", { encoding: "utf8", mode: 0o600 });
  const previous = await readIntelIndex();
  await writeJsonFileAtomic(indexPath(), {
    ...previous,
    schemaVersion: 1,
    updatedAt: new Date().toISOString(),
    itemCount: deduped.length,
  } satisfies IntelCacheIndex);
  return deduped;
}

export async function upsertIntelItems(items: SecurityIntelItem[]): Promise<SecurityIntelItem[]> {
  const existing = await readCachedIntelItems();
  return writeCachedIntelItems([...items, ...existing]);
}

export async function recordIntelFetchResult(result: IntelFetchResult): Promise<IntelFetchResult> {
  await ensureIntelCacheLayout();
  const index = await readIntelIndex();
  const previousState = index.sources[result.source] ?? (await readIntelSourceState(result.source));
  const rawSnapshotPath = result.raw === undefined
    ? result.rawSnapshotPath
    : await writeRawSnapshot(result.source, result.fetchedAt, result.raw);
  const items = rawSnapshotPath
    ? result.items.map((item) => ({
        ...item,
        provenance: { ...item.provenance, rawSnapshotPath },
      }))
    : result.items;

  if (items.length > 0) {
    await upsertIntelItems(items);
  }

  const state: IntelSourceState = {
    source: result.source,
    lastFetchedAt: result.fetchedAt,
    status: result.status,
    itemIds: items.length > 0 ? items.map((item) => item.id) : previousState?.itemIds ?? [],
    ...(result.etag ? { etag: result.etag } : {}),
    ...(result.lastModified ? { lastModified: result.lastModified } : {}),
    ...(rawSnapshotPath ? { rawSnapshotPath } : {}),
    ...(result.error ? { error: result.error.message } : {}),
  };
  await writeJsonFileAtomic(sourceStatePath(result.source), state);
  const nextIndex = await readIntelIndex();
  const updatesCache = result.status === "fresh" || result.status === "cached";
  await writeJsonFileAtomic(indexPath(), {
    ...nextIndex,
    updatedAt: updatesCache ? result.fetchedAt : nextIndex.updatedAt,
    itemCount: (await readCachedIntelItems()).length,
    sources: {
      ...nextIndex.sources,
      [result.source]: state,
    },
  } satisfies IntelCacheIndex);

  return {
    ...result,
    ...(rawSnapshotPath ? { rawSnapshotPath } : {}),
    items,
  };
}

export async function cacheAgeMs(now = new Date()): Promise<number | undefined> {
  const index = await readIntelIndex();
  const updated = Date.parse(index.updatedAt);
  return Number.isNaN(updated) || updated === 0 ? undefined : now.getTime() - updated;
}

export function sourceCacheAgeMs(state: IntelSourceState | undefined, now = new Date()): number | undefined {
  if (!state?.lastFetchedAt || state.status === "failed") {
    return undefined;
  }
  const updated = Date.parse(state.lastFetchedAt);
  return Number.isNaN(updated) ? undefined : now.getTime() - updated;
}

export function sourceCacheFresh(state: IntelSourceState | undefined, ttlMs: number, now = new Date()): boolean {
  const age = sourceCacheAgeMs(state, now);
  return age !== undefined && age >= 0 && age < ttlMs;
}
