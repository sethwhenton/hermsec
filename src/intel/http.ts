import type { HermsecError, IntelFetchCache, IntelSource } from "./schema.js";

export type IntelJsonResult<T> =
  | {
      ok: true;
      status: "fresh" | "not-modified";
      url: string;
      data?: T;
      etag?: string;
      lastModified?: string;
    }
  | {
      ok: false;
      url: string;
      httpStatus?: number;
      error: HermsecError;
    };

export type IntelJsonRequest = {
  method?: "GET" | "POST";
  headers?: Record<string, string>;
  body?: string;
  cache?: IntelFetchCache;
  timeoutMs?: number;
  signal?: AbortSignal;
};

const defaultTimeoutMs = 15_000;

export async function fetchIntelJson<T>(
  source: IntelSource,
  url: string | URL,
  request: IntelJsonRequest = {},
): Promise<IntelJsonResult<T>> {
  const target = String(url);
  const headers: Record<string, string> = {
    accept: "application/json",
    ...request.headers,
  };

  if (request.cache?.etag) {
    headers["if-none-match"] = request.cache.etag;
  }
  if (request.cache?.lastModified) {
    headers["if-modified-since"] = request.cache.lastModified;
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), request.timeoutMs ?? defaultTimeoutMs);

  try {
    const response = await fetch(target, {
      method: request.method ?? "GET",
      headers,
      ...(request.body ? { body: request.body } : {}),
      signal: request.signal
        ? AbortSignal.any([request.signal, controller.signal])
        : controller.signal,
    });

    const etag = response.headers.get("etag") ?? undefined;
    const lastModified = response.headers.get("last-modified") ?? undefined;

    if (response.status === 304) {
      return {
        ok: true,
        status: "not-modified",
        url: target,
        ...(etag ? { etag } : {}),
        ...(lastModified ? { lastModified } : {}),
      };
    }

    if (!response.ok) {
      return {
        ok: false,
        url: target,
        httpStatus: response.status,
        error: {
          code: `${source}-http`,
          message: `${source} returned HTTP ${response.status} for ${target}`,
        },
      };
    }

    const data = (await response.json()) as T;
    return {
      ok: true,
      status: "fresh",
      url: target,
      data,
      ...(etag ? { etag } : {}),
      ...(lastModified ? { lastModified } : {}),
    };
  } catch (error) {
    const aborted = error instanceof Error && error.name === "AbortError";
    const canceled = request.signal?.aborted === true;
    return {
      ok: false,
      url: target,
      error: {
          code: canceled
            ? `${source}-canceled`
            : aborted
              ? `${source}-timeout`
              : `${source}-network`,
          message: canceled
            ? `${source} request was canceled`
            : aborted
            ? `${source} request timed out after ${request.timeoutMs ?? defaultTimeoutMs}ms`
            : `${source} request failed: ${error instanceof Error ? error.message : String(error)}`,
      },
    };
  } finally {
    clearTimeout(timeout);
  }
}
