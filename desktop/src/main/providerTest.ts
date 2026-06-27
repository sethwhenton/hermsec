import type { ModelConfig, ProviderTestRequest, ProviderTestResult } from "../renderer/src/types/settings";
import { getEnvDefaults } from "./env";
import { labelFromModelId } from "./providerCatalog";

const TIMEOUT_MS = 8000;
const ANTHROPIC_VERSION = "2023-06-01";

function resolveApiKey(request: ProviderTestRequest): string | undefined {
  if (request.apiKey?.trim()) {
    return request.apiKey.trim();
  }
  if (request.providerId === "ollama-local") {
    return undefined;
  }
  if (request.apiKeyEnvVar?.trim()) {
    return process.env[request.apiKeyEnvVar.trim()];
  }
  const env = getEnvDefaults();
  return process.env[env.apiKeyEnvVar];
}

function resolveBaseUrl(request: ProviderTestRequest): string {
  if (request.baseUrl?.trim()) {
    return request.baseUrl.trim().replace(/\/$/, "");
  }
  return getEnvDefaults().baseUrl.replace(/\/$/, "");
}

export async function testProvider(request: ProviderTestRequest): Promise<ProviderTestResult> {
  const started = Date.now();
  const baseUrl = resolveBaseUrl(request);
  const apiKey = resolveApiKey(request);

  if (!baseUrl) {
    return {
      ok: false,
      message: "Base URL is required. Set it in the provider form or HERMSEC_MODEL_BASE_URL.",
      latencyMs: Date.now() - started,
    };
  }

  if (!apiKey && providerRequiresApiKey(request)) {
    return {
      ok: false,
      message: `API key is required. Enter a key or set ${request.apiKeyEnvVar || "the provider API key environment variable"}.`,
      latencyMs: Date.now() - started,
    };
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const response = await fetchModelList({ request, baseUrl, apiKey, signal: controller.signal });
    const latencyMs = Date.now() - started;

    if (response.ok) {
      const models = normalizeModelResponse(await response.json(), request);
      return {
        ok: true,
        status: response.status,
        message: models.length > 0
          ? `Connected successfully. ${models.length} model${models.length === 1 ? "" : "s"} available.`
          : `Connected successfully (${response.status}), but no models were returned.`,
        latencyMs,
        modelCount: models.length,
        models,
      };
    }

    let detail = "";
    try {
      const body = await response.text();
      detail = body.slice(0, 200);
    } catch {
      detail = "";
    }

    return {
      ok: false,
      status: response.status,
      message: detail
        ? `Request failed (${response.status}): ${detail}`
        : `Request failed with status ${response.status}`,
      latencyMs,
    };
  } catch (error) {
    const latencyMs = Date.now() - started;
    if (error instanceof Error && error.name === "AbortError") {
      return {
        ok: false,
        message: `Request timed out after ${TIMEOUT_MS / 1000}s`,
        latencyMs,
      };
    }
    return {
      ok: false,
      message: error instanceof Error ? error.message : "Unknown network error",
      latencyMs,
    };
  } finally {
    clearTimeout(timeout);
  }
}

function providerRequiresApiKey(request: ProviderTestRequest): boolean {
  return request.providerId === "ollama-cloud" || request.apiFormat === "cursor";
}

async function fetchModelList({
  request,
  baseUrl,
  apiKey,
  signal,
}: {
  request: ProviderTestRequest;
  baseUrl: string;
  apiKey?: string;
  signal: AbortSignal;
}): Promise<Response> {
  const headers: Record<string, string> = {
    Accept: "application/json",
  };
  const apiFormat = request.apiFormat ?? "openai-compatible";

  if (apiFormat === "anthropic") {
    if (apiKey) headers["x-api-key"] = apiKey;
    headers["anthropic-version"] = ANTHROPIC_VERSION;
    return fetch(`${baseUrl}/models`, { method: "GET", headers, signal });
  }

  if (apiFormat === "gemini") {
    const url = geminiModelsUrl(baseUrl, apiKey);
    if (apiKey) headers["x-goog-api-key"] = apiKey;
    return fetch(url, { method: "GET", headers, signal });
  }

  if (apiFormat === "cursor") {
    if (apiKey) headers.Authorization = `Basic ${Buffer.from(`${apiKey}:`).toString("base64")}`;
    return fetch(`${baseUrl}/v0/models`, { method: "GET", headers, signal });
  }

  if (apiKey) {
    headers.Authorization = `Bearer ${apiKey}`;
  }
  return fetch(`${baseUrl}/models`, { method: "GET", headers, signal });
}

function normalizeModelResponse(value: unknown, request: ProviderTestRequest): ModelConfig[] {
  if (request.apiFormat === "cursor") {
    return uniqueModels(cursorModelIds(value).map((id) => ({
      id,
      label: labelFromModelId(id),
      enabled: true,
    })));
  }

  const records = modelRecords(value);
  const models = records
    .map((record) => modelFromRecord(record, request.apiFormat))
    .filter((model): model is ModelConfig => Boolean(model?.id));

  return uniqueModels(models);
}

function uniqueModels(models: ModelConfig[]): ModelConfig[] {
  const seen = new Set<string>();
  return models.filter((model) => {
    if (seen.has(model.id)) return false;
    seen.add(model.id);
    return true;
  });
}

function cursorModelIds(value: unknown): string[] {
  if (!value || typeof value !== "object") return [];
  const record = value as Record<string, unknown>;
  const models = record.models;
  if (!Array.isArray(models)) return [];
  return models.filter((item): item is string => typeof item === "string" && item.trim().length > 0);
}

function modelRecords(value: unknown): Array<Record<string, unknown>> {
  if (!value || typeof value !== "object") return [];
  const record = value as Record<string, unknown>;
  const candidates = [record.data, record.models];
  for (const candidate of candidates) {
    if (Array.isArray(candidate)) {
      return candidate.filter((item): item is Record<string, unknown> =>
        Boolean(item && typeof item === "object" && !Array.isArray(item)),
      );
    }
  }
  return [];
}

function modelFromRecord(record: Record<string, unknown>, apiFormat = "openai-compatible"): ModelConfig | undefined {
  const rawId = typeof record.id === "string"
    ? record.id
    : typeof record.name === "string"
      ? record.name
      : undefined;
  if (!rawId) return undefined;

  const id = apiFormat === "gemini" ? rawId.replace(/^models\//u, "") : rawId;
  const label =
    stringValue(record.display_name) ??
    stringValue(record.displayName) ??
    stringValue(record.name) ??
    labelFromModelId(id);
  return {
    id,
    label: label.replace(/^models\//u, ""),
    enabled: true,
  };
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function geminiModelsUrl(baseUrl: string, apiKey: string | undefined): string {
  const url = new URL(baseUrl);
  url.pathname = url.pathname.replace(/\/openai\/?$/u, "").replace(/\/?$/u, "/models");
  if (apiKey) {
    url.searchParams.set("key", apiKey);
  }
  return url.toString();
}
