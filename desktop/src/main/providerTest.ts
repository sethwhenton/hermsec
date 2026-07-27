import type { ModelConfig, ProviderTestRequest, ProviderTestResult } from "../renderer/src/types/settings";
import { getEnvDefaults } from "./env";
import { labelFromModelId } from "./providerCatalog";
import {
  redactExactCredential,
  resolveCredentialValue,
  safeEnvironmentVariableName,
} from "./providerCredentials";
import { isLoopbackProviderUrl } from "../shared/providerSecurity";
import { redactSecretText } from "./privacy";

const TIMEOUT_MS = 8000;
const ANTHROPIC_VERSION = "2023-06-01";

function resolveApiKey(request: ProviderTestRequest): string | undefined {
  if (request.providerId === "ollama-local") {
    return undefined;
  }
  const env = getEnvDefaults();
  return resolveCredentialValue(request, [env.apiKeyEnvVar]);
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
    const environmentVariable = safeEnvironmentVariableName(
      request.apiKeyEnvVar,
      getEnvDefaults().apiKeyEnvVar,
    );
    return {
      ok: false,
      message: `API key is required. Enter a key${
        environmentVariable
          ? ` or set ${environmentVariable}`
          : " or configure the provider API key environment variable"
      }.`,
      latencyMs: Date.now() - started,
    };
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    if (apiKey && isOpenRouterRequest(request, baseUrl)) {
      const credentialResponse = await fetch(`${baseUrl}/key`, {
        method: "GET",
        headers: {
          Accept: "application/json",
          Authorization: `Bearer ${apiKey}`,
        },
        signal: controller.signal,
      });
      if (!credentialResponse.ok) {
        return providerFailureResult(
          credentialResponse,
          started,
          "OpenRouter credential check failed",
          apiKey,
        );
      }
    }

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

    return providerFailureResult(response, started, "Request failed", apiKey);
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
      message: safeProviderErrorMessage(error, apiKey),
      latencyMs,
    };
  } finally {
    clearTimeout(timeout);
  }
}

function providerRequiresApiKey(request: ProviderTestRequest): boolean {
  return request.providerId !== "ollama-local" &&
    !isLoopbackProviderUrl(request.baseUrl);
}

function isOpenRouterRequest(
  request: ProviderTestRequest,
  baseUrl: string,
): boolean {
  if (request.providerId === "openrouter") return true;
  try {
    return new URL(baseUrl).hostname.toLocaleLowerCase() === "openrouter.ai";
  } catch {
    return false;
  }
}

async function providerFailureResult(
  response: Response,
  started: number,
  prefix = "Request failed",
  credential?: string,
): Promise<ProviderTestResult> {
  let detail = "";
  try {
    detail = safeProviderErrorDetail(await response.text(), credential);
  } catch {
    detail = "";
  }

  return {
    ok: false,
    status: response.status,
    message: detail
      ? `${prefix} (${response.status}): ${detail}`
      : `${prefix} with status ${response.status}`,
    latencyMs: Date.now() - started,
  };
}

function safeProviderErrorDetail(raw: string, credential?: string): string {
  let detail = raw;
  try {
    const parsed = JSON.parse(raw) as {
      error?: { message?: unknown };
      message?: unknown;
    };
    const message = parsed.error?.message ?? parsed.message;
    detail = typeof message === "string" ? message : "";
  } catch {
    // Plain-text provider errors are still redacted and bounded below.
  }
  return redactSecretText(redactExactCredential(detail, credential))
    .replace(/\s+/gu, " ")
    .trim()
    .slice(0, 200);
}

function safeProviderErrorMessage(error: unknown, credential?: string): string {
  const message = error instanceof Error ? error.message : "Unknown network error";
  const safeMessage = redactSecretText(redactExactCredential(message, credential))
    .replace(/\s+/gu, " ")
    .trim()
    .slice(0, 300);
  return safeMessage || "Unknown network error";
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
