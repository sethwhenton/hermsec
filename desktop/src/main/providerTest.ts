import type { ProviderTestRequest, ProviderTestResult } from "../renderer/src/types/settings";
import { getEnvDefaults } from "./env";

const TIMEOUT_MS = 8000;

function resolveApiKey(request: ProviderTestRequest): string | undefined {
  if (request.apiKey?.trim()) {
    return request.apiKey.trim();
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

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const headers: Record<string, string> = {
      Accept: "application/json",
    };
    if (apiKey) {
      headers.Authorization = `Bearer ${apiKey}`;
    }

    const response = await fetch(`${baseUrl}/models`, {
      method: "GET",
      headers,
      signal: controller.signal,
    });

    const latencyMs = Date.now() - started;

    if (response.ok) {
      return {
        ok: true,
        status: response.status,
        message: `Connected successfully (${response.status})`,
        latencyMs,
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
