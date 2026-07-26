import assert from "node:assert/strict";
import test from "node:test";
import { anthropicProvider } from "../../src/model/anthropic.js";
import { credentialFingerprint } from "../../src/model/credentials.js";
import { geminiProvider } from "../../src/model/gemini.js";
import { createOpenAiCompatibleProvider } from "../../src/model/openaiCompatible.js";
import {
  ModelProviderRequestError,
  type OpenRouterMaxPrice,
  type ProviderConfig,
} from "../../src/model/provider.js";

test("provider health verifies env credentials without exposing the key", async () => {
  const envName = "HERMSEC_TEST_PROVIDER_KEY";
  const secret = "sk-test-provider-secret-value-1234567890";
  const previous = process.env[envName];
  process.env[envName] = secret;

  try {
    const provider = createOpenAiCompatibleProvider({
      id: "opencode-go",
      baseUrl: "https://example.invalid/v1",
      credentialEnv: envName,
      models: ["test-model"],
      local: false,
      label: "Test provider",
    });

    const health = await provider.healthCheck();
    const serialized = JSON.stringify(health);

    assert.equal(health.ok, true);
    assert.equal(health.credential, "env-present");
    assert.equal(health.credentialEnv, envName);
    assert.equal(health.credentialFingerprint, credentialFingerprint(secret));
    assert.equal(serialized.includes(secret), false);
  } finally {
    if (previous === undefined) {
      delete process.env[envName];
    } else {
      process.env[envName] = previous;
    }
  }
});

test("provider health rejects raw-looking credential references without leaking them", async () => {
  const rawLookingKey = "sk-this-should-not-be-echoed-1234567890";
  const provider = createOpenAiCompatibleProvider({
    id: "opencode-go",
    baseUrl: "https://example.invalid/v1",
    credentialEnv: "HERMSEC_TEST_PROVIDER_KEY",
    models: ["test-model"],
    local: false,
    label: "Test provider",
  });

  const health = await provider.healthCheck({ apiKeyEnv: rawLookingKey });
  const serialized = JSON.stringify(health);

  assert.equal(health.ok, false);
  assert.equal(health.credentialEnv, "<invalid-env-name>");
  assert.equal(serialized.includes(rawLookingKey), false);
  await assert.rejects(
    () => provider.complete({ messages: [{ role: "user", content: "hello" }] }, { apiKeyEnv: rawLookingKey }),
    /environment variable name/,
  );
});

test("OpenAI-compatible providers send chat completion requests through configured env credentials", async () => {
  const envName = "HERMSEC_TEST_OPENAI_COMPAT_KEY";
  const secret = "sk-test-openai-compatible-secret-1234567890";
  const previousSecret = process.env[envName];
  const previousFetch = globalThis.fetch;
  process.env[envName] = secret;

  try {
    const provider = createOpenAiCompatibleProvider({
      id: "openai-compatible",
      baseUrl: "https://example.invalid/v1/",
      credentialEnv: envName,
      models: ["test-model"],
      local: true,
      label: "Test provider",
    });
    globalThis.fetch = (async (input, init) => {
      assert.equal(String(input), "https://example.invalid/v1/chat/completions");
      assert.equal((init?.headers as Record<string, string>).authorization, `Bearer ${secret}`);
      const body = JSON.parse(String(init?.body)) as { model: string; messages: unknown[]; max_tokens?: number };
      assert.equal(body.model, "test-model");
      assert.equal(body.max_tokens, 128);
      assert.equal(body.messages.length, 1);
      return new Response(JSON.stringify({
        model: "test-model",
        choices: [{ message: { content: "Provider explanation" } }],
        usage: { prompt_tokens: 11, completion_tokens: 7, total_tokens: 18 },
      }), { status: 200 });
    }) as typeof fetch;

    const response = await provider.complete({
      messages: [{ role: "user", content: "hello" }],
      maxTokens: 128,
    });

    assert.equal(response.provider, "openai-compatible");
    assert.equal(response.content, "Provider explanation");
    assert.equal(response.usage?.totalTokens, 18);
  } finally {
    globalThis.fetch = previousFetch;
    if (previousSecret === undefined) {
      delete process.env[envName];
    } else {
      process.env[envName] = previousSecret;
    }
  }
});

test("OpenAI-compatible providers preserve normalized tool calls and accept tool-only responses", async () => {
  const previousFetch = globalThis.fetch;

  try {
    const provider = createOpenAiCompatibleProvider({
      id: "openai-compatible",
      baseUrl: "https://example.invalid/v1",
      models: ["tool-model"],
      local: true,
      label: "Tool provider",
    });
    globalThis.fetch = (async (_input, init) => {
      const body = JSON.parse(String(init?.body)) as {
        messages: Array<Record<string, unknown>>;
        tools: unknown[];
        tool_choice: string;
        parallel_tool_calls: boolean;
      };
      assert.equal(body.tools.length, 1);
      assert.equal(body.tool_choice, "auto");
      assert.equal(body.parallel_tool_calls, false);
      assert.deepEqual(body.messages[1], {
        role: "assistant",
        content: null,
        tool_calls: [{
          id: "prior-call",
          type: "function",
          function: { name: "inspect_project", arguments: "{}" },
        }],
      });
      assert.deepEqual(body.messages[2], {
        role: "tool",
        tool_call_id: "prior-call",
        content: "{\"ok\":true}",
      });
      return new Response(JSON.stringify({
        model: "tool-model",
        choices: [{
          finish_reason: "tool_calls",
          message: {
            content: null,
            tool_calls: [{
              id: "next-call",
              type: "function",
              function: {
                name: "search_code",
                arguments: "{\"query\":\"exec(\"}",
              },
            }],
          },
        }],
        usage: { prompt_tokens: 20, completion_tokens: 4, total_tokens: 24 },
      }), { status: 200 });
    }) as typeof fetch;

    const response = await provider.complete({
      messages: [
        { role: "user", content: "inspect" },
        {
          role: "assistant",
          content: "",
          toolCalls: [{
            id: "prior-call",
            type: "function",
            function: { name: "inspect_project", arguments: "{}" },
          }],
        },
        {
          role: "tool",
          toolCallId: "prior-call",
          name: "inspect_project",
          content: "{\"ok\":true}",
        },
      ],
      tools: [{
        type: "function",
        function: {
          name: "search_code",
          description: "Search source",
          parameters: { type: "object" },
        },
      }],
      toolChoice: "auto",
    });

    assert.equal(response.content, "");
    assert.equal(response.finishReason, "tool_calls");
    assert.equal(response.toolCalls?.[0]?.id, "next-call");
    assert.equal(response.toolCalls?.[0]?.function.name, "search_code");
    assert.equal(response.usage?.totalTokens, 24);
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test("OpenAI-compatible providers reject tool calls without a valid provider ID", async () => {
  const previousFetch = globalThis.fetch;
  try {
    const provider = createOpenAiCompatibleProvider({
      id: "openai-compatible",
      baseUrl: "https://example.invalid/v1",
      models: ["tool-model"],
      local: true,
    });
    for (const id of [undefined, "invalid tool id"]) {
      globalThis.fetch = (async () => new Response(JSON.stringify({
        model: "tool-model",
        choices: [{
          message: {
            content: null,
            tool_calls: [{
              ...(id === undefined ? {} : { id }),
              type: "function",
              function: { name: "inspect_project", arguments: "{}" },
            }],
          },
        }],
      }), { status: 200 })) as typeof fetch;

      await assert.rejects(
        () => provider.complete({
          messages: [{ role: "user", content: "inspect" }],
          tools: [{
            type: "function",
            function: {
              name: "inspect_project",
              description: "Inspect",
              parameters: { type: "object" },
            },
          }],
        }),
        /without a valid ID/i,
      );
    }
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test("OpenAI-compatible JSON completion makes one HTTP request and fails a blank response", async () => {
  const previousFetch = globalThis.fetch;
  let attempts = 0;
  try {
    const provider = createOpenAiCompatibleProvider({
      id: "openai-compatible",
      baseUrl: "https://example.invalid/v1",
      models: ["test-model"],
      local: true,
    });
    globalThis.fetch = (async () => {
      attempts += 1;
      return new Response(JSON.stringify({
        model: "test-model",
        choices: [{ message: { content: null } }],
        usage: { prompt_tokens: 1, completion_tokens: 0, total_tokens: 1 },
      }), { status: 200 });
    }) as typeof fetch;

    await assert.rejects(
      () => provider.complete({
        messages: [{ role: "user", content: "return json" }],
        responseFormat: "json",
      }),
      /returned no message content/i,
    );
    assert.equal(attempts, 1);
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test("OpenRouter classifies a blank generation as provider unavailable", async () => {
  const previousFetch = globalThis.fetch;
  try {
    const provider = createOpenAiCompatibleProvider({
      id: "openrouter",
      baseUrl: "https://openrouter.example/api/v1",
      models: ["requested/model"],
      local: true,
    });
    globalThis.fetch = (async () =>
      new Response(
        JSON.stringify({
          model: "requested/model",
          choices: [{ message: { content: null } }],
          usage: {
            prompt_tokens: 10,
            completion_tokens: 0,
            total_tokens: 10,
          },
        }),
        { status: 200 },
      )) as typeof fetch;

    await assert.rejects(
      () =>
        provider.complete({
          messages: [{ role: "user", content: "return json" }],
          model: "requested/model",
          responseFormat: "json",
        }),
      (error: unknown) => {
        assert.ok(error instanceof ModelProviderRequestError);
        assert.equal(error.provider, "openrouter");
        assert.equal(error.errorType, "provider_unavailable");
        assert.match(error.message, /returned no message content/i);
        return true;
      },
    );
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test("OpenRouter tool requests send bounded routing controls and retain authoritative metadata", async () => {
  const previousFetch = globalThis.fetch;
  try {
    const provider = createOpenAiCompatibleProvider({
      id: "openrouter",
      baseUrl: "https://openrouter.example/api/v1",
      models: ["requested/model"],
      local: true,
    });
    globalThis.fetch = (async (_input, init) => {
      const headers = init?.headers as Record<string, string>;
      assert.equal(headers["x-openrouter-metadata"], "enabled");
      const body = JSON.parse(String(init?.body)) as {
        provider?: {
          require_parameters?: boolean;
          allow_fallbacks?: boolean;
          data_collection?: string;
        };
        parallel_tool_calls?: boolean;
      };
      assert.deepEqual(body.provider, {
        require_parameters: true,
        allow_fallbacks: true,
        data_collection: "deny",
      });
      assert.equal(
        Object.hasOwn(body, "models"),
        false,
        "provider endpoint failover must not introduce model-family fallbacks",
      );
      assert.equal(
        Object.hasOwn(body, "parallel_tool_calls"),
        false,
        "exact OpenRouter routes must not require an unsupported parallel_tool_calls parameter",
      );
      return new Response(JSON.stringify({
        id: "gen-response-123",
        model: "requested/model",
        provider: "Route Provider",
        choices: [{
          finish_reason: "tool_calls",
          message: {
            content: null,
            tool_calls: [{
              id: "call-1",
              function: { name: "inspect_project", arguments: "{}" },
            }],
          },
        }],
        usage: {
          prompt_tokens: 50,
          completion_tokens: 7,
          total_tokens: 57,
          cost: 0.000123,
          cost_details: { upstream_inference_cost: 0.0001 },
          prompt_tokens_details: { cached_tokens: 12, cache_write_tokens: 3 },
          completion_tokens_details: { reasoning_tokens: 4 },
        },
        openrouter_metadata: {
          requested: "requested/model",
          strategy: "fallback",
          region: "fra",
          attempt: 2,
          is_byok: false,
          endpoints: {
            available: [{
              provider: "Route Provider",
              model: "requested/model",
              selected: true,
            }],
          },
          attempts: [
            { provider: "First Provider", model: "requested/model", status: 503 },
            { provider: "Route Provider", model: "requested/model", status: 200 },
          ],
        },
      }), {
        status: 200,
        headers: {
          "x-generation-id": "gen-header-456",
          "x-request-id": "req-header-789",
        },
      });
    }) as typeof fetch;

    const response = await provider.complete({
      messages: [{ role: "user", content: "inspect" }],
      tools: [{
        type: "function",
        function: {
          name: "inspect_project",
          description: "Inspect",
          parameters: { type: "object" },
        },
      }],
    }, {
      openRouter: {
        allowFallbacks: true,
        requireParameters: false,
        dataCollection: "allow",
        captureRouteMetadata: false,
      },
    });

    assert.equal(response.model, "requested/model");
    assert.equal(response.responseId, "gen-response-123");
    assert.equal(response.generationId, "gen-header-456");
    assert.equal(response.requestId, "req-header-789");
    assert.equal(response.usage?.authoritativeUsd, 0.000123);
    assert.equal(response.usage?.upstreamInferenceUsd, 0.0001);
    assert.equal(response.usage?.cachedPromptTokens, 12);
    assert.equal(response.usage?.cacheWritePromptTokens, 3);
    assert.equal(response.usage?.reasoningTokens, 4);
    assert.equal(response.route?.selectedProvider, "Route Provider");
    assert.equal(response.route?.attempt, 2);
    assert.equal(response.route?.attempts?.length, 2);
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test("OpenRouter exact requests preserve explicit endpoint-fallback policy and otherwise default it on", async () => {
  const previousFetch = globalThis.fetch;
  try {
    const provider = createOpenAiCompatibleProvider({
      id: "openrouter",
      baseUrl: "https://openrouter.example/api/v1",
      models: ["requested/model"],
      local: true,
    });
    const observedFallbackPolicies: boolean[] = [];
    const observedMaxPrices: Array<OpenRouterMaxPrice | undefined> = [];
    globalThis.fetch = (async (_input, init) => {
      const body = JSON.parse(String(init?.body)) as {
        models?: unknown;
        provider?: {
          allow_fallbacks?: boolean;
          max_price?: OpenRouterMaxPrice;
        };
      };
      assert.equal(
        Object.hasOwn(body, "models"),
        false,
        "endpoint fallback must never introduce a model-family fallback list",
      );
      assert.equal(typeof body.provider?.allow_fallbacks, "boolean");
      observedFallbackPolicies.push(body.provider?.allow_fallbacks as boolean);
      observedMaxPrices.push(body.provider?.max_price);
      return new Response(JSON.stringify({
        model: "requested/model",
        provider: "Route Provider",
        choices: [{ message: { content: "accepted" } }],
        openrouter_metadata: {
          requested: "requested/model",
          endpoints: {
            available: [{
              provider: "Route Provider",
              model: "requested/model",
              selected: true,
            }],
          },
        },
      }), { status: 200 });
    }) as typeof fetch;

    await provider.complete({
      messages: [{ role: "user", content: "use the configured route" }],
      requireExactModel: true,
    }, {
      openRouter: {
        allowFallbacks: false,
        maxPrice: {
          prompt: "0.0938",
          completion: "0.1876",
          request: "0",
        },
      },
    });
    await provider.complete({
      messages: [{ role: "user", content: "use the default route policy" }],
      requireExactModel: true,
    });

    assert.deepEqual(observedFallbackPolicies, [false, true]);
    assert.deepEqual(observedMaxPrices, [
      {
        prompt: "0.0938",
        completion: "0.1876",
        request: "0",
      },
      undefined,
    ]);
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test("OpenRouter rejects malformed max-price ceilings before network dispatch", async () => {
  const previousFetch = globalThis.fetch;
  let fetchCalls = 0;
  try {
    const provider = createOpenAiCompatibleProvider({
      id: "openrouter",
      baseUrl: "https://openrouter.example/api/v1",
      models: ["requested/model"],
      local: true,
    });
    globalThis.fetch = (async () => {
      fetchCalls += 1;
      throw new Error("network must not be called");
    }) as typeof fetch;
    const invalidMaxPrices: unknown[] = [
      {},
      { prompt: "-1" },
      { prompt: "NaN" },
      { prompt: "1e-3" },
      { prompt: 0.1 },
      { prompt: "0.1", currency: "USD" },
    ];

    for (const candidate of invalidMaxPrices) {
      await assert.rejects(
        () =>
          provider.complete(
            {
              messages: [{ role: "user", content: "inspect" }],
              requireExactModel: true,
            },
            {
              openRouter: {
                maxPrice:
                  candidate as NonNullable<
                    NonNullable<
                      ProviderConfig["openRouter"]
                    >["maxPrice"]
                  >,
              },
            },
          ),
        /max price/iu,
      );
    }
    assert.equal(fetchCalls, 0);
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test("OpenRouter transport timeouts become typed timeout failures", async () => {
  const previousFetch = globalThis.fetch;
  try {
    const provider = createOpenAiCompatibleProvider({
      id: "openrouter",
      baseUrl: "https://openrouter.example/api/v1",
      models: ["requested/model"],
      local: true,
    });
    globalThis.fetch = ((_input, init) =>
      new Promise<Response>((_resolve, reject) => {
        const signal = init?.signal;
        assert.ok(signal);
        const rejectWithReason = () => {
          reject(
            signal.reason ??
              new DOMException("The operation timed out.", "TimeoutError"),
          );
        };
        if (signal.aborted) {
          rejectWithReason();
        } else {
          signal.addEventListener("abort", rejectWithReason, {
            once: true,
          });
        }
      })) as typeof fetch;

    await assert.rejects(
      () =>
        provider.complete(
          {
            messages: [{ role: "user", content: "inspect" }],
          },
          { timeoutMs: 5 },
        ),
      (error: unknown) => {
        assert.ok(error instanceof ModelProviderRequestError);
        assert.equal(error.status, undefined);
        assert.equal(error.errorType, "timeout");
        assert.equal(error.providerCode, undefined);
        assert.match(error.message, /provider request timed out/u);
        assert.doesNotMatch(error.message, /abort/iu);
        return true;
      },
    );
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test("OpenRouter errors retain typed diagnostics without echoing moderation input", async () => {
  const previousFetch = globalThis.fetch;
  const flaggedInput = "sensitive-provider-input-that-must-not-be-logged";
  try {
    const provider = createOpenAiCompatibleProvider({
      id: "openrouter",
      baseUrl: "https://openrouter.example/api/v1",
      models: ["requested/model"],
      local: true,
    });
    globalThis.fetch = (async () =>
      new Response(
        JSON.stringify({
          error: {
            code: 429,
            message: "Rate limit exceeded",
            metadata: {
              error_type: "rate_limit_exceeded",
              provider_code: "rate_limited",
              flagged_input: flaggedInput,
            },
          },
        }),
        { status: 429 },
      )) as typeof fetch;

    await assert.rejects(
      () =>
        provider.complete({
          messages: [{ role: "user", content: "inspect" }],
        }),
      (error: unknown) => {
        assert.ok(error instanceof ModelProviderRequestError);
        assert.equal(error.provider, "openrouter");
        assert.equal(error.status, 429);
        assert.equal(error.errorType, "rate_limit_exceeded");
        assert.equal(error.providerCode, "rate_limited");
        const message =
          error instanceof Error ? error.message : String(error);
        assert.match(message, /error_type=rate_limit_exceeded/u);
        assert.match(message, /provider_code=rate_limited/u);
        assert.equal(message.includes(flaggedInput), false);
        assert.equal(message.includes("flagged_input"), false);
        return true;
      },
    );
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test("OpenRouter normalizes safe error tokens and drops secret-shaped metadata", async () => {
  const previousFetch = globalThis.fetch;
  const secretShapedProviderCode = "sk-or-v1-abcdefghijklmnop";
  try {
    const provider = createOpenAiCompatibleProvider({
      id: "openrouter",
      baseUrl: "https://openrouter.example/api/v1",
      models: ["requested/model"],
      local: true,
    });
    globalThis.fetch = (async () =>
      new Response(
        JSON.stringify({
          error: {
            code: 403,
            message: "Request refused.",
            metadata: {
              error_type: "REFUSAL",
              provider_code: secretShapedProviderCode,
            },
          },
        }),
        { status: 403 },
      )) as typeof fetch;

    await assert.rejects(
      () =>
        provider.complete({
          messages: [{ role: "user", content: "inspect" }],
        }),
      (error: unknown) => {
        assert.ok(error instanceof ModelProviderRequestError);
        assert.equal(error.status, 403);
        assert.equal(error.errorType, "refusal");
        assert.equal(error.providerCode, undefined);
        assert.equal(error.message.includes(secretShapedProviderCode), false);
        return true;
      },
    );
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test("OpenRouter structured errors without a message never echo raw metadata", async () => {
  const previousFetch = globalThis.fetch;
  const flaggedInput = "sensitive-missing-message-input-that-must-not-leak";
  try {
    const provider = createOpenAiCompatibleProvider({
      id: "openrouter",
      baseUrl: "https://openrouter.example/api/v1",
      models: ["requested/model"],
      local: true,
    });
    globalThis.fetch = (async () =>
      new Response(
        JSON.stringify({
          error: {
            code: 400,
            metadata: {
              error_type: "content_policy_violation",
              flagged_input: flaggedInput,
            },
          },
        }),
        { status: 400 },
      )) as typeof fetch;

    await assert.rejects(
      () =>
        provider.complete({
          messages: [{ role: "user", content: "inspect" }],
        }),
      (error: unknown) => {
        const message =
          error instanceof Error ? error.message : String(error);
        assert.match(message, /error_type=content_policy_violation/u);
        assert.match(message, /Provider returned an error/u);
        assert.equal(message.includes(flaggedInput), false);
        assert.equal(message.includes("flagged_input"), false);
        return true;
      },
    );
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test("OpenRouter surfaces typed errors embedded in a successful HTTP response", async () => {
  const previousFetch = globalThis.fetch;
  try {
    const provider = createOpenAiCompatibleProvider({
      id: "openrouter",
      baseUrl: "https://openrouter.example/api/v1",
      models: ["requested/model"],
      local: true,
    });
    globalThis.fetch = (async () =>
      new Response(
        JSON.stringify({
          model: "requested/model",
          choices: [
            {
              finish_reason: "error",
              message: { content: null },
              error: {
                code: 503,
                message: "The selected provider is overloaded.",
                metadata: {
                  error_type: "provider_overloaded",
                },
              },
            },
          ],
        }),
        { status: 200 },
      )) as typeof fetch;

    await assert.rejects(
      () =>
        provider.complete({
          messages: [{ role: "user", content: "inspect" }],
        }),
      (error: unknown) => {
        assert.ok(error instanceof ModelProviderRequestError);
        assert.equal(error.status, 503);
        assert.equal(error.errorType, "provider_overloaded");
        assert.match(error.message, /error_type=provider_overloaded/u);
        return true;
      },
    );
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test("OpenRouter scored and exact requests fail closed on model substitution", async () => {
  const previousFetch = globalThis.fetch;
  try {
    const provider = createOpenAiCompatibleProvider({
      id: "openrouter",
      baseUrl: "https://openrouter.example/api/v1",
      models: ["requested/model"],
      local: true,
    });
    globalThis.fetch = (async (_input, init) => {
      const body = JSON.parse(String(init?.body)) as {
        provider?: {
          require_parameters?: boolean;
          allow_fallbacks?: boolean;
          data_collection?: string;
        };
      };
      assert.deepEqual(body.provider, {
        require_parameters: true,
        allow_fallbacks: true,
        data_collection: "deny",
      });
      return new Response(JSON.stringify({
        model: "substituted/model",
        choices: [{ message: { content: "not acceptable" } }],
      }), { status: 200 });
    }) as typeof fetch;

    await assert.rejects(
      () => provider.complete({
        messages: [{ role: "user", content: "score this" }],
        requireExactModel: true,
      }, {
        openRouter: { allowFallbacks: true },
      }),
      /did not honor the exact requested model/i,
    );
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test("OpenRouter exact requests accept only a dated deployment of the requested model", async () => {
  const previousFetch = globalThis.fetch;
  try {
    const provider = createOpenAiCompatibleProvider({
      id: "openrouter",
      baseUrl: "https://openrouter.example/api/v1",
      models: ["deepseek/deepseek-v4-flash"],
      local: true,
    });
    globalThis.fetch = (async () => new Response(JSON.stringify({
      model: "deepseek/deepseek-v4-flash",
      provider: "Route Provider",
      choices: [{ message: { content: "accepted" } }],
      openrouter_metadata: {
        requested: "deepseek/deepseek-v4-flash",
        endpoints: {
          available: [{
            provider: "Route Provider",
            model: "deepseek/deepseek-v4-flash-20260423",
            selected: true,
          }],
        },
      },
    }), { status: 200 })) as typeof fetch;

    const response = await provider.complete({
      messages: [{ role: "user", content: "score this" }],
      requireExactModel: true,
    });

    assert.equal(response.model, "deepseek/deepseek-v4-flash");
    assert.equal(response.route?.selectedModel, "deepseek/deepseek-v4-flash-20260423");
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test("OpenRouter exact requests reject unrelated or malformed deployment routes", async () => {
  const previousFetch = globalThis.fetch;
  try {
    const provider = createOpenAiCompatibleProvider({
      id: "openrouter",
      baseUrl: "https://openrouter.example/api/v1",
      models: ["deepseek/deepseek-v4-flash"],
      local: true,
    });
    for (const selectedModel of [
      "deepseek/deepseek-v4-pro",
      "deepseek/deepseek-v4-flash-latest",
      "deepseek/deepseek-v4-flash-20260423-extra",
    ]) {
      globalThis.fetch = (async () => new Response(JSON.stringify({
        model: "deepseek/deepseek-v4-flash",
        choices: [{ message: { content: "not acceptable" } }],
        openrouter_metadata: {
          requested: "deepseek/deepseek-v4-flash",
          endpoints: {
            available: [{ model: selectedModel, selected: true }],
          },
        },
      }), { status: 200 })) as typeof fetch;

      await assert.rejects(
        () => provider.complete({
          messages: [{ role: "user", content: "score this" }],
          requireExactModel: true,
        }),
        /did not honor the exact requested model/i,
      );
    }
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test("OpenRouter exact requests reject mismatched route request metadata", async () => {
  const previousFetch = globalThis.fetch;
  try {
    const provider = createOpenAiCompatibleProvider({
      id: "openrouter",
      baseUrl: "https://openrouter.example/api/v1",
      models: ["deepseek/deepseek-v4-flash"],
      local: true,
    });
    globalThis.fetch = (async () => new Response(JSON.stringify({
      model: "deepseek/deepseek-v4-flash",
      choices: [{ message: { content: "not acceptable" } }],
      openrouter_metadata: {
        requested: "deepseek/deepseek-v4-pro",
        endpoints: {
          available: [{
            model: "deepseek/deepseek-v4-flash-20260423",
            selected: true,
          }],
        },
      },
    }), { status: 200 })) as typeof fetch;

    await assert.rejects(
      () => provider.complete({
        messages: [{ role: "user", content: "score this" }],
        requireExactModel: true,
      }),
      /did not honor the exact requested model/i,
    );
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test("OpenRouter exact requests reject missing route verification metadata", async () => {
  const previousFetch = globalThis.fetch;
  try {
    const provider = createOpenAiCompatibleProvider({
      id: "openrouter",
      baseUrl: "https://openrouter.example/api/v1",
      models: ["deepseek/deepseek-v4-flash"],
      local: true,
    });
    const incompletePayloads = [
      {
        model: "deepseek/deepseek-v4-flash",
        choices: [{ message: { content: "missing metadata" } }],
      },
      {
        model: "deepseek/deepseek-v4-flash",
        choices: [{ message: { content: "missing requested model" } }],
        openrouter_metadata: {
          endpoints: {
            available: [{
              model: "deepseek/deepseek-v4-flash-20260423",
              selected: true,
            }],
          },
        },
      },
      {
        model: "deepseek/deepseek-v4-flash",
        choices: [{ message: { content: "missing selected model" } }],
        openrouter_metadata: {
          requested: "deepseek/deepseek-v4-flash",
          endpoints: { available: [] },
        },
      },
    ];

    for (const payload of incompletePayloads) {
      globalThis.fetch = (async () => new Response(JSON.stringify(payload), {
        status: 200,
      })) as typeof fetch;

      await assert.rejects(
        () => provider.complete({
          messages: [{ role: "user", content: "score this" }],
          requireExactModel: true,
        }),
        /did not honor the exact requested model/i,
      );
    }
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test("provider transport failures redact URL and environment credentials", async () => {
  const previousFetch = globalThis.fetch;
  const urlSecret = "redis-password-that-must-not-leak";
  const envSecret = "ordinary-provider-secret-that-must-not-leak";
  try {
    const provider = createOpenAiCompatibleProvider({
      id: "openai-compatible",
      baseUrl: "https://example.invalid/v1",
      models: ["test-model"],
      local: true,
    });
    globalThis.fetch = (async () => {
      throw new Error(
        `connect redis://:${urlSecret}@cache.test failed while OPENAI_API_KEY=${envSecret}`,
      );
    }) as typeof fetch;

    await assert.rejects(
      () => provider.complete({ messages: [{ role: "user", content: "hello" }] }),
      (error: unknown) => {
        assert.ok(error instanceof ModelProviderRequestError);
        assert.equal(error.errorType, "transport_error");
        const message = error instanceof Error ? error.message : String(error);
        assert.equal(message.includes(urlSecret), false);
        assert.equal(message.includes(envSecret), false);
        assert.match(message, /\[REDACTED\]/u);
        return true;
      },
    );
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test("provider invalid JSON failures retain a safe typed response classification", async () => {
  const previousFetch = globalThis.fetch;
  try {
    const provider = createOpenAiCompatibleProvider({
      id: "openrouter",
      baseUrl: "https://openrouter.example/api/v1",
      models: ["requested/model"],
      local: true,
    });
    globalThis.fetch = (async () =>
      new Response("{not-valid-json", { status: 200 })) as typeof fetch;

    await assert.rejects(
      () =>
        provider.complete({
          messages: [{ role: "user", content: "inspect" }],
        }),
      (error: unknown) => {
        assert.ok(error instanceof ModelProviderRequestError);
        assert.equal(error.provider, "openrouter");
        assert.equal(error.status, undefined);
        assert.equal(error.errorType, "invalid_response");
        assert.equal(error.providerCode, undefined);
        assert.match(error.message, /invalid json/iu);
        return true;
      },
    );
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test("non-OpenRouter compatible providers do not receive OpenRouter routing fields", async () => {
  const previousFetch = globalThis.fetch;
  try {
    const provider = createOpenAiCompatibleProvider({
      id: "openai-compatible",
      baseUrl: "https://example.invalid/v1",
      models: ["test-model"],
      local: true,
    });
    globalThis.fetch = (async (_input, init) => {
      const headers = init?.headers as Record<string, string>;
      assert.equal(headers["x-openrouter-metadata"], undefined);
      const body = JSON.parse(String(init?.body)) as { provider?: unknown };
      assert.equal(body.provider, undefined);
      return new Response(JSON.stringify({
        id: "chatcmpl-123",
        model: "test-model",
        choices: [{ message: { content: "ok" } }],
        usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2, cost: 99 },
      }), { status: 200 });
    }) as typeof fetch;

    const response = await provider.complete({
      messages: [{ role: "user", content: "hello" }],
    }, {
      openRouter: {
        scored: true,
        allowFallbacks: false,
      },
    });

    assert.equal(response.content, "ok");
    assert.equal(response.usage?.authoritativeUsd, undefined);
    assert.equal(response.route, undefined);
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test("OpenAI-compatible providers reject oversized response bodies before JSON parsing", async () => {
  const previousFetch = globalThis.fetch;
  try {
    const provider = createOpenAiCompatibleProvider({
      id: "openai-compatible",
      baseUrl: "https://example.invalid/v1",
      models: ["test-model"],
      local: true,
    });
    globalThis.fetch = (async () => new Response("x".repeat(2_000_001), {
      status: 200,
    })) as typeof fetch;

    await assert.rejects(
      () => provider.complete({ messages: [{ role: "user", content: "hello" }] }),
      /response exceeds the 2000000-byte limit/i,
    );
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test("Claude provider maps messages and parses text responses", async () => {
  const envName = "HERMSEC_TEST_ANTHROPIC_KEY";
  const secret = "sk-test-claude-secret-1234567890";
  const previousSecret = process.env[envName];
  const previousFetch = globalThis.fetch;
  process.env[envName] = secret;

  try {
    globalThis.fetch = (async (input, init) => {
      assert.equal(String(input), "https://example.invalid/v1/messages");
      assert.equal((init?.headers as Record<string, string>)["x-api-key"], secret);
      const body = JSON.parse(String(init?.body)) as { system: string; messages: Array<{ role: string }>; max_tokens: number };
      assert.match(body.system, /system guidance/);
      assert.equal(body.messages[0]?.role, "user");
      assert.equal(body.max_tokens, 64);
      return new Response(JSON.stringify({
        model: "claude-test",
        content: [{ type: "text", text: "Claude explanation" }],
        usage: { input_tokens: 12, output_tokens: 6 },
      }), { status: 200 });
    }) as typeof fetch;

    const response = await anthropicProvider.complete({
      messages: [
        { role: "system", content: "system guidance" },
        { role: "user", content: "hello" },
      ],
      maxTokens: 64,
    }, {
      apiKeyEnv: envName,
      baseUrl: "https://example.invalid",
      model: "claude-test",
    });

    assert.equal(response.provider, "claude");
    assert.equal(response.content, "Claude explanation");
    assert.equal(response.usage?.totalTokens, 18);
  } finally {
    globalThis.fetch = previousFetch;
    if (previousSecret === undefined) {
      delete process.env[envName];
    } else {
      process.env[envName] = previousSecret;
    }
  }
});

test("Claude provider bounds response bodies and generated content", async () => {
  const envName = "HERMSEC_TEST_ANTHROPIC_LIMIT_KEY";
  const previousSecret = process.env[envName];
  const previousFetch = globalThis.fetch;
  process.env[envName] = "anthropic-test-key";
  try {
    globalThis.fetch = (async () =>
      new Response("x".repeat(2_000_001), { status: 200 })) as typeof fetch;
    await assert.rejects(
      () => anthropicProvider.complete({
        messages: [{ role: "user", content: "hello" }],
      }, { apiKeyEnv: envName }),
      /response exceeds the 2000000-byte limit/i,
    );

    globalThis.fetch = (async () => new Response(JSON.stringify({
      model: "claude-test",
      content: [{ type: "text", text: "x".repeat(1_000_001) }],
    }), { status: 200 })) as typeof fetch;
    await assert.rejects(
      () => anthropicProvider.complete({
        messages: [{ role: "user", content: "hello" }],
      }, { apiKeyEnv: envName }),
      /message content exceeds the 1000000-byte limit/i,
    );
  } finally {
    globalThis.fetch = previousFetch;
    if (previousSecret === undefined) {
      delete process.env[envName];
    } else {
      process.env[envName] = previousSecret;
    }
  }
});

test("non-integrated adapters reject normalized tool requests explicitly", async () => {
  const request = {
    messages: [{ role: "user" as const, content: "inspect" }],
    tools: [{
      type: "function" as const,
      function: {
        name: "inspect_project",
        description: "Inspect",
        parameters: { type: "object" },
      },
    }],
  };

  await assert.rejects(
    () => anthropicProvider.complete(request),
    /does not support .* tool protocol/i,
  );
  await assert.rejects(
    () => geminiProvider.complete(request),
    /does not support .* tool protocol/i,
  );
});

test("Gemini provider maps messages and parses candidate responses", async () => {
  const envName = "HERMSEC_TEST_GEMINI_KEY";
  const secret = "AIza-test-gemini-secret-1234567890";
  const previousSecret = process.env[envName];
  const previousFetch = globalThis.fetch;
  process.env[envName] = secret;

  try {
    globalThis.fetch = (async (input, init) => {
      const url = new URL(String(input));
      assert.equal(url.origin + url.pathname, "https://example.invalid/models/gemini-test:generateContent");
      assert.equal(url.search, "");
      assert.equal((init?.headers as Record<string, string>)["x-goog-api-key"], secret);
      const body = JSON.parse(String(init?.body)) as { systemInstruction?: unknown; contents: Array<{ role: string }> };
      assert.ok(body.systemInstruction);
      assert.equal(body.contents[0]?.role, "user");
      return new Response(JSON.stringify({
        candidates: [{ content: { parts: [{ text: "Gemini explanation" }] } }],
        usageMetadata: { promptTokenCount: 8, candidatesTokenCount: 5, totalTokenCount: 13 },
      }), { status: 200 });
    }) as typeof fetch;

    const response = await geminiProvider.complete({
      messages: [
        { role: "system", content: "system guidance" },
        { role: "user", content: "hello" },
      ],
      maxTokens: 64,
    }, {
      apiKeyEnv: envName,
      baseUrl: "https://example.invalid",
      model: "gemini-test",
    });

    assert.equal(response.provider, "gemini");
    assert.equal(response.content, "Gemini explanation");
    assert.equal(response.usage?.totalTokens, 13);
  } finally {
    globalThis.fetch = previousFetch;
    if (previousSecret === undefined) {
      delete process.env[envName];
    } else {
      process.env[envName] = previousSecret;
    }
  }
});

test("Gemini provider bounds responses and redacts transport credentials", async () => {
  const envName = "HERMSEC_TEST_GEMINI_LIMIT_KEY";
  const geminiSecret = ["AI", "za1234567890abcdefghijklmnopqrstuv"].join("");
  const rawEnvSecret = "ordinary-gemini-secret-that-must-not-leak";
  const previousSecret = process.env[envName];
  const previousFetch = globalThis.fetch;
  process.env[envName] = geminiSecret;
  try {
    globalThis.fetch = (async () =>
      new Response("x".repeat(2_000_001), { status: 200 })) as typeof fetch;
    await assert.rejects(
      () => geminiProvider.complete({
        messages: [{ role: "user", content: "hello" }],
      }, { apiKeyEnv: envName }),
      /response exceeds the 2000000-byte limit/i,
    );

    globalThis.fetch = (async () => new Response(JSON.stringify({
      candidates: [{
        content: { parts: [{ text: "x".repeat(1_000_001) }] },
      }],
    }), { status: 200 })) as typeof fetch;
    await assert.rejects(
      () => geminiProvider.complete({
        messages: [{ role: "user", content: "hello" }],
      }, { apiKeyEnv: envName }),
      /message content exceeds the 1000000-byte limit/i,
    );

    globalThis.fetch = (async () => {
      throw new Error(
        `fetch https://example.test/generate?key=${geminiSecret} failed GEMINI_API_KEY=${rawEnvSecret}`,
      );
    }) as typeof fetch;
    await assert.rejects(
      () => geminiProvider.complete({
        messages: [{ role: "user", content: "hello" }],
      }, { apiKeyEnv: envName }),
      (error: unknown) => {
        const message = error instanceof Error ? error.message : String(error);
        assert.equal(message.includes(geminiSecret), false);
        assert.equal(message.includes(rawEnvSecret), false);
        assert.match(message, /\[REDACTED\]/u);
        return true;
      },
    );
  } finally {
    globalThis.fetch = previousFetch;
    if (previousSecret === undefined) {
      delete process.env[envName];
    } else {
      process.env[envName] = previousSecret;
    }
  }
});
