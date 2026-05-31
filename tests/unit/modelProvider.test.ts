import assert from "node:assert/strict";
import test from "node:test";
import { anthropicProvider } from "../../src/model/anthropic.js";
import { credentialFingerprint } from "../../src/model/credentials.js";
import { geminiProvider } from "../../src/model/gemini.js";
import { createOpenAiCompatibleProvider } from "../../src/model/openaiCompatible.js";

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
      assert.equal(url.searchParams.get("key"), secret);
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
