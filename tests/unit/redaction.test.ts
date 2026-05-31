import assert from "node:assert/strict";
import test from "node:test";
import { redactSecrets } from "../../src/shared/text.js";

test("redacts OpenAI-style and Hermsec fake tokens", () => {
  const redacted = redactSecrets("api_key=sk-1234567890abcdefghijklmnopqrstuvwxyz HERMSEC_FAKE_TEST_TOKEN_DO_NOT_USE_123");
  assert.equal(redacted.includes("abcdefghijklmnopqrstuvwxyz"), false);
  assert.equal(redacted.includes("DO_NOT_USE_123"), false);
});
