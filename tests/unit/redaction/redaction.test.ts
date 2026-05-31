import assert from "node:assert/strict";
import test from "node:test";
import { redactSecrets } from "../../../src/shared/text.js";

test("redaction removes fake fixture secrets and token-like values", () => {
  const input = [
    "fake=HERMSEC_FAKE_TEST_TOKEN_DO_NOT_USE_UNIT_SECRET",
    "api_key=HERMSECFAKEAPIKEYVALUE1234567890",
    "openai=sk-HERMSEC_FAKE_TEST_TOKEN_DO_NOT_USE_1234567890",
  ].join("\n");

  const redacted = redactSecrets(input);

  assert.doesNotMatch(redacted, /HERMSEC_FAKE_TEST_TOKEN_DO_NOT_USE_UNIT_SECRET/);
  assert.doesNotMatch(redacted, /HERMSECFAKEAPIKEYVALUE1234567890/);
  assert.doesNotMatch(redacted, /sk-HERMSEC_FAKE_TEST_TOKEN_DO_NOT_USE_1234567890/);
  assert.match(redacted, /HERMSEC_FAKE_TEST_TOKEN_\[REDACTED]/);
  assert.match(redacted, /sk-\[REDACTED]/);
});
