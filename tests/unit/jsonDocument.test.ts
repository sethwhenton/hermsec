import assert from "node:assert/strict";
import test from "node:test";
import { parseSingleJsonObject } from "../../src/agent/jsonDocument.js";

test("single JSON object parser accepts one raw or fenced document", () => {
  assert.deepEqual(
    parseSingleJsonObject('  {"findings":[]}  '),
    { findings: [] },
  );
  assert.deepEqual(
    parseSingleJsonObject(
      '```json\r\n{"findings":[],"abstained":true}\r\n```',
    ),
    { findings: [], abstained: true },
  );
});

test("single JSON object parser rejects prose, duplicate documents, arrays, and malformed fences", () => {
  const rejected = [
    'Here is the result: {"findings":[]}',
    '{"findings":[]}\n{"findings":[]}',
    '[{"findings":[]}]',
    '```json\n{"findings":[]}\n```\nextra',
    '```json {"findings":[]} ```',
    '```json\n{"findings":[]}\n',
    '{"findings":',
  ];
  for (const value of rejected) {
    assert.equal(parseSingleJsonObject(value), undefined, value);
  }
});
