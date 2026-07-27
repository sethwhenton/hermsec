import assert from "node:assert/strict";
import test from "node:test";
import { redactForLog, redactForModel } from "../../src/agent/redaction.js";

test("model redaction covers structured keys and common provider credentials", () => {
  const openRouterKey = ["sk", "or", "v1", "1234567890abcdefghijklmnop"].join("-");
  const slackToken = ["xoxb", "1234567890", "abcdefghijklmnop"].join("-");
  const googleKey = ["AI", "za1234567890abcdefghijklmnopqrstuv"].join("");
  const input = {
    apiKey: openRouterKey,
    nested: {
      password: "correct-horse-battery-staple",
      source: [
        `const token = "${slackToken}";`,
        `GOOGLE_KEY=${googleKey}`,
        "DATABASE_URL=postgres://admin:super-secret@example.test/app",
      ].join("\n"),
    },
  };

  const result = redactForModel(input);
  const serialized = JSON.stringify(result.value);

  assert.equal(result.redacted, true);
  assert.equal(serialized.includes("correct-horse-battery-staple"), false);
  assert.equal(serialized.includes(slackToken), false);
  assert.equal(serialized.includes(googleKey), false);
  assert.equal(serialized.includes("admin:super-secret@"), false);
  assert.match(serialized, /\[REDACTED_FOR_MODEL\]/u);
});

test("log redaction preserves credential URL structure without preserving its password", () => {
  const result = redactForLog("postgres://service:do-not-log-this@example.test/database");

  assert.equal(String(result.value).includes("do-not-log-this"), false);
  assert.equal(result.value, "postgres://service:[REDACTED]@example.test/database");
});

test("log redaction covers empty-user credential URLs and query credentials", () => {
  const password = "redis-password-that-must-not-leak";
  const geminiKey = "gemini-key-that-must-not-leak";
  const result = redactForLog(
    `redis://:${password}@cache.test/0 https://example.test/run?key=${geminiKey}&mode=test`,
  );
  const value = String(result.value);

  assert.equal(value.includes(password), false);
  assert.equal(value.includes(geminiKey), false);
  assert.match(value, /redis:\/\/:\[REDACTED\]@cache\.test/u);
  assert.match(value, /\?key=\[REDACTED\]&mode=test/u);
});

test("log redaction removes embedded environment-style credentials", () => {
  const secret = "transport-secret-that-must-not-leak";
  const result = redactForLog(`fetch failed while GEMINI_API_KEY=${secret} was configured`);

  assert.equal(String(result.value).includes(secret), false);
  assert.match(String(result.value), /GEMINI_API_KEY=\[REDACTED\]/u);
});

test("model redaction removes exported unquoted environment secrets", () => {
  const secret = "ordinary-password-value-that-must-not-leak";
  const result = redactForModel(`  export DATABASE_PASSWORD=${secret}`);

  assert.equal(String(result.value).includes(secret), false);
  assert.equal(result.value, "  export DATABASE_PASSWORD=[REDACTED_FOR_MODEL]");
});

test("redaction catches pass and pwd key abbreviations without matching benign words", () => {
  const dbPass = "db-pass-value-that-must-not-leak";
  const mysqlPwd = "mysql-pwd-value-that-must-not-leak";
  const structured = redactForModel({
    dbPass,
    MYSQL_PWD: mysqlPwd,
    bypass: "enabled",
    compass: "north",
    passwordPolicy: "strict",
  });
  const structuredValue = structured.value as Record<string, unknown>;

  assert.equal(structuredValue.dbPass, "[REDACTED_FOR_MODEL]");
  assert.equal(structuredValue.MYSQL_PWD, "[REDACTED_FOR_MODEL]");
  assert.equal(structuredValue.bypass, "enabled");
  assert.equal(structuredValue.compass, "north");
  assert.equal(structuredValue.passwordPolicy, "strict");

  const assignment = redactForLog([
    `dbPass = "${dbPass}"`,
    `MYSQL_PWD=${mysqlPwd}`,
    'bypass = "enabled"',
    'compass = "north"',
    'passwordPolicy = "strict"',
  ].join("\n"));
  const value = String(assignment.value);

  assert.equal(value.includes(dbPass), false);
  assert.equal(value.includes(mysqlPwd), false);
  assert.match(value, /dbPass = "\[REDACTED\]"/u);
  assert.match(value, /MYSQL_PWD=\[REDACTED\]/u);
  assert.match(value, /bypass = "enabled"/u);
  assert.match(value, /compass = "north"/u);
  assert.match(value, /passwordPolicy = "strict"/u);
});

test("redaction covers short non-empty quoted pass and pwd assignments", () => {
  const result = redactForLog([
    'dbPass="x"',
    'MYSQL_PWD="abc"',
    'bypass="x"',
    'compass="abc"',
    'passwordPolicy="abc"',
  ].join("\n"));
  const value = String(result.value);

  assert.match(value, /dbPass="\[REDACTED\]"/u);
  assert.match(value, /MYSQL_PWD="\[REDACTED\]"/u);
  assert.match(value, /bypass="x"/u);
  assert.match(value, /compass="abc"/u);
  assert.match(value, /passwordPolicy="abc"/u);
});

test("model redaction covers typed declarations and destructured defaults", () => {
  const password = "plain-short-secret";
  const apiKey = "another-short-secret";
  const result = redactForModel([
    `const password: string = "${password}";`,
    `export let apiKey?: string = "${apiKey}";`,
    `const { token = "destructured-secret" } = config;`,
    'const passwordPolicy: string = "strict";',
  ].join("\n"));
  const value = String(result.value);

  assert.equal(value.includes(password), false);
  assert.equal(value.includes(apiKey), false);
  assert.equal(value.includes("destructured-secret"), false);
  assert.match(
    value,
    /const password: string = "\[REDACTED_FOR_MODEL\]"/u,
  );
  assert.match(
    value,
    /apiKey\?: string = "\[REDACTED_FOR_MODEL\]"/u,
  );
  assert.match(
    value,
    /token = "\[REDACTED_FOR_MODEL\]"/u,
  );
  assert.match(value, /passwordPolicy: string = "strict"/u);
});

test("model redaction covers typed class fields and function parameters", () => {
  const classSecret = "class-field-secret";
  const definiteClassSecret = "definite-class-field-secret";
  const parameterSecret = "parameter-secret";
  const result = redactForModel([
    "class Credentials {",
    `  private readonly password: string = "${classSecret}";`,
    `  private apiKey!: string = "${definiteClassSecret}";`,
    "}",
    `function connect(apiKey: string = "${parameterSecret}") {}`,
  ].join("\n"));
  const value = String(result.value);

  assert.equal(value.includes(classSecret), false);
  assert.equal(value.includes(definiteClassSecret), false);
  assert.equal(value.includes(parameterSecret), false);
  assert.match(
    value,
    /private readonly password: string = "\[REDACTED_FOR_MODEL\]"/u,
  );
  assert.match(
    value,
    /private apiKey!: string = "\[REDACTED_FOR_MODEL\]"/u,
  );
  assert.match(
    value,
    /apiKey: string = "\[REDACTED_FOR_MODEL\]"/u,
  );
});

test("model redaction covers JSON-escaped typed source snippets", () => {
  const secret = "typed-json-secret";
  const input = JSON.stringify({
    text: [
      `12: const apiKey: string = "${secret}";`,
      '13: private password: string = "class-json-secret";',
      '14: function connect(token: string = "parameter-json-secret") {}',
      '15: private apiKey!: string = "definite-json-secret";',
    ].join("\n"),
  });
  const result = redactForModel(input);
  const value = String(result.value);

  assert.equal(value.includes(secret), false);
  assert.equal(value.includes("class-json-secret"), false);
  assert.equal(value.includes("parameter-json-secret"), false);
  assert.equal(value.includes("definite-json-secret"), false);
  assert.match(value, /\[REDACTED_FOR_MODEL\]/u);
});

test("redaction placeholders remain inert across model, report, and log boundaries", () => {
  for (const placeholder of [
    "[REDACTED_FOR_MODEL]",
    "[REDACTED_SECRET]",
    "[REDACTED]",
  ]) {
    const source = [
      `const apiKey = "${placeholder}";`,
      `export SERVICE_TOKEN=${placeholder}`,
    ].join("\n");
    const text = redactForLog(source);
    const structured = redactForModel({
      apiKey: placeholder,
      token: placeholder,
    });

    assert.equal(text.value, source);
    assert.equal(text.redacted, false);
    assert.deepEqual(text.markers, []);
    const structuredValue = structured.value as Record<string, unknown>;
    assert.equal(structuredValue.apiKey, placeholder);
    assert.equal(structuredValue.token, placeholder);
    assert.equal(structured.redacted, false);
    assert.deepEqual(structured.markers, []);
  }
});

test("only exact redaction placeholders are inert", () => {
  const marker = "[REDACTED_FOR_MODEL]";
  const inputs = [
    `API_KEY=sk-${marker}-real-secret`,
    `API_KEY="${marker}-suffix"`,
    `API_KEY="prefix-${marker}"`,
    `API_KEY=\\"${marker}}}\\"`,
  ];
  for (const input of inputs) {
    const result = redactForLog(input);
    assert.equal(result.redacted, true, input);
    assert.ok(result.markers.length > 0, input);
    assert.notEqual(result.value, input, input);
  }

  const structured = redactForModel({
    apiKey: `prefix-${marker}-suffix`,
  });
  assert.equal(structured.redacted, true);
  assert.equal(
    (structured.value as Record<string, unknown>).apiKey,
    "[REDACTED_FOR_MODEL]",
  );
});

test("JSON-escaped exact placeholders remain inert but decorated values are redacted", () => {
  const exact =
    '{"preview":"FAKE_FIXTURE_TOKEN = \\"[REDACTED_FOR_MODEL]\\""}';
  const decorated =
    '{"preview":"FAKE_FIXTURE_TOKEN = \\"sk-[REDACTED_FOR_MODEL]-real-secret\\""}';

  const safe = redactForLog(exact);
  const unsafe = redactForLog(decorated);

  assert.equal(safe.value, exact);
  assert.equal(safe.redacted, false);
  assert.deepEqual(safe.markers, []);
  assert.equal(unsafe.redacted, true);
  assert.match(String(unsafe.value), /\[REDACTED\]/u);
  assert.doesNotMatch(String(unsafe.value), /real-secret/u);
});

test("JSON-escaped multiline assignment placeholders remain idempotent", () => {
  const exact = JSON.stringify({
    text: [
      "1: export const SERVICE_API_KEY =",
      "[REDACTED_FOR_MODEL]   process.env.SERVICE_API_KEY;",
      "3: ",
    ].join("\n"),
  });
  const decorated = JSON.stringify({
    text: [
      "1: export const SERVICE_API_KEY =",
      "sk-[REDACTED_FOR_MODEL]-real-secret",
      "3: ",
    ].join("\n"),
  });

  const safe = redactForLog(exact);
  const unsafe = redactForLog(decorated);

  assert.equal(safe.value, exact);
  assert.equal(safe.redacted, false);
  assert.deepEqual(safe.markers, []);
  assert.equal(unsafe.redacted, true);
  assert.doesNotMatch(String(unsafe.value), /real-secret/u);
});

test("structured redaction uses a null prototype and safely preserves __proto__ as data", () => {
  const input = JSON.parse(
    '{"__proto__":{"polluted":"no"},"token":"ordinary-secret-value-that-must-not-leak"}',
  ) as Record<string, unknown>;
  const result = redactForModel(input);
  const output = result.value as Record<string, unknown>;

  assert.equal(Object.getPrototypeOf(output), null);
  assert.equal(Object.hasOwn(output, "__proto__"), true);
  assert.equal((Object.prototype as Record<string, unknown>).polluted, undefined);
  assert.equal(JSON.stringify(output).includes("ordinary-secret-value-that-must-not-leak"), false);
});
