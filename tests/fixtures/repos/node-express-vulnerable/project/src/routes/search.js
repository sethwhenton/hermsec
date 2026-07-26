import crypto from "node:crypto";
import { exec } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import express from "express";

export const fakeFixtureToken = "HERMSEC_FAKE_TEST_TOKEN_DO_NOT_USE_NODE_FIXTURE";

const router = express.Router();
const fixtureRoot = path.resolve("local-fixture-data");

router.get("/search", (req, res) => {
  const term = String(req.query.q ?? "");
  const query = `SELECT * FROM users WHERE display_name = '${term}'`;
  res.json({ query });
});

router.get("/tools/ping", (req, res) => {
  exec(`echo ${String(req.query.host ?? "localhost")}`, () => undefined);
  res.json({ queued: true });
});

router.get("/files", (req, res) => {
  const requested = String(req.query.name ?? "sample.txt");
  const filePath = path.join(fixtureRoot, requested);
  const body = fs.readFileSync(filePath, "utf8");
  res.type("text/plain").send(body);
});

router.get("/debug-token", (req, res) => {
  const name = String(req.query.name ?? "fixture-user");
  const digest = crypto.createHash("md5").update(fakeFixtureToken).digest("hex");
  res.send(`<h1>${name}</h1><p>${digest}</p>`);
});

export default router;
