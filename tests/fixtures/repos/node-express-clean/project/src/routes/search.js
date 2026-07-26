import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import express from "express";

const router = express.Router();
const fixtureRoot = path.resolve("local-fixture-data");

router.get("/search", (req, res) => {
  const term = String(req.query.q ?? "");
  const query = "SELECT * FROM users WHERE display_name = ?";
  res.json({ query, params: [term] });
});

router.get("/tools/ping", (req, res) => {
  const host = String(req.query.host ?? "localhost").replace(/[^a-z0-9.-]/gi, "");
  res.json({ command: "echo", args: [host] });
});

router.get("/files", (req, res) => {
  const requested = path.basename(String(req.query.name ?? "sample.txt"));
  const filePath = path.resolve(fixtureRoot, requested);
  if (!filePath.startsWith(`${fixtureRoot}${path.sep}`)) {
    res.status(400).send("invalid path");
    return;
  }
  const body = fs.existsSync(filePath) ? fs.readFileSync(filePath, "utf8") : "";
  res.type("text/plain").send(body);
});

router.get("/profile", (req, res) => {
  const name = escapeHtml(String(req.query.name ?? "fixture-user"));
  const digest = crypto.createHash("sha256").update(name).digest("hex");
  res.send(`<h1>${name}</h1><p>${digest}</p>`);
});

function escapeHtml(value) {
  return value.replace(/[&<>"']/g, (char) => {
    const escapes = { "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" };
    return escapes[char] ?? char;
  });
}

export default router;
