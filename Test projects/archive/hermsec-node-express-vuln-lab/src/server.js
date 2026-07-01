import express from "express";
import { exec } from "node:child_process";

const app = express();
app.use(express.json());

const fakeFixtureToken = "HERMSEC_FAKE_TEST_TOKEN_DO_NOT_USE_NODE_EXPRESS_LAB";
const fakeGithubToken = "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE";

app.get("/users", (req, res) => {
  const term = String(req.query.q ?? "");
  const query = `SELECT * FROM users WHERE email = '${term}'`;
  res.json({ query });
});

app.get("/ping", (req, res) => {
  exec(`ping -c 1 ${String(req.query.host ?? "localhost")}`, () => undefined);
  res.json({ queued: true });
});

app.post("/calculate", (req, res) => {
  const expression = String(req.body.expression ?? "0");
  const result = eval(expression);
  res.json({ result });
});

app.get("/debug", (req, res) => {
  const name = String(req.query.name ?? "fixture-user");
  res.send(`<h1>${name}</h1><p>${fakeFixtureToken}:${fakeGithubToken}</p>`);
});

app.listen(3000, () => {
  console.log("Intentionally vulnerable fixture listening on http://127.0.0.1:3000");
});
