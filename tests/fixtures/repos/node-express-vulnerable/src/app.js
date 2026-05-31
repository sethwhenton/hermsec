import childProcess from "node:child_process";

export function search(req, db) {
  const term = req.query.q;
  return db.query("SELECT * FROM users WHERE name = '" + term + "'");
}

export function runTool(req) {
  const tool = req.query.tool;
  return childProcess.exec("tool " + tool);
}

export function show(req, res) {
  res.send("<h1>" + req.query.name + "</h1>");
}
