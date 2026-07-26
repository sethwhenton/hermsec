export function search(req, db) {
  const term = String(req.query.q ?? "");
  return db.query("SELECT * FROM users WHERE name = ?", [term]);
}

export function show(req, res, escapeHtml) {
  res.send(`<h1>${escapeHtml(String(req.query.name ?? ""))}</h1>`);
}
