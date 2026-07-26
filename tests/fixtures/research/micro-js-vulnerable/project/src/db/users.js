export async function findUser(database, email) {
  const sql = "SELECT id, email FROM users WHERE email = '" + email + "'";
  return database.query(sql);
}
