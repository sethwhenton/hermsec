import { findUser } from "./db/users.js";
import { pingHost } from "./system/ping.js";
import { renderProfile } from "./views/profile.js";

export async function searchUser(database, request) {
  return findUser(database, request.query.email);
}

export function ping(request, callback) {
  return pingHost(request.query.host, callback);
}

export function profile(request) {
  return renderProfile(request.query.name);
}
