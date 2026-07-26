import { execFile } from "node:child_process";

export function pingHost(host, callback) {
  return execFile("ping", ["-n", "1", host], callback);
}
