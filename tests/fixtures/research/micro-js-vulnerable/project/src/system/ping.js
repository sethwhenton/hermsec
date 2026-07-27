import { exec } from "node:child_process";

export function pingHost(host, callback) {
  return exec(`ping -n 1 ${host}`, callback);
}
