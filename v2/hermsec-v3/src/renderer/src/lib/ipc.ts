import type { HermsecApi } from "../../../preload/index.d";

export function getHermsecApi(): HermsecApi | null {
  return window.hermsec ?? null;
}

export function requireHermsecApi(): HermsecApi {
  const api = getHermsecApi();
  if (!api) {
    throw new Error("Hermsec API is unavailable. Preload bridge not loaded.");
  }
  return api;
}
