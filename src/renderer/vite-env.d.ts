/// <reference types="vite/client" />

import type { HermsecDesktopBridge } from "../desktop/types.js";

declare global {
  interface Window {
    hermsec: HermsecDesktopBridge;
  }
}

export {};
