// FILE: global.d.ts
// Purpose: Declare ambient modules used by the web app when upstream packages omit types.
// Layer: Web type declarations
// Exports: module declarations only

import type { DesktopBridge } from "@t3tools/contracts";

declare module "@fontsource-variable/jetbrains-mono";

declare global {
  interface Window {
    desktopBridge?: DesktopBridge;
  }
}

export {};
