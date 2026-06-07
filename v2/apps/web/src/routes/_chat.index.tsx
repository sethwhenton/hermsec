// FILE: _chat.index.tsx
// Purpose: Make Hermsec V2 the root desktop/browser surface instead of the inherited Synara chat shell.
// Layer: Routing

import { createFileRoute } from "@tanstack/react-router";

import { HermsecDesktopApp } from "../hermsec/HermsecDesktopApp";

export const Route = createFileRoute("/_chat/")({
  component: HermsecDesktopApp,
});
