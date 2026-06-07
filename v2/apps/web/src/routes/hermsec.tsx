import { createFileRoute } from "@tanstack/react-router";
import { HermsecDesktopApp } from "~/hermsec/HermsecDesktopApp";

function HermsecRouteView() {
  return <HermsecDesktopApp />;
}

export const Route = createFileRoute("/hermsec")({
  component: HermsecRouteView,
});
