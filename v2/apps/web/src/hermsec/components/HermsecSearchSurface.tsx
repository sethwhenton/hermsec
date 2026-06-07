import { SearchIcon } from "~/lib/icons";
import { Input } from "~/components/ui/input";
import { MOCK_AUTOMATIONS, MOCK_PROJECTS } from "../mockData";
import { HermsecPageShell } from "./HermsecPageShell";

const SEARCH_RESULTS = [
  ...MOCK_PROJECTS.map((project) => ({
    id: project.id,
    kind: "Project" as const,
    title: project.name,
    subtitle: project.path,
  })),
  ...MOCK_AUTOMATIONS.map((automation) => ({
    id: automation.id,
    kind: "Automation" as const,
    title: automation.name,
    subtitle: automation.targetProject,
  })),
];

export function HermsecSearchSurface() {
  return (
    <HermsecPageShell className="flex flex-col gap-4" maxWidthClassName="max-w-[820px]">
      <div className="space-y-1">
        <h1 className="text-lg font-semibold text-foreground/90">Search</h1>
        <p className="text-[length:var(--app-font-size-ui,12px)] text-muted-foreground/70">
          Find projects, automations, reports, and prior investigations.
        </p>
      </div>

      <div className="relative">
        <SearchIcon className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground/50" />
        <Input
          placeholder="Search Hermsec workspace…"
          className="h-8 rounded-lg border-[color:var(--color-border)] bg-white/[0.02] pl-8 text-[length:var(--app-font-size-ui,12px)]"
        />
      </div>

      <div className="overflow-hidden rounded-lg border border-[color:var(--color-border)]">
        {SEARCH_RESULTS.map((result, index) => (
          <button
            key={result.id}
            type="button"
            className="flex w-full items-start gap-3 px-3 py-2.5 text-left hover:bg-white/[0.03]"
            style={
              index > 0
                ? { borderTop: "1px solid color-mix(in srgb, var(--foreground) 8%, transparent)" }
                : undefined
            }
          >
            <span className="mt-0.5 rounded border border-[color:var(--color-border)] px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-muted-foreground/60">
              {result.kind}
            </span>
            <span className="min-w-0 flex-1">
              <span className="block truncate text-[length:var(--app-font-size-ui,12px)] text-foreground/85">
                {result.title}
              </span>
              <span className="block truncate text-[11px] text-muted-foreground/55">
                {result.subtitle}
              </span>
            </span>
          </button>
        ))}
      </div>
    </HermsecPageShell>
  );
}
