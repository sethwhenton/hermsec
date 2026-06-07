import { FolderOpenIcon, PlusIcon } from "~/lib/icons";
import { Button } from "~/components/ui/button";
import { cn } from "~/lib/utils";
import type { HermsecProject } from "../types";
import { HermsecPageShell } from "./HermsecPageShell";

type HermsecProjectsPageProps = {
  projects: HermsecProject[];
  activeProjectId?: string;
  onSelectProject?: (projectId: string) => void;
};

function riskBadgeClass(risk: HermsecProject["riskLevel"]): string {
  switch (risk) {
    case "high":
      return "border-red-500/30 bg-red-500/10 text-red-300/90";
    case "medium":
      return "border-amber-500/30 bg-amber-500/10 text-amber-200/90";
    default:
      return "border-emerald-500/25 bg-emerald-500/8 text-emerald-200/85";
  }
}

export function HermsecProjectsPage({
  projects,
  activeProjectId,
  onSelectProject,
}: HermsecProjectsPageProps) {
  return (
    <HermsecPageShell className="flex flex-col gap-4" maxWidthClassName="max-w-[980px]">
      <div className="flex items-end justify-between gap-4">
        <div className="space-y-1">
          <h1 className="text-lg font-semibold text-foreground/90">Projects</h1>
          <p className="text-[length:var(--app-font-size-ui,12px)] text-muted-foreground/70">
            Open local folders for scanning, reporting, and agent context.
          </p>
        </div>
        <Button size="sm" variant="outline" className="h-7 gap-1.5 rounded-md text-[11px]">
          <PlusIcon className="size-3" />
          Add project
        </Button>
      </div>

      <div className="overflow-hidden rounded-lg border border-[color:var(--color-border)]">
        {projects.map((project, index) => {
          const isActive = project.id === activeProjectId;
          return (
            <button
              key={project.id}
              type="button"
              onClick={() => onSelectProject?.(project.id)}
              className={cn(
                "flex w-full items-center gap-3 px-3 py-2.5 text-left transition-colors hover:bg-white/[0.03]",
                isActive && "bg-white/[0.04]",
                index > 0 && "border-t border-[color:var(--color-border)]",
              )}
            >
              <FolderOpenIcon className="size-4 shrink-0 text-muted-foreground/55" />
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="truncate text-[length:var(--app-font-size-ui,12px)] font-medium text-foreground/88">
                    {project.name}
                  </span>
                  <span
                    className={cn(
                      "rounded border px-1.5 py-0.5 text-[10px] capitalize",
                      riskBadgeClass(project.riskLevel),
                    )}
                  >
                    {project.riskLevel}
                  </span>
                </div>
                <span className="block truncate text-[11px] text-muted-foreground/55">
                  {project.path}
                </span>
              </div>
              <div className="shrink-0 text-right text-[11px] text-muted-foreground/60">
                <div>{project.findingCount} findings</div>
                <div>{project.lastScan}</div>
              </div>
            </button>
          );
        })}
      </div>
    </HermsecPageShell>
  );
}
