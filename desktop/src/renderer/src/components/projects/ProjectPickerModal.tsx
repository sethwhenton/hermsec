import { Check, Folder, FolderPlus } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { getHermsecApi, requireHermsecApi } from "@/lib/ipc";
import { cn } from "@/lib/cn";
import { Button } from "@/components/ui/Button";
import { Modal } from "@/components/ui/Modal";
import type { ProjectDirectory } from "@/types/projects";

interface ProjectPickerModalProps {
  open: boolean;
  currentProjectPath?: string;
  onClose: () => void;
  onSelect: (projectPath: string) => void | Promise<void>;
}

export function ProjectPickerModal({
  open,
  currentProjectPath,
  onClose,
  onSelect,
}: ProjectPickerModalProps) {
  const [projects, setProjects] = useState<ProjectDirectory[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    const api = getHermsecApi();
    if (!api) return;

    setLoading(true);
    api.projects
      .list()
      .then((items) => {
        setProjects(items);
        setError(null);
      })
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : "Could not load projects.");
      })
      .finally(() => setLoading(false));
  }, [open]);

  const visibleProjects = useMemo(() => {
    const byPath = new Map<string, ProjectDirectory>();
    for (const project of projects) {
      byPath.set(normalizePath(project.path), project);
    }
    if (currentProjectPath && !byPath.has(normalizePath(currentProjectPath))) {
      byPath.set(normalizePath(currentProjectPath), {
        id: currentProjectPath,
        name: folderName(currentProjectPath),
        path: currentProjectPath,
        root: currentProjectPath,
      });
    }
    return Array.from(byPath.values()).sort((a, b) => a.name.localeCompare(b.name));
  }, [currentProjectPath, projects]);

  const selectProject = async (projectPath: string) => {
    await onSelect(projectPath);
    onClose();
  };

  const chooseNewProject = async () => {
    const directory = await requireHermsecApi().settings.chooseProjectDirectory(currentProjectPath);
    if (!directory) return;
    await selectProject(directory);
  };

  return (
    <Modal open={open} onClose={onClose} title="Start from project">
      <div className="space-y-3">
        <div className="max-h-[min(340px,42vh)] overflow-y-auto rounded-xl border border-border bg-background p-1">
          {loading ? (
            <div className="px-3 py-6 text-center text-sm text-muted">Loading projects...</div>
          ) : error ? (
            <div className="px-3 py-6 text-center text-sm text-muted">{error}</div>
          ) : visibleProjects.length === 0 ? (
            <div className="px-3 py-6 text-center text-sm text-muted">
              No saved project folders yet.
            </div>
          ) : (
            visibleProjects.map((project) => {
              const active = normalizePath(project.path) === normalizePath(currentProjectPath ?? "");
              return (
                <button
                  key={project.path}
                  type="button"
                  className={cn(
                    "flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-left transition-colors",
                    active ? "bg-white/8 text-foreground" : "text-muted hover:bg-white/5 hover:text-foreground",
                  )}
                  onClick={() => void selectProject(project.path)}
                >
                  <Folder className="h-4 w-4 shrink-0" />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm font-medium">{project.name}</span>
                    <span className="block truncate text-[11px] text-muted-foreground">
                      {project.path}
                    </span>
                  </span>
                  {active ? <Check className="h-4 w-4 shrink-0 text-accent" /> : null}
                </button>
              );
            })
          )}
        </div>

        <Button className="w-full" variant="outline" onClick={() => void chooseNewProject()}>
          <FolderPlus className="h-4 w-4" />
          New project
        </Button>
      </div>
    </Modal>
  );
}

function normalizePath(filePath: string): string {
  return filePath.replace(/\\/g, "/").toLowerCase();
}

function folderName(filePath: string): string {
  const parts = filePath.split(/[\\/]/).filter(Boolean);
  return parts.at(-1) ?? "Project";
}
