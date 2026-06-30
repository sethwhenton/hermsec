import { motion } from "framer-motion";
import {
  Archive,
  Clock,
  Folder,
  MessageSquarePlus,
  MoreHorizontal,
  PanelLeftClose,
  PanelLeftOpen,
  Plus,
  Settings,
  Trash2,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState, type MouseEvent } from "react";
import { cn } from "@/lib/cn";
import { getHermsecApi } from "@/lib/ipc";
import { useSessionStore } from "@/store/sessionStore";
import { useSettingsStore } from "@/store/settingsStore";
import { useUiStore } from "@/store/uiStore";
import { ProjectPickerModal } from "@/components/projects/ProjectPickerModal";
import { Button } from "@/components/ui/Button";
import type { ProjectDirectory } from "@/types/projects";
import type { ChatSessionSummary } from "@/types/sessions";

export function LeftSidebar() {
  const {
    view,
    setView,
    sidebarCollapsed,
    toggleSidebar,
  } = useUiStore();
  const currentSessionId = useUiStore((s) => s.currentSessionId);
  const settings = useSettingsStore((s) => s.settings);
  const updateSettings = useSettingsStore((s) => s.update);
  const sessions = useSessionStore((s) => s.sessions);
  const refreshSessions = useSessionStore((s) => s.refreshSessions);
  const startNewSession = useSessionStore((s) => s.startNewSession);
  const openSession = useSessionStore((s) => s.openSession);
  const archiveSession = useSessionStore((s) => s.archiveSession);
  const deleteSession = useSessionStore((s) => s.deleteSession);
  const [projects, setProjects] = useState<ProjectDirectory[]>([]);
  const [projectsLoading, setProjectsLoading] = useState(true);
  const [projectsError, setProjectsError] = useState<string | null>(null);
  const [newChatPickerOpen, setNewChatPickerOpen] = useState(false);
  const [openActions, setOpenActions] = useState<{ type: "project" | "session"; id: string } | null>(null);
  const sessionsByProject = useMemo(() => groupSessionsByProject(sessions), [sessions]);

  const loadProjects = useCallback(async () => {
    const api = getHermsecApi();
    if (!api) {
      setProjectsLoading(false);
      setProjectsError("Project folders are available in the desktop app.");
      return;
    }

    setProjectsLoading(true);
    try {
      const items = await api.projects.list();
      setProjects(items);
      setProjectsError(null);
    } catch (error) {
      setProjectsError(error instanceof Error ? error.message : "Could not load project folders.");
    } finally {
      setProjectsLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadProjects();
  }, [loadProjects, settings?.defaultProjectDir]);

  useEffect(() => {
    const close = () => setOpenActions(null);
    window.addEventListener("click", close);
    return () => {
      window.removeEventListener("click", close);
    };
  }, []);

  useEffect(() => {
    void refreshSessions();
  }, [refreshSessions]);

  const handleSelectProject = async (project: ProjectDirectory) => {
    await updateSettings({ defaultProjectDir: project.path });
    const latestSession = sessionsByProject.get(normalizePath(project.path))?.[0];
    if (latestSession) {
      await openSession(latestSession.id);
    } else {
      startNewSession();
    }
    setView("chat");
  };

  const handleNewChatProject = async (projectPath: string) => {
    await updateSettings({ defaultProjectDir: projectPath });
    startNewSession();
    await loadProjects();
    setView("chat");
  };

  const handleNewChatForProject = async (project: ProjectDirectory) => {
    setOpenActions(null);
    await handleNewChatProject(project.path);
  };

  const chooseAndAddProject = async () => {
    const api = getHermsecApi();
    if (!api) return;
    const directory = await api.settings.chooseProjectDirectory(settings?.defaultProjectDir);
    if (!directory) return;
    await handleNewChatProject(directory);
    await loadProjects();
  };

  const handleSelectSession = async (session: ChatSessionSummary) => {
    await updateSettings({ defaultProjectDir: session.projectPath });
    await openSession(session.id);
    setView("chat");
  };

  const handleArchiveSession = async (session: ChatSessionSummary) => {
    setOpenActions(null);
    await archiveSession(session.id);
  };

  const handleDeleteSession = async (session: ChatSessionSummary) => {
    setOpenActions(null);
    await deleteSession(session.id);
  };

  const handleArchiveProject = async (project: ProjectDirectory) => {
    setOpenActions(null);
    const api = getHermsecApi();
    if (!api) return;
    await api.projects.archive(project.path);
    if (settings?.defaultProjectDir.toLowerCase() === project.path.toLowerCase()) {
      await updateSettings({ defaultProjectDir: "" });
      startNewSession();
    }
    await loadProjects();
  };

  const handleDeleteProject = async (project: ProjectDirectory) => {
    setOpenActions(null);
    const api = getHermsecApi();
    if (!api) return;
    await api.projects.delete(project.path);
    if (settings?.defaultProjectDir.toLowerCase() === project.path.toLowerCase()) {
      await updateSettings({ defaultProjectDir: "" });
      startNewSession();
    }
    await loadProjects();
  };

  const openRowActions = (
    event: MouseEvent,
    type: "project" | "session",
    id: string,
  ) => {
    event.preventDefault();
    event.stopPropagation();
    setOpenActions((current) => (current?.type === type && current.id === id ? null : { type, id }));
  };

  return (
    <motion.aside
      className="flex h-full shrink-0 flex-col border-r border-border-subtle bg-surface"
      animate={{ width: sidebarCollapsed ? 52 : 240 }}
      transition={{ type: "spring", stiffness: 420, damping: 38 }}
    >
      <div className="flex items-center justify-between px-2 py-2">
        {!sidebarCollapsed && <div aria-hidden="true" />}
        <Button variant="ghost" size="icon" onClick={toggleSidebar}>
          {sidebarCollapsed ? <PanelLeftOpen className="h-4 w-4" /> : <PanelLeftClose className="h-4 w-4" />}
        </Button>
      </div>

      <div className="space-y-0.5 px-2">
        <SidebarButton
          collapsed={sidebarCollapsed}
          icon={<MessageSquarePlus className="h-4 w-4" />}
          label="New chat"
          active={view === "chat"}
          onClick={() => setNewChatPickerOpen(true)}
        />
        <SidebarButton
          collapsed={sidebarCollapsed}
          icon={<Clock className="h-4 w-4" />}
          label="Automations"
          badge="1"
          active={view === "automations"}
          onClick={() => setView("automations")}
        />
      </div>

      {!sidebarCollapsed && (
        <div className="mt-4 flex-1 overflow-y-auto px-2">
          <div className="mb-2 flex items-center justify-between px-1">
            <div className="text-[10px] uppercase tracking-wider text-muted">Projects</div>
            <button
              type="button"
              className="flex h-5 w-5 items-center justify-center rounded-md text-muted transition-colors duration-150 ease-out hover:bg-white/8 hover:text-foreground active:scale-[0.96]"
              title="Add project"
              onClick={() => void chooseAndAddProject()}
            >
              <Plus className="h-3.5 w-3.5" />
            </button>
          </div>
          <div className="space-y-0.5">
            {projectsLoading && (
              <div className="px-2 py-1.5 text-xs text-muted">Loading project folders...</div>
            )}
            {!projectsLoading && projectsError && (
              <div className="px-2 py-1.5 text-xs text-muted">{projectsError}</div>
            )}
            {!projectsLoading && !projectsError && projects.length === 0 && (
              <div className="px-2 py-1.5 text-xs text-muted">No project folders found.</div>
            )}
            {!projectsLoading &&
              !projectsError &&
              projects.map((project) => {
                const activeProject = settings?.defaultProjectDir.toLowerCase() === project.path.toLowerCase();
                const projectSessions = sessionsByProject.get(normalizePath(project.path)) ?? [];
                return (
                  <div key={project.id} className="pb-1">
                    <div
                      className="group/project relative"
                      onContextMenu={(event) => openRowActions(event, "project", project.id)}
                    >
                      <button
                        type="button"
                        title={project.path}
                        aria-pressed={activeProject}
                        onClick={() => {
                          void handleSelectProject(project);
                        }}
                        className={cn(
                          "flex w-full items-start gap-2 rounded-xl px-2 py-2 pr-14 text-left text-xs transition-colors duration-150 ease-out",
                          activeProject && !currentSessionId
                            ? "bg-white/8 text-foreground"
                            : "text-muted hover:bg-white/5 hover:text-foreground",
                        )}
                      >
                        <Folder className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                        <span className="min-w-0 flex-1">
                          <span className="block truncate">{project.name}</span>
                          <span className="block truncate text-[10px] text-muted-foreground">
                            {project.path}
                          </span>
                        </span>
                      </button>
                      <ProjectNewChatButton
                        label={`Start new chat for ${project.name}`}
                        onClick={(event) => {
                          event.preventDefault();
                          event.stopPropagation();
                          void handleNewChatForProject(project);
                        }}
                      />
                      <RowActionButton
                        label={`Project actions for ${project.name}`}
                        onClick={(event) => openRowActions(event, "project", project.id)}
                      />
                      {openActions?.type === "project" && openActions.id === project.id ? (
                        <ActionMenu
                          onArchive={() => void handleArchiveProject(project)}
                          onDelete={() => void handleDeleteProject(project)}
                        />
                      ) : null}
                    </div>
                    {projectSessions.map((session) => (
                      <div
                        key={session.id}
                        className="group/session relative mt-0.5"
                        onContextMenu={(event) => openRowActions(event, "session", session.id)}
                      >
                        <button
                          type="button"
                          title={session.title}
                          aria-pressed={currentSessionId === session.id}
                          onClick={() => {
                            void handleSelectSession(session);
                          }}
                          className={cn(
                            "flex w-full items-center gap-2 rounded-xl py-1.5 pr-8 pl-7 text-left text-xs transition-colors duration-150 ease-out",
                            currentSessionId === session.id
                              ? "bg-white/8 text-foreground"
                              : "text-muted hover:bg-white/5 hover:text-foreground",
                          )}
                        >
                          <span className="min-w-0 flex-1 truncate">{session.title}</span>
                          <span className="shrink-0 text-[10px] text-muted-foreground">
                            {formatRelativeTime(session.updatedAt)}
                          </span>
                        </button>
                        <RowActionButton
                          label={`Session actions for ${session.title}`}
                          onClick={(event) => openRowActions(event, "session", session.id)}
                        />
                        {openActions?.type === "session" && openActions.id === session.id ? (
                          <ActionMenu
                            onArchive={() => void handleArchiveSession(session)}
                            onDelete={() => void handleDeleteSession(session)}
                          />
                        ) : null}
                      </div>
                    ))}
                  </div>
                );
              })}
          </div>
        </div>
      )}

      <div className="mt-auto border-t border-border-subtle p-2">
        <SidebarButton
          collapsed={sidebarCollapsed}
          icon={<Settings className="h-4 w-4" />}
          label="Settings"
          active={view === "settings"}
          onClick={() => setView("settings")}
        />
      </div>
      <ProjectPickerModal
        open={newChatPickerOpen}
        currentProjectPath={settings?.defaultProjectDir}
        onClose={() => setNewChatPickerOpen(false)}
        onSelect={handleNewChatProject}
      />
    </motion.aside>
  );
}

function groupSessionsByProject(sessions: ChatSessionSummary[]): Map<string, ChatSessionSummary[]> {
  const grouped = new Map<string, ChatSessionSummary[]>();
  for (const session of sessions) {
    const key = normalizePath(session.projectPath);
    grouped.set(key, [...(grouped.get(key) ?? []), session]);
  }
  for (const [key, value] of grouped) {
    grouped.set(key, value.sort((a, b) => b.updatedAt - a.updatedAt));
  }
  return grouped;
}

function normalizePath(filePath: string): string {
  return filePath.replace(/\\/g, "/").toLowerCase();
}

function formatRelativeTime(timestamp: number): string {
  const diffMs = Math.max(0, Date.now() - timestamp);
  const minute = 60_000;
  const hour = minute * 60;
  const day = hour * 24;
  const week = day * 7;

  if (diffMs < minute) return "now";
  if (diffMs < hour) return `${Math.floor(diffMs / minute)}m`;
  if (diffMs < day) return `${Math.floor(diffMs / hour)}h`;
  if (diffMs < week) return `${Math.floor(diffMs / day)}d`;
  return `${Math.floor(diffMs / week)}w`;
}

function RowActionButton({
  label,
  onClick,
}: {
  label: string;
  onClick: (event: MouseEvent<HTMLButtonElement>) => void;
}) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      onClick={onClick}
      className="absolute right-1.5 top-1/2 flex h-6 w-6 -translate-y-1/2 items-center justify-center rounded-md text-muted-foreground opacity-0 transition-[opacity,background-color,color] duration-150 ease-out hover:bg-white/8 hover:text-foreground group-hover/project:opacity-100 group-hover/session:opacity-100"
    >
      <MoreHorizontal className="h-3.5 w-3.5" />
    </button>
  );
}

function ProjectNewChatButton({
  label,
  onClick,
}: {
  label: string;
  onClick: (event: MouseEvent<HTMLButtonElement>) => void;
}) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      onClick={onClick}
      className="absolute right-8 top-1/2 flex h-6 w-6 -translate-y-1/2 items-center justify-center rounded-md text-muted-foreground opacity-0 transition-[opacity,background-color,color] duration-150 ease-out hover:bg-white/8 hover:text-foreground group-hover/project:opacity-100"
    >
      <Plus className="h-3.5 w-3.5" />
    </button>
  );
}

function ActionMenu({
  onArchive,
  onDelete,
}: {
  onArchive: () => void;
  onDelete: () => void;
}) {
  return (
    <div
      className="absolute right-1.5 top-8 z-40 w-36 overflow-hidden rounded-xl border border-border bg-surface-elevated/95 p-1 text-xs shadow-[0_18px_60px_rgba(0,0,0,0.42)] backdrop-blur"
      onClick={(event) => event.stopPropagation()}
    >
      <button
        type="button"
        className="flex w-full items-center gap-2 rounded-lg px-2 py-1.5 text-left text-muted transition-colors hover:bg-white/6 hover:text-foreground"
        onClick={onArchive}
      >
        <Archive className="h-3.5 w-3.5" />
        Archive
      </button>
      <button
        type="button"
        className="flex w-full items-center gap-2 rounded-lg px-2 py-1.5 text-left text-danger transition-colors hover:bg-danger/10"
        onClick={onDelete}
      >
        <Trash2 className="h-3.5 w-3.5" />
        Delete
      </button>
    </div>
  );
}

function SidebarButton({
  collapsed,
  icon,
  label,
  active,
  badge,
  onClick,
}: {
  collapsed: boolean;
  icon: React.ReactNode;
  label: string;
  active?: boolean;
  badge?: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      title={collapsed ? label : undefined}
      className={cn(
        "flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-xs transition-colors",
        active ? "bg-white/8 text-foreground" : "text-muted hover:bg-white/5 hover:text-foreground",
      )}
    >
      {icon}
      {!collapsed && (
        <>
          <span className="flex-1 text-left">{label}</span>
          {badge && (
            <span className="rounded bg-white/10 px-1.5 py-0.5 text-[10px] text-muted">{badge}</span>
          )}
        </>
      )}
    </button>
  );
}
