import { motion } from "framer-motion";
import {
  Clock,
  Folder,
  MessageSquarePlus,
  PanelLeftClose,
  PanelLeftOpen,
  Search,
  Settings,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { cn } from "@/lib/cn";
import { getHermsecApi } from "@/lib/ipc";
import { useSessionStore } from "@/store/sessionStore";
import { useSettingsStore } from "@/store/settingsStore";
import { useUiStore } from "@/store/uiStore";
import { HermsecLogo } from "@/components/branding/HermsecLogo";
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
  const [projects, setProjects] = useState<ProjectDirectory[]>([]);
  const [projectsLoading, setProjectsLoading] = useState(true);
  const [projectsError, setProjectsError] = useState<string | null>(null);
  const sessionsByProject = useMemo(() => groupSessionsByProject(sessions), [sessions]);

  useEffect(() => {
    let active = true;
    const api = getHermsecApi();
    if (!api) {
      setProjectsLoading(false);
      setProjectsError("Project folders are available in the desktop app.");
      return;
    }

    api.projects
      .list()
      .then((items) => {
        if (!active) return;
        setProjects(items);
        setProjectsError(null);
      })
      .catch((error: unknown) => {
        if (!active) return;
        setProjectsError(error instanceof Error ? error.message : "Could not load project folders.");
      })
      .finally(() => {
        if (active) setProjectsLoading(false);
      });

    return () => {
      active = false;
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

  const handleSelectSession = async (session: ChatSessionSummary) => {
    await updateSettings({ defaultProjectDir: session.projectPath });
    await openSession(session.id);
    setView("chat");
  };

  return (
    <motion.aside
      className="flex h-full shrink-0 flex-col border-r border-border-subtle bg-surface"
      animate={{ width: sidebarCollapsed ? 52 : 240 }}
      transition={{ type: "spring", stiffness: 420, damping: 38 }}
    >
      <div className="flex items-center justify-between px-2 py-2">
        {!sidebarCollapsed && (
          <div className="flex min-w-0 items-center gap-2">
            <HermsecLogo className="h-6 w-6 text-accent" aria-label="Hermsec" />
            <span className="truncate text-xs font-semibold text-foreground">Hermsec</span>
          </div>
        )}
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
          onClick={() => {
            startNewSession();
            setView("chat");
          }}
        />
        <SidebarButton
          collapsed={sidebarCollapsed}
          icon={<Search className="h-4 w-4" />}
          label="Search"
          onClick={() => setView("chat")}
        />
        <SidebarButton
          collapsed={sidebarCollapsed}
          icon={<Clock className="h-4 w-4" />}
          label="Automations"
          badge="1"
          onClick={() => setView("chat")}
        />
      </div>

      {!sidebarCollapsed && (
        <div className="mt-4 flex-1 overflow-y-auto px-2">
          <div className="mb-2 px-1 text-[10px] uppercase tracking-wider text-muted">Projects</div>
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
                    <button
                      type="button"
                      title={project.path}
                      aria-pressed={activeProject}
                      onClick={() => {
                        void handleSelectProject(project);
                      }}
                      className={cn(
                        "flex w-full items-start gap-2 rounded-md px-2 py-1.5 text-left text-xs transition-colors",
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
                    {projectSessions.map((session) => (
                      <button
                        key={session.id}
                        type="button"
                        title={session.title}
                        aria-pressed={currentSessionId === session.id}
                        onClick={() => {
                          void handleSelectSession(session);
                        }}
                        className={cn(
                          "mt-0.5 flex w-full items-center gap-2 rounded-md py-1.5 pr-2 pl-7 text-left text-xs transition-colors",
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
