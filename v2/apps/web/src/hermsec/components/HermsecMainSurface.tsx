import type {
  HermsecAutomation,
  HermsecChatChoice,
  HermsecChatMessage,
  HermsecMainView,
  HermsecProject,
  HermsecReportPreview,
  HermsecSettingsState,
} from "../types";
import { HermsecAutomationsPage } from "./HermsecAutomationsPage";
import { HermsecChatSurface } from "./HermsecChatSurface";
import { HermsecProjectsPage } from "./HermsecProjectsPage";
import { HermsecSearchSurface } from "./HermsecSearchSurface";
import { HermsecSettingsPage } from "./HermsecSettingsPage";

type HermsecMainSurfaceProps = {
  activeView: HermsecMainView;
  messages: HermsecChatMessage[];
  automations: HermsecAutomation[];
  projects: HermsecProject[];
  settings: HermsecSettingsState;
  activeProjectId?: string;
  onToggleAutomation: (id: string, enabled: boolean) => void;
  onRunAutomation: (id: string) => void;
  onDeleteAutomation: (id: string) => void;
  onCreateAutomation: () => void;
  onEditAutomation: (id: string) => void;
  onSettingsChange: (patch: Partial<HermsecSettingsState>) => void;
  onSelectProject: (projectId: string) => void;
  onSendMessage: (message: string) => void;
  onChoice: (choice: HermsecChatChoice) => void;
  onQuickAction: (actionId: string) => void;
  onOpenReport: (report: HermsecReportPreview) => void;
};

export function HermsecMainSurface({
  activeView,
  messages,
  automations,
  projects,
  settings,
  activeProjectId,
  onToggleAutomation,
  onRunAutomation,
  onDeleteAutomation,
  onCreateAutomation,
  onEditAutomation,
  onSettingsChange,
  onSelectProject,
  onSendMessage,
  onChoice,
  onQuickAction,
  onOpenReport,
}: HermsecMainSurfaceProps) {
  const activeProject = projects.find((project) => project.id === activeProjectId);

  function renderView() {
    switch (activeView) {
      case "search":
        return <HermsecSearchSurface />;
      case "automation":
        return (
          <HermsecAutomationsPage
            automations={automations}
            onToggleEnabled={onToggleAutomation}
            onRunAutomation={onRunAutomation}
            onDeleteAutomation={onDeleteAutomation}
            onCreateAutomation={onCreateAutomation}
            onEditAutomation={onEditAutomation}
            onOpenReport={onOpenReport}
          />
        );
      case "projects":
        return (
          <HermsecProjectsPage
            projects={projects}
            activeProjectId={activeProjectId}
            onSelectProject={onSelectProject}
          />
        );
      case "settings":
        return <HermsecSettingsPage settings={settings} onChange={onSettingsChange} />;
      case "chat":
      default:
        return (
          <HermsecChatSurface
            messages={messages}
            projectName={activeProject?.name}
            onQuickAction={onQuickAction}
            onSendMessage={onSendMessage}
            onChoice={onChoice}
          />
        );
    }
  }

  return (
    <main className="relative flex h-full min-h-0 min-w-0 flex-1 flex-col overflow-hidden bg-background text-foreground">
      <div className="h-full min-h-0 min-w-0 flex-1">{renderView()}</div>
    </main>
  );
}
