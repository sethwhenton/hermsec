import { ArrowLeft, Bot, Cog, ScanSearch, Server, UsersRound } from "lucide-react";
import { cn } from "@/lib/cn";
import type { SettingsSection } from "@/store/uiStore";
import { HermsecLogo } from "@/components/branding/HermsecLogo";

interface SettingsSidebarProps {
  section: SettingsSection;
  onBack: () => void;
  onSectionChange: (section: SettingsSection) => void;
}

const desktopItems: Array<{ id: SettingsSection; label: string; icon: React.ReactNode }> = [
  { id: "general", label: "General", icon: <Cog className="h-4 w-4" /> },
  { id: "agents", label: "Agents", icon: <UsersRound className="h-4 w-4" /> },
];

const serverItems: Array<{ id: SettingsSection; label: string; icon: React.ReactNode }> = [
  { id: "providers", label: "Providers", icon: <Server className="h-4 w-4" /> },
  { id: "models", label: "Models", icon: <Bot className="h-4 w-4" /> },
  { id: "scanners", label: "Scanners", icon: <ScanSearch className="h-4 w-4" /> },
];

export function SettingsSidebar({ section, onBack, onSectionChange }: SettingsSidebarProps) {
  return (
    <aside className="flex w-64 shrink-0 flex-col border-r border-border-subtle bg-surface px-3 py-4">
      <button
        type="button"
        onClick={onBack}
        className="mb-4 flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-xs text-muted transition-colors duration-150 ease-out hover:bg-white/5 hover:text-foreground active:scale-[0.97]"
      >
        <ArrowLeft className="h-4 w-4" />
        Back to chat
      </button>

      <div className="mb-2 px-2 text-[10px] uppercase tracking-wider text-muted">Desktop</div>
      {desktopItems.map((item) => (
        <SettingsNavButton
          key={item.id}
          active={section === item.id}
          icon={item.icon}
          label={item.label}
          onClick={() => onSectionChange(item.id)}
        />
      ))}

      <div className="mt-4 mb-2 px-2 text-[10px] uppercase tracking-wider text-muted">Server</div>
      {serverItems.map((item) => (
        <SettingsNavButton
          key={item.id}
          active={section === item.id}
          icon={item.icon}
          label={item.label}
          onClick={() => onSectionChange(item.id)}
        />
      ))}

      <div className="mt-auto flex items-center gap-2 px-2 pt-4 text-[10px] text-muted-foreground">
        <HermsecLogo className="h-4 w-4 text-accent" aria-label="Hermsec Desktop" />
        <span>Hermsec Desktop v0.1.6</span>
      </div>
    </aside>
  );
}

function SettingsNavButton({
  active,
  icon,
  label,
  onClick,
}: {
  active: boolean;
  icon: React.ReactNode;
  label: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "mb-0.5 flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-xs transition-colors",
        active ? "bg-white/8 text-foreground" : "text-muted hover:bg-white/5 hover:text-foreground",
      )}
    >
      {icon}
      {label}
    </button>
  );
}
