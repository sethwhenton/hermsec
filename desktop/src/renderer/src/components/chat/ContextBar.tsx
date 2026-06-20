import { AtSign, Brain, Check, ChevronDown, Folder, Globe } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { cn } from "@/lib/cn";
import { useSessionStore } from "@/store/sessionStore";
import { useSettingsStore } from "@/store/settingsStore";
import { useUiStore } from "@/store/uiStore";
import { ProjectPickerModal } from "@/components/projects/ProjectPickerModal";
import type { ContextChip, ContextChipKind } from "@/types/chat";
import type { ModelConfig, ProviderConfig } from "@/types/settings";

const kindIcons: Record<ContextChipKind, React.ReactNode> = {
  project: <Folder className="h-3 w-3" />,
  file: <Folder className="h-3 w-3" />,
  folder: <Folder className="h-3 w-3" />,
  url: <Globe className="h-3 w-3" />,
  selection: <AtSign className="h-3 w-3" />,
};

interface ContextBarProps {
  className?: string;
}

export function ContextBar({ className }: ContextBarProps) {
  const chips = useUiStore((s) => s.contextChips);
  const removeContextChip = useUiStore((s) => s.removeContextChip);
  const settings = useSettingsStore((s) => s.settings);
  const updateSettings = useSettingsStore((s) => s.update);
  const startNewSession = useSessionStore((s) => s.startNewSession);
  const [modelMenuOpen, setModelMenuOpen] = useState(false);
  const [thinkingMenuOpen, setThinkingMenuOpen] = useState(false);
  const [projectPickerOpen, setProjectPickerOpen] = useState(false);
  const modelMenuRef = useRef<HTMLDivElement>(null);
  const thinkingMenuRef = useRef<HTMLDivElement>(null);
  const activeModelId = settings?.activeModelId ?? "deepseek-v4-flash";
  const activeProjectPath = settings?.defaultProjectDir;
  const activeProjectName = activeProjectPath ? folderName(activeProjectPath) : null;
  const modelOptions = useMemo(
    () => getModelOptions(settings?.providers ?? []),
    [settings?.providers],
  );
  const activeModel = modelOptions.find((model) => model.id === activeModelId);

  useEffect(() => {
    if (!modelMenuOpen && !thinkingMenuOpen) return;

    const handlePointerDown = (event: MouseEvent) => {
      if (!modelMenuRef.current?.contains(event.target as Node)) {
        setModelMenuOpen(false);
      }
      if (!thinkingMenuRef.current?.contains(event.target as Node)) {
        setThinkingMenuOpen(false);
      }
    };
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setModelMenuOpen(false);
        setThinkingMenuOpen(false);
      }
    };

    document.addEventListener("mousedown", handlePointerDown);
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("mousedown", handlePointerDown);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [modelMenuOpen, thinkingMenuOpen]);

  const handleSelectModel = (modelId: string) => {
    void updateSettings({ activeModelId: modelId });
    setModelMenuOpen(false);
  };

  const handleSelectThinking = (level: NonNullable<typeof settings>["general"]["thinkingLevel"]) => {
    void updateSettings({ general: { thinkingLevel: level } });
    setThinkingMenuOpen(false);
  };

  const handleSelectProject = async (projectPath: string) => {
    await updateSettings({ defaultProjectDir: projectPath });
    startNewSession();
  };

  return (
    <div className={cn("flex flex-wrap items-center gap-1.5", className)}>
      {activeProjectPath && activeProjectName && (
        <button
          type="button"
          title={activeProjectPath}
          onClick={() => setProjectPickerOpen(true)}
          className="inline-flex max-w-64 items-center gap-1 rounded-md border border-border bg-surface-elevated px-2 py-1 text-[11px] text-foreground transition-colors hover:border-accent/40 hover:bg-accent-muted"
        >
          {kindIcons.project}
          <span className="truncate">{activeProjectName}</span>
        </button>
      )}

      {chips.map((chip) => (
        <ContextChipPill key={chip.id} chip={chip} onRemove={() => removeContextChip(chip.id)} />
      ))}

      <div ref={modelMenuRef} className="relative">
        <button
          type="button"
          aria-haspopup="listbox"
          aria-expanded={modelMenuOpen}
          onClick={() => setModelMenuOpen((open) => !open)}
          className="inline-flex max-w-64 items-center gap-1 rounded-md border border-border bg-surface-elevated px-2 py-1 text-[11px] text-muted transition-colors hover:text-foreground"
        >
          <span className="h-1.5 w-1.5 rounded-full bg-accent" />
          <span className="truncate">{activeModel?.label ?? activeModelId}</span>
          <ChevronDown className="h-3 w-3 shrink-0" />
        </button>

        {modelMenuOpen && (
          <div
            role="listbox"
            aria-label="Select model"
            className="absolute bottom-full left-0 z-50 mb-2 w-72 overflow-hidden rounded-lg border border-border bg-surface-elevated shadow-[0_18px_55px_rgba(0,0,0,0.45)]"
          >
            <div className="border-b border-border-subtle px-3 py-2 text-xs font-medium text-foreground">
              Select model
            </div>
            <div className="max-h-64 overflow-y-auto py-1">
              {modelOptions.map((model) => (
                <button
                  key={`${model.providerId}:${model.id}`}
                  type="button"
                  role="option"
                  aria-selected={activeModelId === model.id}
                  onClick={() => handleSelectModel(model.id)}
                  className={cn(
                    "flex w-full items-center gap-2 px-3 py-2 text-left text-xs transition-colors",
                    activeModelId === model.id
                      ? "bg-white/8 text-foreground"
                      : "text-muted hover:bg-white/5 hover:text-foreground",
                  )}
                >
                  <span className="flex min-w-0 flex-1 flex-col">
                    <span className="truncate font-medium">{model.label}</span>
                    <span className="truncate text-[10px] text-muted-foreground">
                      {model.providerName}
                    </span>
                  </span>
                  {activeModelId === model.id && <Check className="h-3.5 w-3.5 shrink-0" />}
                </button>
              ))}
              {modelOptions.length === 0 && (
                <div className="px-3 py-4 text-xs text-muted">No enabled models configured.</div>
              )}
            </div>
          </div>
        )}
      </div>

      <div ref={thinkingMenuRef} className="relative">
        <button
          type="button"
          aria-haspopup="listbox"
          aria-expanded={thinkingMenuOpen}
          onClick={() => setThinkingMenuOpen((open) => !open)}
          className="inline-flex items-center gap-1 rounded-md border border-border bg-surface-elevated px-2 py-1 text-[11px] text-muted transition-colors hover:text-foreground"
          title="Thinking level"
        >
          <Brain className="h-3 w-3" />
          <span>{thinkingLabel(settings?.general.thinkingLevel)}</span>
          <ChevronDown className="h-3 w-3 shrink-0" />
        </button>

        {thinkingMenuOpen && (
          <div
            role="listbox"
            aria-label="Select thinking level"
            className="absolute bottom-full left-0 z-50 mb-2 w-56 overflow-hidden rounded-lg border border-border bg-surface-elevated shadow-[0_18px_55px_rgba(0,0,0,0.45)]"
          >
            <div className="border-b border-border-subtle px-3 py-2 text-xs font-medium text-foreground">
              Thinking level
            </div>
            {(["fast", "balanced", "deep"] as const).map((level) => (
              <button
                key={level}
                type="button"
                role="option"
                aria-selected={(settings?.general.thinkingLevel ?? "balanced") === level}
                onClick={() => handleSelectThinking(level)}
                className={cn(
                  "flex w-full items-center gap-2 px-3 py-2 text-left text-xs transition-colors",
                  (settings?.general.thinkingLevel ?? "balanced") === level
                    ? "bg-white/8 text-foreground"
                    : "text-muted hover:bg-white/5 hover:text-foreground",
                )}
              >
                <span className="min-w-0 flex-1">
                  <span className="block font-medium">{thinkingLabel(level)}</span>
                  <span className="block text-[10px] text-muted-foreground">{thinkingDescription(level)}</span>
                </span>
                {(settings?.general.thinkingLevel ?? "balanced") === level && <Check className="h-3.5 w-3.5 shrink-0" />}
              </button>
            ))}
          </div>
        )}
      </div>
      <ProjectPickerModal
        open={projectPickerOpen}
        currentProjectPath={activeProjectPath}
        onClose={() => setProjectPickerOpen(false)}
        onSelect={handleSelectProject}
      />
    </div>
  );
}

function thinkingLabel(level: string | undefined): string {
  if (level === "fast") return "Fast";
  if (level === "deep") return "Deep";
  return "Balanced";
}

function thinkingDescription(level: string): string {
  if (level === "fast") return "Shorter answers";
  if (level === "deep") return "More context";
  return "Default security coach";
}

type ModelOption = ModelConfig & {
  providerId: string;
  providerName: string;
};

function getModelOptions(providers: ProviderConfig[]): ModelOption[] {
  const seen = new Set<string>();
  const options: ModelOption[] = [];

  for (const provider of providers) {
    if (!provider.enabled) continue;
    for (const model of provider.models) {
      if (!model.enabled || seen.has(model.id)) continue;
      seen.add(model.id);
      options.push({
        ...model,
        providerId: provider.id,
        providerName: provider.displayName,
      });
    }
  }

  return options;
}

function folderName(filePath: string): string {
  const parts = filePath.split(/[\\/]/).filter(Boolean);
  return parts.at(-1) ?? "Project";
}

function ContextChipPill({
  chip,
  onRemove,
}: {
  chip: ContextChip;
  onRemove: () => void;
}) {
  return (
    <span
      title={chip.detail}
      className="inline-flex max-w-64 items-center gap-1 rounded-md border border-border bg-surface-elevated px-2 py-1 text-[11px] text-foreground"
    >
      {kindIcons[chip.kind]}
      <span className="truncate">{chip.label}</span>
      {chip.removable && (
        <button
          type="button"
          onClick={onRemove}
          className="ml-0.5 text-muted hover:text-foreground"
          aria-label={`Remove ${chip.label}`}
        >
          x
        </button>
      )}
    </span>
  );
}
