import { AtSign, Brain, Check, ChevronDown, Folder, Globe, Search } from "lucide-react";
import { useEffect, useId, useMemo, useRef, useState } from "react";
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
  const [modelQuery, setModelQuery] = useState("");
  const [highlightedModelKey, setHighlightedModelKey] = useState<string>();
  const [thinkingMenuOpen, setThinkingMenuOpen] = useState(false);
  const [projectPickerOpen, setProjectPickerOpen] = useState(false);
  const modelMenuRef = useRef<HTMLDivElement>(null);
  const modelTriggerRef = useRef<HTMLButtonElement>(null);
  const modelSearchRef = useRef<HTMLInputElement>(null);
  const thinkingMenuRef = useRef<HTMLDivElement>(null);
  const modelListboxId = useId();
  const activeModelId = settings?.activeModelId ?? "deepseek-v4-flash";
  const activeProviderId = settings?.activeProviderId;
  const activeProjectPath = settings?.defaultProjectDir;
  const activeProjectName = activeProjectPath ? folderName(activeProjectPath) : null;
  const modelOptions = useMemo(
    () => getModelOptions(settings?.providers ?? []),
    [settings?.providers],
  );
  const filteredModelOptions = useMemo(() => {
    const query = modelQuery.trim().toLocaleLowerCase();
    if (!query) return modelOptions;
    return modelOptions.filter((model) =>
      [model.label, model.id, model.providerName].some((value) =>
        value.toLocaleLowerCase().includes(query),
      ),
    );
  }, [modelOptions, modelQuery]);
  const activeModel =
    modelOptions.find((model) => model.id === activeModelId && model.providerId === activeProviderId) ??
    modelOptions.find((model) => model.id === activeModelId);
  const highlightedModelIndex = filteredModelOptions.findIndex(
    (model) => modelKey(model) === highlightedModelKey,
  );
  const highlightedModel =
    highlightedModelIndex >= 0 ? filteredModelOptions[highlightedModelIndex] : undefined;

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
        setModelQuery("");
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

  useEffect(() => {
    if (!modelMenuOpen) return;
    const frame = window.requestAnimationFrame(() => {
      modelSearchRef.current?.focus();
    });
    return () => window.cancelAnimationFrame(frame);
  }, [modelMenuOpen]);

  useEffect(() => {
    if (!modelMenuOpen) return;
    const currentVisible = filteredModelOptions.some(
      (model) => modelKey(model) === highlightedModelKey,
    );
    if (currentVisible) return;
    const selected =
      filteredModelOptions.find(
        (model) => model.id === activeModelId && model.providerId === activeProviderId,
      ) ?? filteredModelOptions[0];
    setHighlightedModelKey(selected ? modelKey(selected) : undefined);
  }, [
    activeModelId,
    activeProviderId,
    filteredModelOptions,
    highlightedModelKey,
    modelMenuOpen,
  ]);

  const closeModelMenu = (restoreFocus = false) => {
    setModelMenuOpen(false);
    setModelQuery("");
    setHighlightedModelKey(undefined);
    if (restoreFocus) {
      window.requestAnimationFrame(() => modelTriggerRef.current?.focus());
    }
  };

  const handleSelectModel = async (providerId: string, modelId: string) => {
    await updateSettings({ activeProviderId: providerId, activeModelId: modelId });
    closeModelMenu(true);
  };

  const handleModelSearchKeyDown = (event: React.KeyboardEvent<HTMLInputElement>) => {
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      closeModelMenu(true);
      return;
    }
    if (filteredModelOptions.length === 0) return;

    let nextIndex = highlightedModelIndex;
    if (event.key === "ArrowDown") {
      event.preventDefault();
      nextIndex = highlightedModelIndex < filteredModelOptions.length - 1
        ? highlightedModelIndex + 1
        : 0;
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      nextIndex = highlightedModelIndex > 0
        ? highlightedModelIndex - 1
        : filteredModelOptions.length - 1;
    } else if (event.key === "Home") {
      event.preventDefault();
      nextIndex = 0;
    } else if (event.key === "End") {
      event.preventDefault();
      nextIndex = filteredModelOptions.length - 1;
    } else if (event.key === "Enter" && highlightedModel) {
      event.preventDefault();
      void handleSelectModel(highlightedModel.providerId, highlightedModel.id);
      return;
    } else {
      return;
    }

    const nextModel = filteredModelOptions[nextIndex];
    setHighlightedModelKey(modelKey(nextModel));
    window.requestAnimationFrame(() => {
      document.getElementById(modelOptionId(modelListboxId, nextIndex))?.scrollIntoView({
        block: "nearest",
      });
    });
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
          ref={modelTriggerRef}
          type="button"
          aria-haspopup="listbox"
          aria-expanded={modelMenuOpen}
          aria-controls={modelMenuOpen ? modelListboxId : undefined}
          onClick={() => {
            setThinkingMenuOpen(false);
            if (modelMenuOpen) {
              closeModelMenu();
            } else {
              setModelQuery("");
              setModelMenuOpen(true);
            }
          }}
          className="inline-flex max-w-64 items-center gap-1 rounded-md border border-border bg-surface-elevated px-2 py-1 text-[11px] text-muted transition-colors hover:text-foreground"
        >
          <span className="h-1.5 w-1.5 rounded-full bg-accent" />
          <span className="truncate">{activeModel?.label ?? activeModelId}</span>
          <ChevronDown className="h-3 w-3 shrink-0" />
        </button>

        {modelMenuOpen && (
          <div
            className="absolute bottom-full left-0 z-50 mb-2 w-72 overflow-hidden rounded-lg border border-border bg-surface-elevated shadow-[0_18px_55px_rgba(0,0,0,0.45)]"
          >
            <div className="border-b border-border-subtle px-3 py-2 text-xs font-medium text-foreground">
              Select model
            </div>
            <div className="border-b border-border-subtle p-2">
              <div className="relative">
                <Search
                  aria-hidden="true"
                  className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground"
                />
                <input
                  ref={modelSearchRef}
                  type="search"
                  role="combobox"
                  aria-label="Search models"
                  aria-autocomplete="list"
                  aria-expanded="true"
                  aria-controls={modelListboxId}
                  aria-activedescendant={
                    highlightedModelIndex >= 0
                      ? modelOptionId(modelListboxId, highlightedModelIndex)
                      : undefined
                  }
                  value={modelQuery}
                  onChange={(event) => setModelQuery(event.target.value)}
                  onKeyDown={handleModelSearchKeyDown}
                  placeholder="Search models..."
                  className="h-8 w-full rounded-md border border-border bg-surface pl-8 pr-2 text-xs text-foreground outline-none transition-colors placeholder:text-muted-foreground focus:border-accent/50"
                />
              </div>
            </div>
            <div
              id={modelListboxId}
              role="listbox"
              aria-label="Available models"
              className="max-h-64 overflow-y-auto py-1"
            >
              {filteredModelOptions.map((model, index) => {
                const key = modelKey(model);
                const selected = activeModelId === model.id && activeProviderId === model.providerId;
                const highlighted = highlightedModelKey === key;
                return (
                  <button
                    id={modelOptionId(modelListboxId, index)}
                    key={key}
                    type="button"
                    role="option"
                    aria-selected={selected}
                    onMouseEnter={() => setHighlightedModelKey(key)}
                    onMouseDown={(event) => event.preventDefault()}
                    onClick={() => void handleSelectModel(model.providerId, model.id)}
                    className={cn(
                      "flex w-full items-center gap-2 px-3 py-2 text-left text-xs transition-colors",
                      selected
                        ? "bg-white/8 text-foreground"
                        : highlighted
                          ? "bg-white/5 text-foreground"
                          : "text-muted hover:bg-white/5 hover:text-foreground",
                    )}
                  >
                    <span className="flex min-w-0 flex-1 flex-col">
                      <span className="truncate font-medium">{model.label}</span>
                      <span className="truncate text-[10px] text-muted-foreground">
                        {model.providerName}
                      </span>
                    </span>
                    {selected && <Check className="h-3.5 w-3.5 shrink-0" />}
                  </button>
                );
              })}
              {filteredModelOptions.length === 0 && (
                <div className="px-3 py-4 text-xs text-muted">
                  {modelOptions.length === 0
                    ? "No enabled models configured."
                    : `No models match "${modelQuery.trim()}".`}
                </div>
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
  return "Direct security review";
}

type ModelOption = ModelConfig & {
  providerId: string;
  providerName: string;
};

function getModelOptions(providers: ProviderConfig[]): ModelOption[] {
  const seen = new Set<string>();
  const options: ModelOption[] = [];

  for (const provider of providers) {
    if (!provider.enabled || provider.apiFormat === "cursor") continue;
    for (const model of provider.models) {
      const key = `${provider.id}:${model.id}`;
      if (!model.enabled || seen.has(key)) continue;
      seen.add(key);
      options.push({
        ...model,
        providerId: provider.id,
        providerName: provider.displayName,
      });
    }
  }

  return options;
}

function modelKey(model: Pick<ModelOption, "providerId" | "id">): string {
  return `${model.providerId}:${model.id}`;
}

function modelOptionId(listboxId: string, index: number): string {
  return `${listboxId}-option-${index}`;
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
