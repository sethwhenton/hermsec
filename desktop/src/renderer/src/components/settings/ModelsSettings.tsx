import { Check, ChevronDown, ChevronRight, RefreshCw, Search } from "lucide-react";
import { useMemo, useState } from "react";
import { cn } from "@/lib/cn";
import { requireHermsecApi } from "@/lib/ipc";
import { useSettingsStore } from "@/store/settingsStore";
import type { ModelConfig, ProviderConfig } from "@/types/settings";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Toggle } from "@/components/ui/Toggle";
import { ProviderLogo } from "./ProviderLogo";

export function ModelsSettings() {
  const settings = useSettingsStore((s) => s.settings);
  const update = useSettingsStore((s) => s.update);
  const [query, setQuery] = useState("");
  const [openProviders, setOpenProviders] = useState<Set<string>>(() => new Set());
  const [refreshingProviderId, setRefreshingProviderId] = useState<string | null>(null);

  const filteredProviders = useMemo(() => {
    if (!settings) return [];
    const q = query.trim().toLowerCase();
    if (!q) return settings.providers;
    return settings.providers
      .map((provider) => ({
        ...provider,
        models: provider.models.filter(
          (model) => model.label.toLowerCase().includes(q) || model.id.toLowerCase().includes(q),
        ),
      }))
      .filter((provider) => provider.models.length > 0 || provider.displayName.toLowerCase().includes(q));
  }, [settings, query]);

  if (!settings) return null;

  const toggleProviderOpen = (providerId: string) => {
    setOpenProviders((current) => {
      const next = new Set(current);
      if (next.has(providerId)) {
        next.delete(providerId);
      } else {
        next.add(providerId);
      }
      return next;
    });
  };

  const toggleModel = (providerId: string, modelId: string, enabled: boolean) => {
    const providers = settings.providers.map((provider) => {
      if (provider.id !== providerId) return provider;
      return {
        ...provider,
        models: provider.models.map((model) =>
          model.id === modelId ? { ...model, enabled } : model,
        ),
      };
    });
    void update({ providers });
  };

  const setActiveModel = (providerId: string, modelId: string) => {
    void update({ activeProviderId: providerId, activeModelId: modelId });
  };

  const refreshModels = async (provider: ProviderConfig) => {
    if (refreshingProviderId) return;
    setRefreshingProviderId(provider.id);
    try {
      const result = await requireHermsecApi().provider.test({
        providerId: provider.id,
        baseUrl: provider.baseUrl,
        apiFormat: provider.apiFormat,
        apiKey: provider.apiKey,
        apiKeyEnvVar: provider.apiKeyEnvVar,
      });
      const providers = settings.providers.map((item) => {
        if (item.id !== provider.id) return item;
        return {
          ...item,
          models: result.models?.length ? mergeModels(item.models, result.models) : item.models,
          modelDiscovery: {
            status: result.ok ? "success" as const : "error" as const,
            message: result.message,
            modelCount: result.modelCount,
            lastCheckedAt: new Date().toISOString(),
          },
        };
      });
      void update({ providers });
    } finally {
      setRefreshingProviderId(null);
    }
  };

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-xl font-medium">Models</h1>
        <p className="mt-1 text-xs text-muted">Expand a provider to choose which models Hermsec may use.</p>
      </div>

      <div className="relative mb-6">
        <Search className="absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-muted" />
        <Input
          className="pl-9"
          placeholder="Search models or providers"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
      </div>

      <div className="space-y-3">
        {filteredProviders.map((provider) => {
          const open = openProviders.has(provider.id);
          const enabledCount = provider.models.filter((model) => model.enabled).length;
          const activeInProvider = settings.activeProviderId === provider.id;
          return (
            <section key={provider.id} className="overflow-hidden rounded-lg border border-border bg-surface">
              <button
                type="button"
                className="flex w-full items-center gap-3 px-4 py-3 text-left transition-colors duration-150 ease-out hover:bg-white/[0.04] active:scale-[0.995]"
                onClick={() => toggleProviderOpen(provider.id)}
                aria-expanded={open}
              >
                <ProviderLogo name={provider.displayName} logoUrl={provider.logoUrl} className="h-7 w-7" />
                <span className="min-w-0 flex-1">
                  <span className="flex items-center gap-2">
                    <span className="truncate text-sm font-medium text-foreground">{provider.displayName}</span>
                    {activeInProvider && <Badge>Active provider</Badge>}
                  </span>
                  <span className="mt-0.5 block text-xs text-muted">
                    {enabledCount} enabled / {provider.models.length} available
                    {provider.modelDiscovery?.message ? ` · ${provider.modelDiscovery.message}` : ""}
                  </span>
                </span>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={(event) => {
                    event.stopPropagation();
                    void refreshModels(provider);
                  }}
                  disabled={refreshingProviderId === provider.id || provider.supportsModelDiscovery === false}
                >
                  <RefreshCw className={cn("h-3.5 w-3.5", refreshingProviderId === provider.id && "animate-spin")} />
                  Refresh
                </Button>
                {open ? <ChevronDown className="h-4 w-4 text-muted" /> : <ChevronRight className="h-4 w-4 text-muted" />}
              </button>

              {open && (
                <div className="border-t border-border-subtle">
                  {provider.models.map((model, index) => {
                    const active = settings.activeProviderId === provider.id && settings.activeModelId === model.id;
                    return (
                      <div
                        key={model.id}
                        className={`flex items-center justify-between gap-3 px-4 py-2.5 ${index > 0 ? "border-t border-border-subtle" : ""}`}
                      >
                        <button
                          type="button"
                          className="min-w-0 flex-1 text-left"
                          onClick={() => setActiveModel(provider.id, model.id)}
                        >
                          <span className="flex items-center gap-2">
                            <span className="truncate text-sm text-foreground">{model.label}</span>
                            {active && <span className="inline-flex items-center gap-1 text-[10px] text-accent"><Check className="h-3 w-3" /> Active</span>}
                          </span>
                          <span className="mt-0.5 block truncate text-[11px] text-muted">{model.id}</span>
                        </button>
                        <Toggle
                          checked={model.enabled}
                          onChange={(enabled) => toggleModel(provider.id, model.id, enabled)}
                        />
                      </div>
                    );
                  })}
                  {provider.models.length === 0 && (
                    <div className="px-4 py-6 text-center text-xs text-muted">
                      No models for this provider. Use Refresh or edit the provider.
                    </div>
                  )}
                </div>
              )}
            </section>
          );
        })}

        {filteredProviders.length === 0 && (
          <div className="rounded-lg border border-border px-4 py-8 text-center text-sm text-muted">
            No providers or models match this search.
          </div>
        )}
      </div>
    </div>
  );
}

function mergeModels(existing: ModelConfig[], incoming: ModelConfig[]): ModelConfig[] {
  const byId = new Map(existing.map((model) => [model.id, model]));
  for (const model of incoming) {
    const current = byId.get(model.id);
    byId.set(model.id, {
      ...model,
      enabled: current?.enabled ?? model.enabled,
      label: model.label || current?.label || model.id,
    });
  }
  return [...byId.values()].sort((left, right) => left.label.localeCompare(right.label));
}
