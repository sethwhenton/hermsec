import { Bot, Network } from "lucide-react";
import { useMemo } from "react";
import { cn } from "@/lib/cn";
import { useSettingsStore } from "@/store/settingsStore";
import type {
  AgentModelSelection,
  AgentReasoningDepth,
  AgentScanSettings,
  MoAInspectionPresetConfig,
  MoAInspectionPresetId,
  SingleAgentScanConfig,
} from "@/types/settings";
import { Badge } from "@/components/ui/Badge";
import { Input } from "@/components/ui/Input";
import { Select } from "@/components/ui/Select";

type ModelChoice = {
  providerId: string;
  providerName: string;
  modelId: string;
  modelLabel: string;
};

const moaRoleModels: Array<{ id: string; label: string; description: string }> = [
  {
    id: "injection-and-execution",
    label: "Injection and execution",
    description: "Command execution, SQL/query injection, eval, deserialization, and code execution risks.",
  },
  {
    id: "auth-and-data-flow",
    label: "Auth and data flow",
    description: "Authentication, authorization, session, redirect, CORS, and sensitive data exposure risks.",
  },
  {
    id: "secrets-and-config",
    label: "Secrets and config",
    description: "Hardcoded secrets, debug posture, weak headers, deployment config, and unsafe defaults.",
  },
  {
    id: "moa-false-positive-judge",
    label: "False-positive judge",
    description: "Reviews candidate findings and rejects weak or unsupported agent claims.",
  },
  {
    id: "moa-aggregator",
    label: "Aggregator",
    description: "Deduplicates accepted candidates and writes the final MoA findings.",
  },
];

const moaPresets: Array<{
  id: MoAInspectionPresetId;
  label: string;
  description: string;
  panelSize: MoAInspectionPresetConfig["panelSize"];
  debateRounds: number;
  consensusThreshold: MoAInspectionPresetConfig["consensusThreshold"];
}> = [
  {
    id: "fast-quorum",
    label: "Fast quorum",
    description: "Three agents, one comparison round, and a majority decision.",
    panelSize: 3,
    debateRounds: 1,
    consensusThreshold: "majority",
  },
  {
    id: "balanced-panel",
    label: "Balanced panel",
    description: "Five agents compare bounded code evidence before a coordinator summary.",
    panelSize: 5,
    debateRounds: 2,
    consensusThreshold: "coordinator",
  },
  {
    id: "deep-panel",
    label: "Deep panel",
    description: "Seven agents, extra debate, and a stricter consensus threshold.",
    panelSize: 7,
    debateRounds: 3,
    consensusThreshold: "supermajority",
  },
];

const fallbackAgents: AgentScanSettings = {
  singleAgent: {
    reasoningDepth: "balanced",
    maxToolRounds: 4,
  },
  moa: {
    presetId: "balanced-panel",
    panelSize: 5,
    debateRounds: 2,
    consensusThreshold: "coordinator",
  },
};

export function AgentsSettings() {
  const settings = useSettingsStore((s) => s.settings);
  const update = useSettingsStore((s) => s.update);

  const modelChoices = useMemo(() => {
    return (settings?.providers ?? [])
      .filter((provider) => provider.enabled && provider.apiFormat !== "cursor")
      .flatMap((provider) =>
        provider.models
          .filter((model) => model.enabled)
          .map((model) => ({
            providerId: provider.id,
            providerName: provider.displayName,
            modelId: model.id,
            modelLabel: model.label,
          })),
      );
  }, [settings?.providers]);

  if (!settings) return null;

  const agents = normalizeAgentSettings(settings.agents, modelChoices);

  const saveAgents = (next: AgentScanSettings) => {
    void update({ agents: next });
  };

  const updateSingle = (patch: Partial<SingleAgentScanConfig>) => {
    saveAgents({
      ...agents,
      singleAgent: {
        ...agents.singleAgent,
        ...patch,
      },
    });
  };

  const updateMoa = (patch: Partial<MoAInspectionPresetConfig>) => {
    saveAgents({
      ...agents,
      moa: {
        ...agents.moa,
        ...patch,
      },
    });
  };

  const modelOptions = buildModelOptions(modelChoices);
  const singleModelValue = composeModelValue(agents.singleAgent.providerId, agents.singleAgent.modelId);
  const updateMoaRoleModel = (roleId: string, selection: AgentModelSelection | undefined) => {
    const nextRoleModels = { ...(agents.moa.roleModels ?? {}) };
    if (selection?.providerId && selection.modelId) {
      nextRoleModels[roleId] = selection;
    } else {
      delete nextRoleModels[roleId];
    }
    updateMoa({ roleModels: nextRoleModels });
  };

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-xl font-medium">Agents</h1>
        <p className="mt-1 text-xs leading-5 text-muted">
          Configure the scanner-free agent modes. Deep assisted scan remains the scanner-backed mode.
        </p>
      </div>

      <div className="space-y-4">
        <SettingsCard
          icon={<Bot className="h-4 w-4" />}
          title="Single Agent Inspection"
          description="One model inspects bounded repository evidence directly. HermSec scanners do not run in this mode."
        >
          <div className="grid gap-4">
            <Field label="Inspection model" hint="Defaults to the active chat model when no model is selected.">
              <Select
                value={singleModelValue}
                onChange={(value) => {
                  const selected = splitModelValue(value);
                  updateSingle({ providerId: selected?.providerId, modelId: selected?.modelId });
                }}
                options={modelOptions}
              />
            </Field>

            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Reasoning depth">
                <Select
                  value={agents.singleAgent.reasoningDepth}
                  onChange={(reasoningDepth) =>
                    updateSingle({ reasoningDepth: reasoningDepth as AgentReasoningDepth })
                  }
                  options={[
                    { value: "fast", label: "Fast" },
                    { value: "balanced", label: "Balanced" },
                    { value: "deep", label: "Deep" },
                  ]}
                />
              </Field>
              <Field label="Tool rounds" hint="Caps repeated inspection loops.">
                <Input
                  type="number"
                  min={1}
                  max={12}
                  value={agents.singleAgent.maxToolRounds}
                  onChange={(event) =>
                    updateSingle({ maxToolRounds: clampInteger(Number(event.target.value), 1, 12) })
                  }
                />
              </Field>
            </div>
          </div>
        </SettingsCard>

        <SettingsCard
          icon={<Network className="h-4 w-4" />}
          title="MoA Inspection"
          description="A scanner-free mixture-of-agents preset coordinates specialist reviews, judging, and aggregation."
        >
          <div className="grid gap-4">
            <div>
              <div className="mb-2 text-xs font-medium text-foreground">Preset</div>
              <div className="grid gap-2 sm:grid-cols-3">
                {moaPresets.map((preset) => {
                  const active = agents.moa.presetId === preset.id;
                  return (
                    <button
                      key={preset.id}
                      type="button"
                      onClick={() =>
                        updateMoa({
                          presetId: preset.id,
                          panelSize: preset.panelSize,
                          debateRounds: preset.debateRounds,
                          consensusThreshold: preset.consensusThreshold,
                        })
                      }
                      className={cn(
                        "min-h-28 rounded-lg border px-3 py-3 text-left transition-colors duration-150 ease-out",
                        active
                          ? "border-accent/45 bg-accent-muted text-foreground"
                          : "border-border bg-background text-muted hover:border-foreground/20 hover:bg-white/[0.04] hover:text-foreground",
                      )}
                    >
                      <span className="block text-xs font-semibold">{preset.label}</span>
                      <span className="mt-1 block text-[11px] leading-4 text-muted-foreground">
                        {preset.description}
                      </span>
                      <span className="mt-3 flex flex-wrap gap-1">
                        <Badge>{preset.panelSize} agents</Badge>
                        <Badge>{preset.debateRounds} round{preset.debateRounds === 1 ? "" : "s"}</Badge>
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>

            <div className="grid gap-3 sm:grid-cols-3">
              <Field label="Panel size">
                <Select
                  value={String(agents.moa.panelSize)}
                  onChange={(panelSize) => updateMoa({ panelSize: Number(panelSize) as 3 | 5 | 7 })}
                  options={[
                    { value: "3", label: "3 agents" },
                    { value: "5", label: "5 agents" },
                    { value: "7", label: "7 agents" },
                  ]}
                />
              </Field>
              <Field label="Debate rounds">
                <Input
                  type="number"
                  min={1}
                  max={5}
                  value={agents.moa.debateRounds}
                  onChange={(event) =>
                    updateMoa({ debateRounds: clampInteger(Number(event.target.value), 1, 5) })
                  }
                />
              </Field>
              <Field label="Consensus">
                <Select
                  value={agents.moa.consensusThreshold}
                  onChange={(consensusThreshold) =>
                    updateMoa({
                      consensusThreshold: consensusThreshold as MoAInspectionPresetConfig["consensusThreshold"],
                    })
                  }
                  options={[
                    { value: "majority", label: "Majority" },
                    { value: "supermajority", label: "Supermajority" },
                    { value: "coordinator", label: "Coordinator" },
                  ]}
                />
              </Field>
            </div>

            <div className="rounded-lg border border-border-subtle bg-background p-3">
              <div className="mb-3">
                <div className="text-xs font-semibold text-foreground">Panel models</div>
                <div className="mt-1 text-[11px] leading-4 text-muted">
                  Assign a model to each MoA task. Unset rows use the active chat model.
                </div>
              </div>
              <div className="grid gap-2">
                {moaRoleModels.map((role) => {
                  const selection = agents.moa.roleModels?.[role.id];
                  return (
                    <div
                      key={role.id}
                      className="grid gap-2 rounded-md border border-border-subtle bg-surface/60 px-3 py-2 sm:grid-cols-[minmax(0,1fr)_minmax(220px,300px)] sm:items-center"
                    >
                      <div className="min-w-0">
                        <div className="text-xs font-medium text-foreground">{role.label}</div>
                        <div className="mt-0.5 text-[11px] leading-4 text-muted">{role.description}</div>
                      </div>
                      <Select
                        value={composeModelValue(selection?.providerId, selection?.modelId)}
                        onChange={(value) => updateMoaRoleModel(role.id, splitModelValue(value))}
                        options={modelOptions}
                      />
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </SettingsCard>
      </div>
    </div>
  );
}

function SettingsCard({
  icon,
  title,
  description,
  children,
}: {
  icon: React.ReactNode;
  title: string;
  description: string;
  children: React.ReactNode;
}) {
  return (
    <section className="rounded-lg border border-border bg-surface p-4">
      <div className="mb-4 flex items-start gap-3">
        <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md border border-border bg-surface-elevated text-accent">
          {icon}
        </span>
        <div className="min-w-0">
          <h2 className="text-sm font-semibold text-foreground">{title}</h2>
          <p className="mt-1 text-xs leading-5 text-muted">{description}</p>
        </div>
      </div>
      {children}
    </section>
  );
}

function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <label className="block space-y-1.5">
      <span className="text-xs font-medium text-foreground">{label}</span>
      {children}
      {hint ? <span className="block text-[11px] leading-4 text-muted">{hint}</span> : null}
    </label>
  );
}

function normalizeAgentSettings(
  value: AgentScanSettings | undefined,
  modelChoices: ModelChoice[],
): AgentScanSettings {
  const fallbackModel = modelChoices[0];
  const presetId = value?.moa?.presetId ?? fallbackAgents.moa.presetId;
  const consensusThreshold = value?.moa?.consensusThreshold ?? fallbackAgents.moa.consensusThreshold;
  const legacyMoa = value?.moa as MoAInspectionPresetConfig & {
    coordinatorProviderId?: string;
    coordinatorModelId?: string;
  } | undefined;
  const roleModels = normalizeRoleModels(value?.moa?.roleModels, modelChoices);
  if (!roleModels["moa-aggregator"] && legacyMoa?.coordinatorProviderId && legacyMoa.coordinatorModelId) {
    roleModels["moa-aggregator"] = {
      providerId: legacyMoa.coordinatorProviderId,
      modelId: legacyMoa.coordinatorModelId,
    };
  }
  return {
    singleAgent: {
      providerId: fallbackModel?.providerId,
      modelId: fallbackModel?.modelId,
      ...(value?.singleAgent?.providerId ? { providerId: value.singleAgent.providerId } : {}),
      ...(value?.singleAgent?.modelId ? { modelId: value.singleAgent.modelId } : {}),
      reasoningDepth: value?.singleAgent?.reasoningDepth ?? fallbackAgents.singleAgent.reasoningDepth,
      maxToolRounds: clampInteger(value?.singleAgent?.maxToolRounds ?? fallbackAgents.singleAgent.maxToolRounds, 1, 12),
    },
    moa: {
      presetId,
      consensusThreshold,
      panelSize: normalizePanelSize(value?.moa?.panelSize ?? fallbackAgents.moa.panelSize),
      debateRounds: clampInteger(value?.moa?.debateRounds ?? fallbackAgents.moa.debateRounds, 1, 5),
      ...(Object.keys(roleModels).length > 0 ? { roleModels } : {}),
    },
  };
}

function normalizeRoleModels(
  value: Record<string, AgentModelSelection> | undefined,
  modelChoices: ModelChoice[],
): Record<string, AgentModelSelection> {
  if (!value) return {};
  const valid = new Set(modelChoices.map((choice) => composeModelValue(choice.providerId, choice.modelId)));
  const normalized: Record<string, AgentModelSelection> = {};
  for (const role of moaRoleModels) {
    const selection = value[role.id];
    const composed = composeModelValue(selection?.providerId, selection?.modelId);
    if (composed && valid.has(composed)) {
      normalized[role.id] = {
        providerId: selection.providerId,
        modelId: selection.modelId,
      };
    }
  }
  return normalized;
}

function buildModelOptions(modelChoices: ModelChoice[]) {
  return [
    { value: "", label: modelChoices.length > 0 ? "Use active chat model" : "No enabled models" },
    ...modelChoices.map((choice) => ({
      value: composeModelValue(choice.providerId, choice.modelId),
      label: `${choice.modelLabel} (${choice.providerName})`,
    })),
  ];
}

function composeModelValue(providerId?: string, modelId?: string): string {
  return providerId && modelId ? `${providerId}::${modelId}` : "";
}

function splitModelValue(value: string): { providerId: string; modelId: string } | undefined {
  const [providerId, ...modelParts] = value.split("::");
  const modelId = modelParts.join("::");
  return providerId && modelId ? { providerId, modelId } : undefined;
}

function clampInteger(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) return min;
  return Math.min(max, Math.max(min, Math.floor(value)));
}

function normalizePanelSize(value: number): 3 | 5 | 7 {
  if (value === 3 || value === 7) return value;
  return 5;
}
