import { CheckCircle2, ChevronDown, ChevronRight, ExternalLink, RefreshCw, XCircle } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { cn } from "@/lib/cn";
import { requireHermsecApi } from "@/lib/ipc";
import type { ModelConfig, ProviderConfig, ProviderTestResult } from "@/types/settings";
import { Button } from "@/components/ui/Button";
import { Drawer } from "@/components/ui/Drawer";
import { Input } from "@/components/ui/Input";
import { Select } from "@/components/ui/Select";
import Spiral5x5 from "@/components/ui/Spiral5x5";

interface ProviderEditDrawerProps {
  open: boolean;
  provider: ProviderConfig | null;
  isNew?: boolean;
  onClose: () => void;
  onSave: (provider: ProviderConfig) => void;
}

type TestState = "idle" | "testing" | "success" | "error";

export function ProviderEditDrawer({
  open,
  provider,
  isNew,
  onClose,
  onSave,
}: ProviderEditDrawerProps) {
  const [draft, setDraft] = useState<ProviderConfig | null>(provider);
  const [testState, setTestState] = useState<TestState>("idle");
  const [testResult, setTestResult] = useState<ProviderTestResult | null>(null);
  const [modelsOpen, setModelsOpen] = useState(false);
  const requestIdRef = useRef(0);

  useEffect(() => {
    setDraft(provider);
    setTestState("idle");
    setTestResult(null);
    setModelsOpen(false);
  }, [provider, open]);

  useEffect(() => {
    if (!open || !draft?.baseUrl.trim() || draft.supportsModelDiscovery === false) return;
    const timer = window.setTimeout(() => {
      void runProviderCheck("auto");
    }, 750);
    return () => window.clearTimeout(timer);
    // Keep this dependency list narrow so model updates from discovery do not retrigger discovery.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, draft?.id, draft?.baseUrl, draft?.apiKey, draft?.apiKeyEnvVar, draft?.apiFormat, draft?.supportsModelDiscovery]);

  if (!draft) return null;

  const isPreset = Boolean(draft.presetId);
  const canDiscover = draft.supportsModelDiscovery !== false;
  const requiresApiKey = !providerAllowsNoApiKey(draft);
  const invalidEnvironmentVariable = Boolean(
    draft.apiKeyEnvVar?.trim() &&
    !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(draft.apiKeyEnvVar.trim()),
  );

  const runProviderCheck = async (_source: "auto" | "manual") => {
    if (!draft.baseUrl.trim() || !canDiscover) return;
    const requestId = requestIdRef.current + 1;
    requestIdRef.current = requestId;
    setTestState("testing");
    setTestResult(null);
    try {
      const result = await requireHermsecApi().provider.test({
        providerId: draft.id,
        baseUrl: draft.baseUrl,
        apiFormat: draft.apiFormat,
        apiKey: draft.apiKey,
        apiKeyEnvVar: draft.apiKeyEnvVar,
      });
      if (requestId !== requestIdRef.current) return;
      setTestResult(result);
      setTestState(result.ok ? "success" : "error");
      setDraft((current) => current ? {
        ...current,
        models: result.models?.length ? mergeModels(current.models, result.models) : current.models,
        modelDiscovery: {
          status: result.ok ? "success" : "error",
          message: result.message,
          modelCount: result.modelCount,
          lastCheckedAt: new Date().toISOString(),
        },
      } : current);
      if (result.models?.length) {
        setModelsOpen(true);
      }
    } catch (error) {
      if (requestId !== requestIdRef.current) return;
      setTestResult({
        ok: false,
        message: error instanceof Error ? error.message : "Test failed",
        latencyMs: 0,
      });
      setTestState("error");
    }
  };

  const handleSave = () => {
    onSave({
      ...draft,
      apiFormat: draft.apiFormat ?? "openai-compatible",
      supportsModelDiscovery: canDiscover,
      modelDiscovery: draft.modelDiscovery ?? { status: "idle" },
    });
    onClose();
  };

  const discoveryText = modelStatusText(testState, testResult, draft.models.length);

  return (
    <Drawer open={open} onClose={onClose} title={isNew ? "Add provider" : "Edit provider"}>
      <div className="space-y-4">
        <p className="text-xs text-muted">
          {isPreset && requiresApiKey
            ? "Use the preset URL and add your API key. Hermsec will check the provider and import available models."
            : isPreset
              ? "Use the preset URL for your local provider. Hermsec will check the endpoint and import available models."
            : "Configure a custom provider. OpenAI-compatible endpoints work best today."}
        </p>
        <ProviderVisitLink href={draft.websiteUrl} />

        <Field label="Provider ID" hint="Lowercase letters, numbers, hyphens, or underscores">
          <Input
            value={draft.id}
            disabled={!isNew || isPreset}
            onChange={(e) => setDraft({ ...draft, id: e.target.value })}
          />
        </Field>

        <Field label="Display name">
          <Input
            value={draft.displayName}
            disabled={isPreset}
            onChange={(e) => setDraft({ ...draft, displayName: e.target.value })}
          />
        </Field>

        <Field label="Provider URL">
          <Input
            value={draft.baseUrl}
            disabled={isPreset}
            onChange={(e) => setDraft({ ...draft, baseUrl: e.target.value })}
            placeholder="https://api.example.com/v1"
          />
        </Field>

        <Field label="API format">
          <Select
            value={draft.apiFormat ?? "openai-compatible"}
            disabled={isPreset}
            onChange={(apiFormat) =>
              setDraft({
                ...draft,
                apiFormat: apiFormat as ProviderConfig["apiFormat"],
              })
            }
            options={[
              { value: "openai-compatible", label: "OpenAI-compatible" },
              { value: "anthropic", label: "Anthropic" },
              { value: "gemini", label: "Gemini" },
              { value: "custom", label: "Custom" },
            ]}
          />
        </Field>

        {!isPreset && (
          <Field label="Auth kind">
            <Select
              value={draft.authKind}
              onChange={(authKind) =>
                setDraft({
                  ...draft,
                  authKind: authKind as ProviderConfig["authKind"],
                })
              }
              options={[
                { value: "api_key", label: "API key" },
                { value: "custom", label: "Custom" },
                { value: "environment", label: "Environment" },
              ]}
            />
          </Field>
        )}

        {requiresApiKey ? (
          <>
            <Field label="API key" hint="Stored locally in Hermsec settings. Leave empty to use an environment variable.">
              <Input
                type="password"
                value={draft.apiKey ?? ""}
                onChange={(e) => setDraft({ ...draft, apiKey: e.target.value })}
                placeholder="Paste provider API key"
              />
            </Field>

            <Field
              label="Environment variable"
              hint="Enter the variable name only, such as OPENROUTER_API_KEY."
            >
              <Input
                value={draft.apiKeyEnvVar ?? ""}
                onChange={(e) => setDraft({ ...draft, apiKeyEnvVar: e.target.value })}
                placeholder="HERMSEC_MODEL_API_KEY"
                aria-invalid={invalidEnvironmentVariable}
              />
              {invalidEnvironmentVariable && (
                <p className="mt-1.5 text-[11px] text-danger">
                  This looks like a credential. Paste it into the API key field above; Hermsec will safely correct it when you save.
                </p>
              )}
            </Field>
          </>
        ) : (
          <div className="rounded-lg border border-border bg-surface px-3 py-2 text-xs text-muted">
            This local provider does not require an API key. Keep Ollama running locally, then use Check to load available models.
          </div>
        )}

        <div className="rounded-lg border border-border bg-surface px-3 py-3">
          <div className="flex items-start gap-2">
            {testState === "testing" && <Spiral5x5 glow className="mt-0.5 shrink-0" />}
            {testState === "success" && <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-success" />}
            {testState === "error" && <XCircle className="mt-0.5 h-4 w-4 shrink-0 text-danger" />}
            {testState === "idle" && <span className="mt-1 h-2 w-2 shrink-0 rounded-full bg-muted" />}
            <div className="min-w-0 flex-1">
              <div className={cn("text-xs font-medium", testState === "error" ? "text-danger" : testState === "success" ? "text-success" : "text-foreground")}>
                {discoveryText}
              </div>
              <div className="mt-0.5 text-[11px] text-muted">
                {canDiscover ? "Hermsec checks the provider after URL or key changes." : "Model discovery is not available for this provider yet."}
              </div>
            </div>
            <Button variant="outline" size="sm" onClick={() => void runProviderCheck("manual")} disabled={testState === "testing" || !canDiscover}>
              <RefreshCw className={cn("h-3.5 w-3.5", testState === "testing" && "animate-spin")} />
              Check
            </Button>
          </div>

          <button
            type="button"
            className="mt-3 flex w-full items-center justify-between rounded-md px-1 py-1 text-left text-xs text-muted transition-colors hover:bg-white/5 hover:text-foreground"
            onClick={() => setModelsOpen((open) => !open)}
          >
            <span>{draft.models.length} available model{draft.models.length === 1 ? "" : "s"}</span>
            {modelsOpen ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
          </button>

          {modelsOpen && (
            <div className="mt-2 max-h-44 overflow-y-auto rounded-md border border-border-subtle">
              {draft.models.map((model, index) => (
                <div
                  key={model.id}
                  className={cn("flex items-center justify-between px-3 py-2 text-xs", index > 0 && "border-t border-border-subtle")}
                >
                  <span className="truncate text-foreground">{model.label}</span>
                  <span className="ml-2 shrink-0 text-[10px] text-muted">{model.id}</span>
                </div>
              ))}
              {draft.models.length === 0 && (
                <div className="px-3 py-4 text-center text-xs text-muted">No models discovered yet.</div>
              )}
            </div>
          )}
        </div>

        <div className="flex items-center justify-end gap-2 pt-2">
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={handleSave}>Save provider</Button>
        </div>
      </div>
    </Drawer>
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
      {hint && <span className="block text-[11px] text-muted">{hint}</span>}
    </label>
  );
}

function providerAllowsNoApiKey(provider: ProviderConfig): boolean {
  return provider.id === "ollama-local" || provider.presetId === "ollama-local";
}

function ProviderVisitLink({ href }: { href?: string }) {
  if (!href) return null;
  return (
    <a
      href={href}
      target="_blank"
      rel="noreferrer"
      className="inline-flex items-center gap-1 rounded-md px-1.5 py-1 text-[10px] font-medium text-muted transition-colors duration-150 ease-out hover:bg-white/6 hover:text-foreground"
    >
      Visit provider
      <ExternalLink className="h-3 w-3" />
    </a>
  );
}

function modelStatusText(state: TestState, result: ProviderTestResult | null, fallbackCount: number): string {
  if (state === "testing") return "Checking provider and loading models...";
  if (result?.ok) {
    const count = result.modelCount ?? fallbackCount;
    return `Connected. ${count} model${count === 1 ? "" : "s"} available.`;
  }
  if (result && !result.ok) return result.message;
  return fallbackCount > 0
    ? `${fallbackCount} model${fallbackCount === 1 ? "" : "s"} configured.`
    : "Provider not checked yet.";
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
