export type ModelUsage = {
  provider: string;
  model: string;
  promptTokens?: number;
  completionTokens?: number;
  totalTokens?: number;
  estimatedUsd?: number;
  local: boolean;
};

export function summarizeModelUsage(usages: readonly ModelUsage[]): ModelUsage {
  const first = usages[0];
  const promptTokens = sumOptional(usages.map((usage) => usage.promptTokens));
  const completionTokens = sumOptional(usages.map((usage) => usage.completionTokens));
  const totalTokens = sumOptional(usages.map((usage) => usage.totalTokens));
  const estimatedUsd = sumOptional(usages.map((usage) => usage.estimatedUsd));
  return {
    provider: first?.provider ?? "none",
    model: first?.model ?? "none",
    ...(promptTokens !== undefined ? { promptTokens } : {}),
    ...(completionTokens !== undefined ? { completionTokens } : {}),
    ...(totalTokens !== undefined ? { totalTokens } : {}),
    ...(estimatedUsd !== undefined ? { estimatedUsd } : {}),
    local: usages.every((usage) => usage.local)
  };
}

function sumOptional(values: readonly (number | undefined)[]): number | undefined {
  const present = values.filter((value): value is number => value !== undefined);
  if (present.length === 0) {
    return undefined;
  }
  return present.reduce((total, value) => total + value, 0);
}
