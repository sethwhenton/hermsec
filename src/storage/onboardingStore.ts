import { ensureHermsecAppData, getAppDataLayout } from "./appData.js";
import { JsonStore, optionalString, requireEnum, requireRecord } from "./jsonStore.js";

export const onboardingSteps = [
  "not-started",
  "privacy-selected",
  "workspace-selected",
  "scanner-checked",
  "report-location-selected",
  "provider-selected",
  "complete",
] as const;

export type OnboardingStep = (typeof onboardingSteps)[number];

export type OnboardingState = {
  schemaVersion: 1;
  step: OnboardingStep;
  workspaceId?: string;
  updatedAt: string;
};

export function defaultOnboardingState(now = new Date()): OnboardingState {
  return {
    schemaVersion: 1,
    step: "not-started",
    updatedAt: now.toISOString(),
  };
}

export function validateOnboardingState(value: unknown): OnboardingState {
  const record = requireRecord(value, "onboarding");
  if (record.schemaVersion !== 1) {
    throw new Error("onboarding.schemaVersion must be 1");
  }
  const step = requireEnum(record.step, "onboarding.step", onboardingSteps);
  const updatedAt = optionalString(record.updatedAt, "onboarding.updatedAt") ?? new Date().toISOString();
  const workspaceId = optionalString(record.workspaceId, "onboarding.workspaceId");
  const state: OnboardingState = { schemaVersion: 1, step, updatedAt };
  if (workspaceId) {
    state.workspaceId = workspaceId;
  }
  return state;
}

export async function loadOnboardingState(): Promise<OnboardingState> {
  const layout = await ensureHermsecAppData();
  return new JsonStore(layout.onboardingFile, defaultOnboardingState(), validateOnboardingState).load();
}

export async function saveOnboardingState(state: OnboardingState): Promise<OnboardingState> {
  const layout = await ensureHermsecAppData();
  return new JsonStore(layout.onboardingFile, defaultOnboardingState(), validateOnboardingState).save(state);
}

export async function advanceOnboarding(step: OnboardingStep, workspaceId?: string): Promise<OnboardingState> {
  const layout = await ensureHermsecAppData();
  const store = new JsonStore(layout.onboardingFile, defaultOnboardingState(), validateOnboardingState);
  return store.save({
    schemaVersion: 1,
    step,
    ...(workspaceId ? { workspaceId } : {}),
    updatedAt: new Date().toISOString(),
  });
}

export function onboardingPath(): string {
  return getAppDataLayout().onboardingFile;
}
