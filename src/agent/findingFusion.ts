import { stableId } from "../shared/text.js";
import type { Finding } from "../shared/types.js";
import {
  advisoryIdentifiers,
  areFindingIdentitiesCompatible,
  buildStableFindingIdentity,
  normalizeAdvisoryIdentifier,
  normalizeCweList,
  type StableFindingIdentity,
} from "./findingIdentity.js";

export type FindingSourceKind = "scanner" | "agent";

export type FindingFusionInput = {
  finding: Finding;
  sourceId?: string;
  sourceLabel?: string;
  sourceKind?: FindingSourceKind;
  vulnerabilityClass?: string;
  sinkAnchor?: string;
};

export type FindingFusionOptions = {
  repoRoot?: string;
  lineTolerance?: number;
};

export type FusedFindingSource = {
  sourceId: string;
  sourceLabel: string;
  sourceKind: FindingSourceKind;
  findingId: string;
  fingerprint: string;
  identityId: string;
  contentDigest: string;
  identity: StableFindingIdentity;
  rawFinding: Finding;
};

export type CanonicalFindingSources = {
  canonicalFindingId: string;
  canonicalFingerprint: string;
  identity: StableFindingIdentity;
  sourceIds: string[];
  sourceLabels: string[];
  scannerSourceIds: string[];
  agentSourceIds: string[];
  sources: FusedFindingSource[];
};

export type DuplicateFindingGroup = {
  groupId: string;
  canonicalFindingId: string;
  reason: "compatible-repository-sink" | "matching-package-advisory";
  sourceIds: string[];
  sourceLabels: string[];
};

export type FindingFusionSidecar = {
  canonicalSources: CanonicalFindingSources[];
  duplicateGroups: DuplicateFindingGroup[];
};

export type FindingFusionResult = {
  canonicalFindings: Finding[];
  sidecar: FindingFusionSidecar;
};

/** Hard ceiling protecting deterministic complete-link fusion from quadratic input. */
export const MAX_FINDING_FUSION_INPUTS = 2_000;

type NormalizedFusionSource = {
  finding: Finding;
  sourceId: string;
  sourceLabel: string;
  sourceKind: FindingSourceKind;
  identity: StableFindingIdentity;
  contentKey: string;
};

type WorkingGroup = {
  members: NormalizedFusionSource[];
};

type StableGroupIdentity = {
  groupAnchor: string;
  mergeAnchor: string;
};

type CanonicalBundle = {
  finding: Finding;
  sources: CanonicalFindingSources;
  duplicateGroup?: DuplicateFindingGroup;
};

const severityRank: Record<Finding["severity"], number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const confidenceRank: Record<Finding["confidence"], number> = {
  low: 0,
  medium: 1,
  high: 2,
  confirmed: 3,
};

export function fuseFindings(
  inputs: readonly FindingFusionInput[],
  options: FindingFusionOptions = {},
): FindingFusionResult {
  if (inputs.length > MAX_FINDING_FUSION_INPUTS) {
    throw new RangeError(
      `Finding fusion accepts at most ${MAX_FINDING_FUSION_INPUTS} inputs; received ${inputs.length}.`,
    );
  }
  const normalizedSources = inputs
    .map((input) => normalizeSource(input, options.repoRoot))
    .sort(compareSources);
  const groups: WorkingGroup[] = [];

  for (const source of normalizedSources) {
    const compatibleGroup = groups.find((group) => {
      const members = [...group.members, source];
      return group.members.every((member) =>
        areFindingIdentitiesCompatible(member.identity, source.identity, {
          ...(options.lineTolerance !== undefined
            ? { lineTolerance: options.lineTolerance }
            : {}),
        }),
      ) && deriveStableGroupIdentity(members) !== undefined;
    });
    if (compatibleGroup) {
      compatibleGroup.members.push(source);
      compatibleGroup.members.sort(compareSources);
    } else {
      groups.push({ members: [source] });
    }
  }

  const bundles = groups
    .map((group) => buildCanonicalBundle(group, options.repoRoot))
    .sort((left, right) =>
      compareText(left.sources.identity.key, right.sources.identity.key) ||
      compareText(left.finding.id, right.finding.id),
    );

  const sidecar = deepFreeze<FindingFusionSidecar>({
    canonicalSources: bundles.map((bundle) => bundle.sources),
    duplicateGroups: bundles
      .flatMap((bundle) => bundle.duplicateGroup ? [bundle.duplicateGroup] : [])
      .sort((left, right) => compareText(left.groupId, right.groupId)),
  });
  return {
    canonicalFindings: bundles.map((bundle) => bundle.finding),
    sidecar,
  };
}

function normalizeSource(
  input: FindingFusionInput,
  repoRoot: string | undefined,
): NormalizedFusionSource {
  const finding = input.finding;
  const sourceKind = input.sourceKind ?? inferSourceKind(finding);
  const sourceId = nonEmpty(input.sourceId) ?? nonEmpty(finding.id) ??
    nonEmpty(finding.fingerprint) ?? stableId(stableSerialize(finding), "source");
  const sourceLabel = nonEmpty(input.sourceLabel) ?? nonEmpty(finding.tool) ?? sourceKind;
  const identity = buildStableFindingIdentity(finding, {
    ...(repoRoot ? { repoRoot } : {}),
    ...(input.vulnerabilityClass ? { vulnerabilityClass: input.vulnerabilityClass } : {}),
    ...(input.sinkAnchor ? { sinkAnchor: input.sinkAnchor } : {}),
  });

  return {
    finding,
    sourceId,
    sourceLabel,
    sourceKind,
    identity,
    contentKey: stableId(stableSerialize(finding), "content"),
  };
}

function buildCanonicalBundle(
  group: WorkingGroup,
  repoRoot: string | undefined,
): CanonicalBundle {
  const members = [...group.members].sort(compareRepresentativeCandidates);
  const representative = members[0];
  if (!representative) {
    throw new Error("Finding fusion cannot canonicalize an empty group.");
  }
  const assessmentRepresentative = [...members].sort(compareAssessmentCandidates)[0];
  if (!assessmentRepresentative) {
    throw new Error("Finding fusion cannot assess an empty group.");
  }

  const vulnerabilityClass = representative.identity.vulnerabilityClass;
  const canonical = cloneFinding(representative.finding);
  canonical.severity = assessmentRepresentative.finding.severity;
  canonical.confidence = assessmentRepresentative.finding.confidence;

  const cwes = normalizeCweList(members.flatMap((member) => member.finding.cwe ?? []));
  if (cwes.length > 0) {
    canonical.cwe = cwes;
  } else {
    delete canonical.cwe;
  }

  const identifiers = mergeIdentifiers(members.map((member) => member.finding));
  if (identifiers) {
    canonical.identifiers = identifiers;
  } else {
    delete canonical.identifiers;
  }

  const expandedIdentity = buildStableFindingIdentity(canonical, {
    vulnerabilityClass,
    ...(repoRoot ? { repoRoot } : {}),
  });
  const stableGroupIdentity = deriveStableGroupIdentity(members);
  if (!stableGroupIdentity) {
    throw new Error("Finding fusion group does not have a stable common identity anchor.");
  }
  const { groupAnchor: stableGroupAnchor, mergeAnchor } = stableGroupIdentity;
  const identity: StableFindingIdentity = {
    ...expandedIdentity,
    id: stableId(stableGroupAnchor, "identity"),
    key: canonicalIdentityKey(stableGroupAnchor, expandedIdentity),
    mergeAnchor,
    groupAnchor: stableGroupAnchor,
  };
  canonical.id = stableId(`canonical|${stableGroupAnchor}`, "finding");
  canonical.fingerprint = stableId(`canonical|${stableGroupAnchor}`, "fp");

  const sources = members
    .map(toFusedSource)
    .sort(compareFusedSources);
  const sourceIds = uniqueSorted(sources.map((source) => source.sourceId));
  const sourceLabels = uniqueSorted(sources.map((source) => source.sourceLabel));
  const scannerSourceIds = uniqueSorted(
    sources.filter((source) => source.sourceKind === "scanner").map((source) => source.sourceId),
  );
  const agentSourceIds = uniqueSorted(
    sources.filter((source) => source.sourceKind === "agent").map((source) => source.sourceId),
  );
  const canonicalSources: CanonicalFindingSources = {
    canonicalFindingId: canonical.id,
    canonicalFingerprint: canonical.fingerprint,
    identity,
    sourceIds,
    sourceLabels,
    scannerSourceIds,
    agentSourceIds,
    sources,
  };

  if (members.length === 1) {
    return { finding: canonical, sources: canonicalSources };
  }

  const groupKey = sources
    .map((source) => `${source.sourceKind}:${source.sourceLabel}:${source.sourceId}:${source.fingerprint}`)
    .join("|");
  return {
    finding: canonical,
    sources: canonicalSources,
    duplicateGroup: {
      groupId: stableId(`${identity.key}|${groupKey}`, "duplicate-group"),
      canonicalFindingId: canonical.id,
      reason: identity.kind === "dependency"
        ? "matching-package-advisory"
        : "compatible-repository-sink",
      sourceIds,
      sourceLabels,
    },
  };
}

function deriveStableGroupIdentity(
  members: readonly NormalizedFusionSource[],
): StableGroupIdentity | undefined {
  const first = members[0]?.identity;
  if (!first) {
    return undefined;
  }
  if (members.some((member) =>
    member.identity.kind !== first.kind ||
    member.identity.category !== first.category ||
    member.identity.vulnerabilityClass !== first.vulnerabilityClass
  )) {
    return undefined;
  }

  const identities = members.map((member) => member.identity);
  if (first.kind === "dependency") {
    const packageAnchors = identities.map(dependencyPackageAnchor);
    const commonAdvisory = commonValues(
      identities.map((identity) => identity.dependency?.advisoryIds ?? []),
    ).sort(compareAdvisoryIdentifiers)[0];
    const packageAnchor = packageAnchors[0];
    const hasConcreteCommonPackage = packageAnchor !== undefined &&
      packageAnchors.every((candidate) => candidate === packageAnchor);
    if (!hasConcreteCommonPackage || !commonAdvisory) {
      return members.length === 1
        ? isolatedDependencyIdentity(members[0])
        : undefined;
    }
    const mergeAnchor = `advisory:${commonAdvisory}`;
    return {
      mergeAnchor,
      groupAnchor: [
        "dependency",
        first.category,
        first.vulnerabilityClass,
        packageAnchor,
        mergeAnchor,
      ].join("|"),
    };
  }

  const locationPaths = uniqueSorted(
    identities.map((identity) => identity.location?.path ?? "unlocated"),
  );
  if (locationPaths.length !== 1) {
    return undefined;
  }
  const isLocated = identities.every((identity) => identity.location !== undefined);
  const isUnlocated = identities.every((identity) => identity.location === undefined);
  if (!isLocated && !isUnlocated) {
    return undefined;
  }
  const locationAnchor = isLocated
    ? repositoryLocationAnchor(identities)
    : "unlocated";
  if (!locationAnchor) {
    return undefined;
  }
  const commonSink = preferredCommonSinkAnchor(commonValues(
    identities.map((identity) => identity.sinkAnchors),
  ));
  const commonContent = commonAnchors(identities, "content:")[0];
  const commonFingerprint = commonAnchors(identities, "fingerprint:")[0];
  const mergeAnchor = isLocated
    ? commonSink ?? commonContent
    : commonContent ?? commonFingerprint;
  if (!mergeAnchor) {
    return undefined;
  }
  return {
    mergeAnchor,
    groupAnchor: [
      "repository",
      first.category,
      first.vulnerabilityClass,
      locationAnchor,
      mergeAnchor,
    ].join("|"),
  };
}

function repositoryLocationAnchor(
  identities: readonly StableFindingIdentity[],
): string | undefined {
  const path = identities[0]?.location?.path;
  if (!path || identities.some((identity) => identity.location?.path !== path)) {
    return undefined;
  }
  const startLines = identities.flatMap((identity) =>
    identity.location?.startLine !== undefined
      ? [identity.location.startLine]
      : []
  );
  if (startLines.length === 0) {
    return `${path}:unranged`;
  }
  if (startLines.length !== identities.length) {
    return undefined;
  }
  const endLines = identities.map((identity) =>
    identity.location?.endLine ?? identity.location?.startLine
  );
  if (endLines.some((line) => line === undefined)) {
    return undefined;
  }
  const overlapStart = Math.max(...startLines);
  const overlapEnd = Math.min(...endLines as number[]);
  if (overlapStart > overlapEnd) {
    return undefined;
  }
  return `${path}:line-${overlapStart}`;
}

function dependencyPackageAnchor(identity: StableFindingIdentity): string | undefined {
  const dependency = identity.dependency;
  if (
    !dependency?.ecosystem.trim() ||
    !dependency.name.trim() ||
    !dependency.installedVersion?.trim()
  ) {
    return undefined;
  }
  return `${dependency.ecosystem}:${dependency.name}@${dependency.installedVersion}`;
}

function isolatedDependencyIdentity(
  source: NormalizedFusionSource | undefined,
): StableGroupIdentity | undefined {
  if (!source) {
    return undefined;
  }
  const isolatedAnchor = stableId(stableSerialize({
    sourceId: source.sourceId,
    findingId: source.finding.id,
    fingerprint: source.finding.fingerprint,
    contentKey: source.contentKey,
    identityKey: source.identity.key,
  }), "anchor");
  const mergeAnchor = `isolated:${isolatedAnchor}`;
  return {
    mergeAnchor,
    groupAnchor: [
      "dependency",
      source.identity.category,
      source.identity.vulnerabilityClass,
      mergeAnchor,
    ].join("|"),
  };
}

function commonAnchors(
  identities: readonly StableFindingIdentity[],
  prefix: string,
): string[] {
  return commonValues(
    identities.map((identity) =>
      identity.exactAnchors.filter((anchor) => anchor.startsWith(prefix))
    ),
  );
}

function commonValues(values: readonly (readonly string[])[]): string[] {
  const first = values[0];
  if (!first) {
    return [];
  }
  return uniqueSorted(
    first.filter((value) =>
      values.slice(1).every((candidates) => candidates.includes(value))
    ),
  );
}

function preferredCommonSinkAnchor(anchors: readonly string[]): string | undefined {
  return anchors.find((anchor) => anchor.startsWith("sink-explicit:")) ??
    anchors.find((anchor) => anchor.startsWith("sink-code:")) ??
    anchors[0];
}

function compareAdvisoryIdentifiers(left: string, right: string): number {
  return advisoryIdentifierRank(left) - advisoryIdentifierRank(right) ||
    compareText(left, right);
}

function advisoryIdentifierRank(value: string): number {
  if (value.startsWith("CVE-")) {
    return 0;
  }
  if (value.startsWith("GHSA-")) {
    return 1;
  }
  return 2;
}

function canonicalIdentityKey(
  stableGroupAnchor: string,
  identity: StableFindingIdentity,
): string {
  return [
    stableGroupAnchor,
    `cwes:${identity.cwes.join(",")}`,
    `exact:${identity.exactAnchors.join(",")}`,
    `sink:${identity.sinkAnchors.join(",")}`,
  ].join("|");
}

function inferSourceKind(finding: Finding): FindingSourceKind {
  if (finding.agent?.source === "scanner-backed") {
    return "scanner";
  }
  if (finding.agent || /\bagent\b/iu.test(finding.tool)) {
    return "agent";
  }
  return "scanner";
}

function compareSources(
  left: NormalizedFusionSource,
  right: NormalizedFusionSource,
): number {
  return (
    compareText(left.identity.key, right.identity.key) ||
    sourceKindRank(left.sourceKind) - sourceKindRank(right.sourceKind) ||
    compareText(left.sourceLabel, right.sourceLabel) ||
    compareText(left.sourceId, right.sourceId) ||
    compareText(left.finding.id, right.finding.id) ||
    compareText(left.finding.fingerprint, right.finding.fingerprint) ||
    compareText(left.contentKey, right.contentKey)
  );
}

function compareRepresentativeCandidates(
  left: NormalizedFusionSource,
  right: NormalizedFusionSource,
): number {
  return (
    sourceKindRank(left.sourceKind) - sourceKindRank(right.sourceKind) ||
    specificityScore(right.finding) - specificityScore(left.finding) ||
    severityRank[right.finding.severity] - severityRank[left.finding.severity] ||
    confidenceRank[right.finding.confidence] - confidenceRank[left.finding.confidence] ||
    compareSources(left, right)
  );
}

function compareAssessmentCandidates(
  left: NormalizedFusionSource,
  right: NormalizedFusionSource,
): number {
  return (
    severityRank[right.finding.severity] - severityRank[left.finding.severity] ||
    confidenceRank[right.finding.confidence] - confidenceRank[left.finding.confidence] ||
    sourceKindRank(left.sourceKind) - sourceKindRank(right.sourceKind) ||
    specificityScore(right.finding) - specificityScore(left.finding) ||
    compareSources(left, right)
  );
}

function compareFusedSources(left: FusedFindingSource, right: FusedFindingSource): number {
  return (
    sourceKindRank(left.sourceKind) - sourceKindRank(right.sourceKind) ||
    compareText(left.sourceLabel, right.sourceLabel) ||
    compareText(left.sourceId, right.sourceId) ||
    compareText(left.findingId, right.findingId) ||
    compareText(left.fingerprint, right.fingerprint) ||
    compareText(left.contentDigest, right.contentDigest)
  );
}

function sourceKindRank(value: FindingSourceKind): number {
  return value === "scanner" ? 0 : 1;
}

function specificityScore(finding: Finding): number {
  return (
    (finding.location?.file ? 2 : 0) +
    (finding.location?.startLine ? 2 : 0) +
    (finding.location?.endLine ? 1 : 0) +
    (finding.ruleId ? 1 : 0) +
    (finding.package ? 2 : 0) +
    (finding.cwe?.length ?? 0) +
    advisoryIdentifiers(finding).length * 2
  );
}

function toFusedSource(source: NormalizedFusionSource): FusedFindingSource {
  return {
    sourceId: source.sourceId,
    sourceLabel: source.sourceLabel,
    sourceKind: source.sourceKind,
    findingId: source.finding.id,
    fingerprint: source.finding.fingerprint,
    identityId: source.identity.id,
    contentDigest: source.contentKey,
    identity: deepFreeze(cloneIdentity(source.identity)),
    rawFinding: deepFreeze(cloneFinding(source.finding)),
  };
}

function mergeIdentifiers(
  findings: readonly Finding[],
): Finding["identifiers"] | undefined {
  const cve = uniqueSorted(
    findings.flatMap((finding) => finding.identifiers?.cve ?? [])
      .map(normalizeAdvisoryIdentifier)
      .filter(Boolean),
  );
  const ghsa = uniqueSorted(
    findings.flatMap((finding) => finding.identifiers?.ghsa ?? [])
      .map(normalizeAdvisoryIdentifier)
      .filter(Boolean),
  );
  const osv = uniqueSorted(
    findings.flatMap((finding) => finding.identifiers?.osv ?? [])
      .map(normalizeAdvisoryIdentifier)
      .filter(Boolean),
  );
  if (cve.length === 0 && ghsa.length === 0 && osv.length === 0) {
    return undefined;
  }
  return {
    ...(cve.length > 0 ? { cve } : {}),
    ...(ghsa.length > 0 ? { ghsa } : {}),
    ...(osv.length > 0 ? { osv } : {}),
  };
}

function cloneFinding(finding: Finding): Finding {
  return structuredClone(finding);
}

function cloneIdentity(identity: StableFindingIdentity): StableFindingIdentity {
  return {
    ...identity,
    cwes: [...identity.cwes],
    exactAnchors: [...identity.exactAnchors],
    sinkAnchors: [...identity.sinkAnchors],
    ...(identity.location ? { location: { ...identity.location } } : {}),
    ...(identity.dependency
      ? {
          dependency: {
            ...identity.dependency,
            advisoryIds: [...identity.dependency.advisoryIds],
          },
        }
      : {}),
  };
}

function deepFreeze<T>(value: T, seen = new WeakSet<object>()): T {
  if (value && typeof value === "object") {
    const object = value as object;
    if (seen.has(object)) {
      return value;
    }
    seen.add(object);
    if (!Object.isFrozen(object)) {
      Object.freeze(object);
    }
    for (const child of Object.values(value as Record<string, unknown>)) {
      deepFreeze(child, seen);
    }
  }
  return value;
}

function uniqueSorted(values: readonly string[]): string[] {
  return [...new Set(values)].sort(compareText);
}

function nonEmpty(value: string | undefined): string | undefined {
  const normalized = value?.trim();
  return normalized || undefined;
}

function stableSerialize(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(stableSerialize).join(",")}]`;
  }
  const record = value as Record<string, unknown>;
  const entries = Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableSerialize(record[key])}`);
  return `{${entries.join(",")}}`;
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
