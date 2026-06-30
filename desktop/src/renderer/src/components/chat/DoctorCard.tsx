import { motion } from "framer-motion";
import {
  AlertTriangle,
  Bug,
  CheckCircle2,
  ClipboardCheck,
  DatabaseZap,
  Globe2,
  KeyRound,
  Loader2,
  MinusCircle,
  PackageCheck,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  XCircle,
  type LucideIcon,
} from "lucide-react";
import { cn } from "@/lib/cn";
import type {
  DoctorCheck,
  DoctorConnectivityCheck,
  DoctorGroupSummary,
  DoctorProgressEvent,
  DoctorProgressStatus,
  DoctorRunResult,
  DoctorStatus,
} from "@/types/doctor";

interface DoctorCardProps {
  result?: DoctorRunResult;
  progress?: DoctorProgressEvent[];
  running?: boolean;
  error?: string;
}

const scannerRows: Array<{ id: string; label: string; icon: LucideIcon }> = [
  { id: "command-semgrep", label: "Semgrep", icon: Shield },
  { id: "command-gitleaks", label: "Gitleaks", icon: KeyRound },
  { id: "command-bandit", label: "Bandit", icon: Bug },
  { id: "command-osv-scanner", label: "OSV", icon: DatabaseZap },
  { id: "command-pip-audit", label: "pip-audit", icon: PackageCheck },
  { id: "command-pmg", label: "PMG", icon: ShieldAlert },
];

const scannerIds = new Set(scannerRows.map((scanner) => scanner.id));

const connectivityRows: Array<{ id: string; label: string; url: string }> = [
  { id: "github", label: "GitHub", url: "https://github.com" },
  { id: "npm", label: "npm", url: "https://registry.npmjs.org" },
  { id: "osv", label: "OSV", url: "https://api.osv.dev" },
  { id: "cisa-kev", label: "CISA KEV", url: "https://www.cisa.gov" },
  { id: "nvd", label: "NVD", url: "https://nvd.nist.gov" },
];

const statIcons: Record<DoctorGroupSummary["id"], LucideIcon> = {
  required: ClipboardCheck,
  scanners: ShieldCheck,
  internet: Globe2,
  providers: Server,
};

type DisplayStatus = DoctorProgressStatus;
type CardStatus = DoctorRunResult["status"] | "running";
type DisplayCheck = Omit<DoctorCheck, "status"> & {
  status: DisplayStatus;
};
type DisplayConnectivityCheck = Omit<DoctorConnectivityCheck, "status"> & {
  status: DisplayStatus;
};

export function DoctorCard({ result, progress = [], running = false, error }: DoctorCardProps) {
  const rawProgressById = latestProgressById(progress);
  const connectedProvider = hasConnectedProvider(result, rawProgressById);
  const visibleProgress = progress.filter((event) => !isProviderProgressNoise(event, connectedProvider));
  const progressById = latestProgressById(visibleProgress);
  const visibleChecks = result?.checks.filter((check) => !isProviderCheckNoise(check, connectedProvider));
  const groups = normalizeProviderGroup(result?.groups ?? buildLiveGroups(visibleProgress), connectedProvider);
  const required = groupById(groups, "required");
  const scanners = groupById(groups, "scanners");
  const internet = groupById(groups, "internet");
  const providers = groupById(groups, "providers");
  const live = running && !result;
  const blockers = result ? readinessBlockers(result, connectedProvider) : [];
  const cardStatus = displayCardStatus(groups, live, error, blockers.length);
  const statusTone = tone(
    cardStatus === "blocked" ? "fail" : cardStatus === "attention" ? "warn" : cardStatus,
  );
  const healthScore = liveHealthScore(groups, live);
  const generatedTime = result?.generatedAt ? formatTime(result.generatedAt) : "Live now";
  const attention = result
    ? mostImportantAttention({ ...result, checks: visibleChecks ?? result.checks })
    : mostImportantLiveAttention(visibleProgress, error);
  const internetReady = result ? internet?.status === "pass" : hasPassingInternet(progressById);
  const cliRunning = progressById.get("doctor-cli")?.status === "running";
  const visibleConnectivity = result?.connectivity ?? buildLiveConnectivity(progressById);
  const latestEvents = [...visibleProgress].slice(-3).reverse();

  return (
    <motion.div
      className="flex w-full justify-start"
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.2 }}
    >
      <div className="relative w-full max-w-[min(700px,96%)] overflow-hidden rounded-2xl border border-border/80 bg-surface-elevated/95 text-foreground shadow-[0_16px_48px_rgba(0,0,0,0.28)] backdrop-blur">
        <motion.div
          className={cn("absolute inset-x-0 top-0 h-px", statusTone.sweep, live ? "animate-pulse" : "")}
          initial={{ scaleX: 0, transformOrigin: "left" }}
          animate={{ scaleX: 1 }}
          transition={{ duration: 0.45, ease: "easeOut" }}
        />
        <div className="relative p-3.5 sm:p-4">
          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="text-sm font-semibold tracking-normal text-foreground">
                  {live ? "Doctor running" : result ? "Doctor complete" : "Doctor check"}
                </h2>
                <span className={cn("rounded-md border border-border bg-background/60 px-2 py-0.5 text-[11px]", statusTone.text)}>
                  {live ? "Checking" : statusLabel(cardStatus)}
                </span>
                <span className="text-[11px] text-muted-foreground">{generatedTime}</span>
              </div>
              <p className="mt-1 line-clamp-1 text-xs text-muted">
                Scanner readiness, one connected model provider, and internet reachability.
              </p>
            </div>
            <div className="shrink-0 text-right">
              <div className="text-2xl font-semibold leading-none tabular-nums text-foreground">{healthScore}%</div>
              <div className="mt-1 flex items-center justify-end gap-1.5 text-[10px] uppercase tracking-wide text-muted-foreground">
                <span
                  className={cn(
                    "h-1.5 w-1.5 rounded-full",
                    live ? "bg-foreground animate-pulse" : internetReady ? "bg-foreground" : statusTone.dot,
                  )}
                />
                readiness
              </div>
            </div>
          </div>

          <motion.div
            className="mt-3 grid grid-cols-2 gap-1.5 sm:grid-cols-4"
            initial="hidden"
            animate="show"
            variants={{
              hidden: {},
              show: { transition: { staggerChildren: 0.07, delayChildren: 0.1 } },
            }}
          >
            {[required, scanners, internet, providers].filter(isGroup).map((group, index) => (
              <SummaryStat
                key={group.id}
                group={group}
                first={index === 0}
                active={live && isGroupActive(progressById, group.id)}
              />
            ))}
          </motion.div>

          <div className="mt-3 grid gap-3 lg:grid-cols-[1.15fr_0.85fr]">
            <section className="overflow-hidden rounded-xl border border-border bg-background/45">
              <div className="flex items-center justify-between border-b border-border/70 px-3 py-1.5">
                <span className="text-xs font-medium text-muted">Scanner stack</span>
                <span className="text-[10px] uppercase tracking-wide text-muted-foreground">tools</span>
              </div>
              <div className="grid sm:grid-cols-2">
                {scannerRows.map((scanner, index) => (
                  <ScannerRow
                    key={scanner.id}
                    check={findDisplayCheck(visibleChecks, progressById, scanner.id, scanner.label, cliRunning)}
                    icon={scanner.icon}
                    index={index}
                  />
                ))}
              </div>
            </section>

            <section className="overflow-hidden rounded-xl border border-border bg-background/45">
              <div className="flex items-center justify-between border-b border-border/70 px-3 py-1.5">
                <span className="text-xs font-medium text-muted">Internet</span>
                <span className="text-[10px] uppercase tracking-wide text-muted-foreground">HTTPS</span>
              </div>
              <div className="grid grid-cols-2 gap-px bg-border/50">
                {visibleConnectivity.map((check) => (
                  <ConnectivityChip key={check.id} check={check} />
                ))}
              </div>
            </section>
          </div>

          {blockers.length > 0 ? (
            <div className="mt-3 overflow-hidden rounded-xl border border-border bg-background/45">
              <div className="flex items-center justify-between border-b border-border/70 px-3 py-1.5">
                <div className="flex items-center gap-2 text-xs font-medium text-muted">
                  <AlertTriangle className="h-3.5 w-3.5 text-muted-foreground" />
                  Readiness blockers
                </div>
                <span className="text-[10px] uppercase tracking-wide text-muted-foreground">
                  {blockers.length} item{blockers.length !== 1 ? "s" : ""}
                </span>
              </div>
              <div className="divide-y divide-border/60">
                {blockers.slice(0, 3).map((check) => (
                  <ReadinessBlockerRow key={check.id} check={check} />
                ))}
              </div>
            </div>
          ) : null}

          {attention ? (
            <motion.div
              className={cn(
                "mt-3 flex items-start gap-2 rounded-xl border px-3 py-2 text-xs",
                attention.status === "fail"
                  ? "border-danger/35 bg-danger/8 text-danger"
                  : "border-amber-400/35 bg-amber-400/8 text-amber-200",
              )}
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.45, duration: 0.18 }}
            >
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
              <div className="min-w-0">
                <div className="font-medium text-foreground">{attention.label}</div>
                <div className="mt-0.5 text-muted">{attention.message}</div>
                {attention.remediation ? (
                  <div className="mt-1 text-[11px] text-amber-200/90">{attention.remediation}</div>
                ) : null}
              </div>
            </motion.div>
          ) : null}

          {latestEvents.length > 0 ? (
            <div className="mt-3 overflow-hidden rounded-xl border border-border bg-background/35">
              <div className="flex items-center justify-between border-b border-border/70 px-3 py-1.5">
                <span className="text-xs font-medium text-muted">Latest checks</span>
                <span className="text-[10px] uppercase tracking-wide text-muted-foreground">
                  {live ? "updating" : "last run"}
                </span>
              </div>
              <div className="grid divide-y divide-border/60 sm:grid-cols-3 sm:divide-x sm:divide-y-0">
                {latestEvents.map((event, index) => (
                  <LiveEventRow key={`${event.id}-${event.at}-${index}`} event={event} />
                ))}
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </motion.div>
  );
}

function SummaryStat({
  group,
  first,
  active,
}: {
  group: DoctorGroupSummary;
  first: boolean;
  active?: boolean;
}) {
  const Icon = statIcons[group.id];
  const groupTone = tone(active ? "running" : group.status);
  return (
    <motion.div
      className={cn(
        "min-w-0 rounded-lg border border-border/70 bg-background/45 px-2.5 py-2",
        first ? "sm:border-l-0" : "",
      )}
      variants={{
        hidden: { opacity: 0, y: 6 },
        show: { opacity: 1, y: 0 },
      }}
      transition={{ duration: 0.18 }}
    >
      <div className="flex items-center justify-between gap-2">
        <Icon className={cn("h-3.5 w-3.5 shrink-0", groupTone.text)} />
        <StatusIcon status={active ? "running" : group.status} className="h-3.5 w-3.5 shrink-0" />
      </div>
      <div className="mt-1.5 truncate text-[11px] text-muted">{group.label}</div>
      <div className="mt-0.5 text-sm font-semibold tabular-nums text-foreground">
        {group.ready}<span className="text-muted-foreground">/{group.total}</span>
      </div>
    </motion.div>
  );
}

function ScannerRow({
  check,
  icon: Icon,
  index,
}: {
  check: DisplayCheck;
  icon: LucideIcon;
  index: number;
}) {
  const checkTone = tone(check.status);
  return (
    <motion.div
      className={cn(
        "grid grid-cols-[18px_1fr_auto_16px] items-center gap-2 border-border/70 px-3 py-1.5 text-xs",
        index % 2 === 0 ? "sm:border-r" : "",
        index < scannerRows.length - 2 ? "border-b" : index < scannerRows.length - 1 ? "border-b sm:border-b-0" : "",
      )}
      initial={{ opacity: 0, x: -6 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: 0.18 + index * 0.04, duration: 0.18 }}
    >
      <Icon className={cn("h-3.5 w-3.5", checkTone.text)} />
      <div className="min-w-0 truncate text-foreground">{displayScannerLabel(check)}</div>
      <span
        className={cn(
          "rounded-md border border-border/70 bg-white/[0.03] px-1.5 py-0.5 text-[10px] font-medium leading-4",
          checkTone.pill,
        )}
      >
        {shortStatus(check.status)}
      </span>
      <StatusIcon status={check.status} className="h-3.5 w-3.5" />
    </motion.div>
  );
}

function ConnectivityChip({ check }: { check: DisplayConnectivityCheck }) {
  const checkTone = tone(check.status);
  return (
    <div
      className="flex min-w-0 items-center gap-2 bg-background/45 px-3 py-2"
      title={`${check.label}: ${check.message}`}
    >
      <span
        className={cn(
          "h-2 w-2 shrink-0 rounded-full",
          checkTone.dot,
          check.status === "pass" || check.status === "running" ? "animate-pulse" : "",
        )}
      />
      <div className="min-w-0">
        <div className="truncate text-xs text-foreground">{check.label}</div>
        <div className={cn("text-[10px] tabular-nums", checkTone.text)}>
          {check.status === "running"
            ? "Checking"
            : typeof check.latencyMs === "number"
              ? `${check.latencyMs} ms`
              : "No reply"}
        </div>
      </div>
    </div>
  );
}

function LiveEventRow({ event }: { event: DoctorProgressEvent }) {
  return (
    <div className="grid min-w-0 grid-cols-[16px_1fr] items-center gap-2 px-3 py-2 text-xs">
      <StatusIcon status={event.status} className="h-3.5 w-3.5" />
      <div className="min-w-0">
        <div className="truncate text-foreground">{event.label}</div>
        <div className="truncate text-muted">{event.message}</div>
      </div>
    </div>
  );
}

function ReadinessBlockerRow({ check }: { check: DoctorCheck }) {
  const checkTone = tone(check.status);
  return (
    <div className="grid grid-cols-[18px_1fr_auto] items-start gap-2 px-3 py-2 text-xs">
      <StatusIcon status={check.status} className="mt-0.5 h-3.5 w-3.5" />
      <div className="min-w-0">
        <div className="truncate font-medium text-foreground">{check.label}</div>
        <div className="mt-0.5 line-clamp-2 text-muted">{check.message}</div>
        {check.remediation ? (
          <div className="mt-1 line-clamp-2 text-[11px] text-muted-foreground">{check.remediation}</div>
        ) : null}
      </div>
      <span className={cn("rounded-md px-2 py-0.5 text-[10px] font-medium leading-5", checkTone.pill)}>
        {shortStatus(check.status)}
      </span>
    </div>
  );
}

function StatusIcon({ status, className }: { status: DisplayStatus; className?: string }) {
  if (status === "running") return <Loader2 className={cn("animate-spin text-accent", className)} />;
  if (status === "pass") return <CheckCircle2 className={cn("text-success", className)} />;
  if (status === "warn") return <AlertTriangle className={cn("text-amber-400", className)} />;
  if (status === "fail") return <XCircle className={cn("text-danger", className)} />;
  return <MinusCircle className={cn("text-muted-foreground", className)} />;
}

function latestProgressById(progress: DoctorProgressEvent[]): Map<string, DoctorProgressEvent> {
  const byId = new Map<string, DoctorProgressEvent>();
  progress.forEach((event) => byId.set(event.id, event));
  return byId;
}

function findCheck(checks: DoctorCheck[], id: string, label: string): DoctorCheck {
  return (
    checks.find((check) => check.id === id) ?? {
      id,
      label,
      status: "skip",
      requirement: "optional",
      message: `${label} was not reported by Doctor.`,
    }
  );
}

function findDisplayCheck(
  checks: DoctorCheck[] | undefined,
  progressById: Map<string, DoctorProgressEvent>,
  id: string,
  label: string,
  cliRunning: boolean,
): DisplayCheck {
  const finalCheck = checks?.find((check) => check.id === id);
  if (finalCheck) return finalCheck;

  const progress = progressById.get(id);
  if (progress) {
    return {
      id,
      label: progress.label,
      status: progress.status,
      requirement: progress.requirement ?? "optional",
      message: progress.message,
    };
  }

  return {
    id,
    label,
    status: cliRunning ? "running" : "skip",
    requirement: "optional",
    message: cliRunning
      ? "Waiting for Hermsec CLI to return scanner readiness."
      : `${label} has not started yet.`,
  };
}

function buildLiveConnectivity(
  progressById: Map<string, DoctorProgressEvent>,
): DisplayConnectivityCheck[] {
  return connectivityRows.map((target) => {
    const progress = progressById.get(`connectivity-${target.id}`);
    if (!progress) {
      return {
        id: target.id,
        label: target.label,
        url: target.url,
        status: "skip",
        message: `Waiting to ping ${target.label}.`,
      };
    }

    return {
      id: target.id,
      label: progress.label,
      url: target.url,
      status: progress.status,
      latencyMs: progress.latencyMs,
      statusCode: progress.statusCode,
      message: progress.message,
    };
  });
}

function buildLiveGroups(progress: DoctorProgressEvent[]): DoctorGroupSummary[] {
  const latest = Array.from(latestProgressById(progress).values());
  return [
    buildLiveGroup("required", "Required", latest),
    buildLiveGroup("scanners", "Scanners", latest),
    buildLiveGroup("internet", "Internet", latest),
    buildLiveGroup("providers", "Providers", latest),
  ];
}

function buildLiveGroup(
  id: DoctorGroupSummary["id"],
  label: string,
  progress: DoctorProgressEvent[],
): DoctorGroupSummary {
  const checks = progress.filter((event) => event.groupId === id);
  const total = expectedLiveTotal(id, checks.length);
  const ready = checks.filter((event) => event.status === "pass").length;
  const failed = checks.filter((event) => event.status === "fail").length;
  const warned = checks.filter((event) => event.status === "warn").length;
  const skipped = checks.filter((event) => event.status === "skip").length;
  const active = checks.some((event) => event.status === "running");

  let status: DoctorStatus = "skip";
  if (failed > 0) {
    status = "fail";
  } else if (warned > 0 || active) {
    status = "warn";
  } else if (ready > 0 && ready >= total) {
    status = "pass";
  } else if (skipped > 0) {
    status = "warn";
  }

  return {
    id,
    label,
    ready,
    total,
    status,
    message: active ? `${ready}/${total} checking` : `${ready}/${total} ready`,
  };
}

function expectedLiveTotal(id: DoctorGroupSummary["id"], seen: number): number {
  if (id === "scanners") return scannerRows.length;
  if (id === "internet") return connectivityRows.length;
  if (id === "providers") return Math.max(1, seen);
  return Math.max(1, seen);
}

function liveHealthScore(groups: DoctorGroupSummary[], live: boolean): number {
  const total = groups.reduce((sum, group) => sum + group.total, 0);
  const ready = groups.reduce((sum, group) => sum + group.ready, 0);
  if (total === 0) return live ? 10 : 0;
  return Math.max(live ? 12 : 0, Math.min(98, Math.round((ready / total) * 100)));
}

function isGroupActive(
  progressById: Map<string, DoctorProgressEvent>,
  groupId: DoctorGroupSummary["id"],
): boolean {
  return Array.from(progressById.values()).some(
    (event) => event.groupId === groupId && event.status === "running",
  );
}

function hasPassingInternet(progressById: Map<string, DoctorProgressEvent>): boolean {
  return connectivityRows.some((target) => progressById.get(`connectivity-${target.id}`)?.status === "pass");
}

function mostImportantLiveAttention(
  progress: DoctorProgressEvent[],
  error?: string,
): DoctorCheck | undefined {
  if (error) {
    return {
      id: "doctor-error",
      label: "Doctor watchdog",
      status: "fail",
      requirement: "required",
      message: error,
      remediation: "Retry Doctor after checking the local scanner setup.",
    };
  }

  const issue = [...progress]
    .reverse()
    .find((event) => event.status === "fail" || event.status === "warn" || event.status === "skip");
  if (!issue || issue.status === "running") return undefined;
  return {
    id: issue.id,
    label: issue.label,
    status: issue.status,
    requirement: issue.requirement ?? "recommended",
    message: issue.message,
  };
}

function displayScannerLabel(check: Pick<DoctorCheck, "id" | "label">): string {
  if (check.id === "command-osv-scanner") return "OSV";
  if (check.id === "command-pmg") return "PMG";
  return check.label;
}

function mostImportantAttention(result: DoctorRunResult): DoctorCheck | undefined {
  const direct = result.checks.find((check) => check.status === "fail" || check.status === "warn");
  if (direct) return direct;
  const missingScanner = scannerRows
    .map((scanner) => findCheck(result.checks, scanner.id, scanner.label))
    .find((check) => check.status === "skip");
  if (missingScanner) return missingScanner;
  const connectivityIssue = result.connectivity.find((check) => check.status !== "pass");
  if (!connectivityIssue) return undefined;
  return {
    id: `connectivity-${connectivityIssue.id}`,
    label: connectivityIssue.label,
    status: connectivityIssue.status,
    requirement: "recommended",
    message: connectivityIssue.message,
    remediation: "Check the network connection or retry when the service is reachable.",
  };
}

function readinessBlockers(result: DoctorRunResult, connectedProvider: boolean): DoctorCheck[] {
  const byId = new Map<string, DoctorCheck>();

  for (const check of result.checks) {
    if (isProviderCheckNoise(check, connectedProvider)) continue;
    if (check.status === "fail" || check.status === "warn") {
      byId.set(check.id, check);
    }
  }

  for (const scanner of scannerRows) {
    const check = findCheck(result.checks, scanner.id, scanner.label);
    if (check.status === "skip") {
      byId.set(check.id, check);
    }
  }

  for (const check of result.connectivity) {
    if (check.status !== "pass") {
      byId.set(`connectivity-${check.id}`, {
        id: `connectivity-${check.id}`,
        label: check.label,
        status: check.status,
        requirement: "recommended",
        message: check.message,
        remediation:
          check.status === "fail"
            ? "Check the network connection or retry when the service is reachable."
            : "Hermsec can continue, but this source should be reviewed before relying on full online intelligence.",
      });
    }
  }

  return Array.from(byId.values()).sort((left, right) => blockerRank(left) - blockerRank(right));
}

function hasConnectedProvider(
  result: DoctorRunResult | undefined,
  progressById: Map<string, DoctorProgressEvent>,
): boolean {
  if (result?.groups.some((group) => group.id === "providers" && group.ready > 0)) return true;
  if (result?.checks.some((check) => check.id.startsWith("provider-") && check.status === "pass")) return true;
  return Array.from(progressById.values()).some(
    (event) => event.groupId === "providers" && event.status === "pass",
  );
}

function isProviderCheckNoise(check: DoctorCheck, connectedProvider: boolean): boolean {
  if (!connectedProvider) return check.id.startsWith("provider-env-") && check.status === "skip";
  if (!check.id.startsWith("provider-")) return false;
  if (check.status === "pass" || check.requirement === "required") return false;
  return true;
}

function isProviderProgressNoise(event: DoctorProgressEvent, connectedProvider: boolean): boolean {
  if (!connectedProvider) return event.id.startsWith("provider-env-") && event.status === "skip";
  if (event.groupId !== "providers") return false;
  return event.status !== "pass" && event.status !== "running";
}

function normalizeProviderGroup(
  groups: DoctorGroupSummary[],
  connectedProvider: boolean,
): DoctorGroupSummary[] {
  if (!connectedProvider) return groups;
  return groups.map((group) =>
    group.id === "providers"
      ? {
          ...group,
          ready: Math.max(1, group.ready),
          total: Math.max(1, Math.min(group.total, Math.max(1, group.ready))),
          status: "pass",
          message: "At least one model provider is connected.",
        }
      : group,
  );
}

function displayCardStatus(
  groups: DoctorGroupSummary[],
  live: boolean,
  error: string | undefined,
  blockerCount: number,
): CardStatus {
  if (live) return "running";
  if (error || groups.some((group) => group.status === "fail")) return "blocked";
  if (blockerCount > 0 || groups.some((group) => group.status === "warn" || group.status === "skip")) {
    return "attention";
  }
  return "ready";
}

function blockerRank(check: DoctorCheck): number {
  if (check.status === "fail") return 0;
  if (check.status === "warn") return 1;
  if (scannerIds.has(check.id)) return 2;
  return 3;
}

function groupById(
  groups: DoctorGroupSummary[],
  id: DoctorGroupSummary["id"],
): DoctorGroupSummary | undefined {
  return groups.find((group) => group.id === id);
}

function isGroup(group: DoctorGroupSummary | undefined): group is DoctorGroupSummary {
  return Boolean(group);
}

function statusLabel(status: CardStatus): string {
  if (status === "running") return "Running";
  if (status === "ready") return "Ready";
  if (status === "blocked") return "Blocked";
  return "Needs tools";
}

function shortStatus(status: DisplayStatus): string {
  if (status === "running") return "Checking";
  if (status === "pass") return "Ready";
  if (status === "warn") return "Warn";
  if (status === "fail") return "Fail";
  return "Missing";
}

function formatTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return date.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
}

function tone(status: DisplayStatus | "ready" | "attention" | "blocked") {
  if (status === "running") {
    return {
      text: "text-foreground",
      dot: "bg-foreground",
      pill: "text-foreground",
      sweep: "bg-[linear-gradient(90deg,transparent,rgba(255,255,255,0.55),transparent)]",
      hex: "#3b82f6",
    };
  }
  if (status === "pass" || status === "ready") {
    return {
      text: "text-foreground",
      dot: "bg-foreground",
      pill: "text-foreground",
      sweep: "bg-[linear-gradient(90deg,transparent,rgba(255,255,255,0.45),transparent)]",
      hex: "#22c55e",
    };
  }
  if (status === "fail" || status === "blocked") {
    return {
      text: "text-danger",
      dot: "bg-danger",
      pill: "bg-danger/14 text-danger",
      sweep: "bg-[linear-gradient(90deg,transparent,rgba(59,130,246,0.7),rgba(239,68,68,0.95),transparent)]",
      hex: "#ef4444",
    };
  }
  if (status === "warn" || status === "attention") {
    return {
      text: "text-amber-400",
      dot: "bg-amber-400",
      pill: "bg-amber-400/14 text-amber-300",
      sweep: "bg-[linear-gradient(90deg,transparent,rgba(59,130,246,0.85),rgba(251,191,36,0.95),transparent)]",
      hex: "#f59e0b",
    };
  }
  return {
    text: "text-muted-foreground",
    dot: "bg-muted-foreground",
    pill: "bg-white/7 text-muted",
    sweep: "bg-[linear-gradient(90deg,transparent,rgba(59,130,246,0.65),transparent)]",
    hex: "#71717a",
  };
}
