import { motion } from "framer-motion";
import {
  Activity,
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
import type { CSSProperties } from "react";
import { HermsecLogo } from "@/components/branding/HermsecLogo";
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

const connectivityRows: Array<{ id: string; label: string; url: string }> = [
  { id: "github", label: "GitHub", url: "https://github.com" },
  { id: "npm", label: "npm", url: "https://registry.npmjs.org" },
  { id: "osv", label: "OSV", url: "https://api.osv.dev" },
  { id: "cisa-kev", label: "CISA KEV", url: "https://www.cisa.gov" },
  { id: "nvd", label: "NVD", url: "https://services.nvd.nist.gov" },
];

const statIcons: Record<DoctorGroupSummary["id"], LucideIcon> = {
  required: ClipboardCheck,
  scanners: ShieldCheck,
  internet: Globe2,
  providers: Server,
};

type DisplayStatus = DoctorProgressStatus;
type DisplayCheck = Omit<DoctorCheck, "status"> & {
  status: DisplayStatus;
};
type DisplayConnectivityCheck = Omit<DoctorConnectivityCheck, "status"> & {
  status: DisplayStatus;
};

export function DoctorCard({ result, progress = [], running = false, error }: DoctorCardProps) {
  const progressById = latestProgressById(progress);
  const groups = result?.groups ?? buildLiveGroups(progress);
  const required = groupById(groups, "required");
  const scanners = groupById(groups, "scanners");
  const internet = groupById(groups, "internet");
  const providers = groupById(groups, "providers");
  const live = running && !result;
  const cardStatus = result?.status ?? (error ? "blocked" : live ? "running" : "attention");
  const statusTone = tone(
    cardStatus === "blocked" ? "fail" : cardStatus === "attention" ? "warn" : cardStatus,
  );
  const healthScore = result?.healthScore ?? liveHealthScore(groups, live);
  const ringStyle = healthRingStyle(healthScore, statusTone.hex);
  const generatedTime = result?.generatedAt ? formatTime(result.generatedAt) : "Live now";
  const attention = result ? mostImportantAttention(result) : mostImportantLiveAttention(progress, error);
  const internetReady = result ? internet?.status === "pass" : hasPassingInternet(progressById);
  const cliRunning = progressById.get("doctor-cli")?.status === "running";
  const visibleConnectivity = result?.connectivity ?? buildLiveConnectivity(progressById);
  const latestEvents = [...progress].slice(-5).reverse();

  return (
    <motion.div
      className="flex w-full justify-start"
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.2 }}
    >
      <div className="relative max-w-[min(700px,96%)] overflow-hidden rounded-2xl border border-border/80 bg-[linear-gradient(180deg,rgba(24,24,27,0.96),rgba(13,13,16,0.96))] text-foreground shadow-[0_22px_70px_rgba(0,0,0,0.36)]">
        <motion.div
          className={cn("absolute inset-x-0 top-0 h-px", statusTone.sweep, live ? "animate-pulse" : "")}
          initial={{ scaleX: 0, transformOrigin: "left" }}
          animate={{ scaleX: 1 }}
          transition={{ duration: 0.9, ease: "easeOut" }}
        />
        <div className="absolute inset-x-0 top-0 h-16 bg-[radial-gradient(circle_at_12%_0%,rgba(59,130,246,0.16),transparent_42%)]" />
        <div className="relative p-4 sm:p-5">
          <div className="flex items-start justify-between gap-3">
            <div className="flex min-w-0 items-center gap-3">
              <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border border-accent/30 bg-accent/10 text-accent shadow-[0_0_24px_rgba(59,130,246,0.18)]">
                <HermsecLogo className="h-5 w-5" mode="dark" />
              </div>
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                  <h2 className="text-sm font-semibold tracking-normal text-foreground">
                    {live ? "Doctor running" : result ? "Doctor complete" : "Doctor stopped"}
                  </h2>
                  <span className="text-xs text-muted-foreground">{generatedTime}</span>
                </div>
                <p className="mt-0.5 truncate text-xs text-muted">
                  {live
                    ? "Streaming scanner, provider, and internet readiness"
                    : "Scanner tools, local paths, providers, and internet reachability"}
                </p>
              </div>
            </div>
            <div className="flex shrink-0 items-center gap-1.5 rounded-md border border-border/70 bg-background/45 px-2 py-1 text-xs text-muted">
              <span
                className={cn(
                  "h-1.5 w-1.5 rounded-full",
                  live ? "bg-accent animate-pulse" : internetReady ? "bg-success animate-pulse" : statusTone.dot,
                )}
              />
              <span>{live ? "Live" : internetReady ? "Online" : "Check"}</span>
            </div>
          </div>

          <div className="mt-5 grid gap-4 md:grid-cols-[170px_1fr]">
            <div className="flex items-center justify-center md:justify-start">
              <motion.div
                className="relative flex h-32 w-32 items-center justify-center rounded-full p-2"
                style={ringStyle}
                initial={{ rotate: -12, scale: 0.94 }}
                animate={{ rotate: 0, scale: 1 }}
                transition={{ duration: 0.5, ease: "easeOut" }}
              >
                <div className="flex h-full w-full flex-col items-center justify-center rounded-full border border-white/6 bg-background/90 shadow-inner">
                  <span className={cn("text-sm font-semibold", statusTone.text)}>
                    {live ? "Checking" : statusLabel(cardStatus === "running" ? "attention" : cardStatus)}
                  </span>
                  <span className="mt-1 text-2xl font-semibold tabular-nums text-foreground">
                    {healthScore}%
                  </span>
                  <span className="mt-1 text-[10px] uppercase tracking-wide text-muted-foreground">
                    readiness
                  </span>
                </div>
              </motion.div>
            </div>

            <motion.div
              className="grid grid-cols-2 gap-x-0 gap-y-3 sm:grid-cols-4"
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
          </div>

          {latestEvents.length > 0 ? (
            <div className="mt-4 overflow-hidden rounded-xl border border-border/70 bg-background/24">
              <div className="flex items-center justify-between border-b border-border/70 px-3 py-2">
                <div className="flex items-center gap-2 text-xs font-medium text-muted">
                  <Activity className="h-3.5 w-3.5 text-accent" />
                  Live checks
                </div>
                <span className="text-[10px] uppercase tracking-wide text-muted-foreground">
                  {live ? "Updating" : "Last run"}
                </span>
              </div>
              <div className="divide-y divide-border/60">
                {latestEvents.map((event, index) => (
                  <LiveEventRow key={`${event.id}-${event.at}-${index}`} event={event} />
                ))}
              </div>
            </div>
          ) : null}

          <div className="mt-5 border-t border-border/70 pt-4">
            <div className="mb-2 text-xs font-medium text-muted">Scanner stack</div>
            <div className="overflow-hidden rounded-xl border border-border/70 bg-background/24">
              <div className="grid sm:grid-cols-2">
                {scannerRows.map((scanner, index) => (
                  <ScannerRow
                    key={scanner.id}
                    check={findDisplayCheck(result?.checks, progressById, scanner.id, scanner.label, cliRunning)}
                    icon={scanner.icon}
                    index={index}
                  />
                ))}
              </div>
            </div>
          </div>

          {attention ? (
            <motion.div
              className={cn(
                "mt-4 flex items-start gap-3 rounded-xl border px-3 py-2.5 text-xs",
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

          <div className="mt-5 border-t border-border/70 pt-4">
            <div className="mb-2 flex items-center justify-between gap-3">
              <span className="text-xs font-medium text-muted">Internet connectivity</span>
              <span className="text-[10px] uppercase tracking-wide text-muted-foreground">
                HTTPS checks
              </span>
            </div>
            <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
              {visibleConnectivity.map((check) => (
                <ConnectivityChip key={check.id} check={check} />
              ))}
            </div>
          </div>
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
        "min-w-0 px-3 text-center sm:border-l sm:border-border/70",
        first ? "sm:border-l-0" : "",
      )}
      variants={{
        hidden: { opacity: 0, y: 6 },
        show: { opacity: 1, y: 0 },
      }}
      transition={{ duration: 0.18 }}
    >
      <Icon className={cn("mx-auto h-5 w-5", groupTone.text)} />
      <div className="mt-2 truncate text-xs text-muted">{group.label}</div>
      <div className={cn("mt-1 text-base font-semibold tabular-nums", groupTone.text)}>
        {group.ready} / {group.total}
      </div>
      <StatusIcon status={active ? "running" : group.status} className="mx-auto mt-1 h-3.5 w-3.5" />
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
        "grid grid-cols-[22px_1fr_auto_18px] items-center gap-2 border-border/70 px-3 py-2.5 text-sm",
        index % 2 === 0 ? "sm:border-r" : "",
        index < scannerRows.length - 2 ? "border-b" : index < scannerRows.length - 1 ? "border-b sm:border-b-0" : "",
      )}
      initial={{ opacity: 0, x: -6 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: 0.18 + index * 0.04, duration: 0.18 }}
    >
      <Icon className={cn("h-4 w-4", checkTone.text)} />
      <div className="min-w-0 truncate text-foreground">{displayScannerLabel(check)}</div>
      <span
        className={cn(
          "rounded-md px-2 py-0.5 text-[11px] font-medium leading-5",
          checkTone.pill,
        )}
      >
        {shortStatus(check.status)}
      </span>
      <StatusIcon status={check.status} className="h-4 w-4" />
    </motion.div>
  );
}

function ConnectivityChip({ check }: { check: DisplayConnectivityCheck }) {
  const checkTone = tone(check.status);
  return (
    <div
      className="flex min-w-[108px] items-center gap-2 border-r border-border/70 pr-3 last:border-r-0"
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
        <div className={cn("text-[11px] tabular-nums", checkTone.text)}>
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
  const eventTone = tone(event.status);
  return (
    <div className="grid grid-cols-[18px_1fr_auto] items-center gap-2 px-3 py-2 text-xs">
      <StatusIcon status={event.status} className="h-3.5 w-3.5" />
      <div className="min-w-0">
        <div className="truncate text-foreground">{event.label}</div>
        <div className="truncate text-muted">{event.message}</div>
      </div>
      <span className={cn("rounded-md px-2 py-0.5 text-[10px] font-medium leading-5", eventTone.pill)}>
        {shortStatus(event.status)}
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

function groupById(
  groups: DoctorGroupSummary[],
  id: DoctorGroupSummary["id"],
): DoctorGroupSummary | undefined {
  return groups.find((group) => group.id === id);
}

function isGroup(group: DoctorGroupSummary | undefined): group is DoctorGroupSummary {
  return Boolean(group);
}

function statusLabel(status: DoctorRunResult["status"]): string {
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

function healthRingStyle(score: number, color: string): CSSProperties {
  const clamped = Math.max(0, Math.min(100, score));
  return {
    background: `conic-gradient(${color} ${clamped * 3.6}deg, rgba(255,255,255,0.08) 0deg)`,
  };
}

function tone(status: DisplayStatus | "ready" | "attention" | "blocked") {
  if (status === "running") {
    return {
      text: "text-accent",
      dot: "bg-accent",
      pill: "bg-accent/14 text-accent",
      sweep: "bg-[linear-gradient(90deg,transparent,rgba(59,130,246,0.95),rgba(20,184,166,0.85),transparent)]",
      hex: "#3b82f6",
    };
  }
  if (status === "pass" || status === "ready") {
    return {
      text: "text-success",
      dot: "bg-success",
      pill: "bg-success/14 text-success",
      sweep: "bg-[linear-gradient(90deg,transparent,rgba(59,130,246,0.9),rgba(34,197,94,0.95),transparent)]",
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
