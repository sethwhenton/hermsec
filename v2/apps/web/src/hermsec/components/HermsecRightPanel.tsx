import { type CSSProperties, useMemo } from "react";
import { ExternalLinkIcon, PanelRightCloseIcon, XIcon } from "~/lib/icons";
import { IconButton } from "~/components/ui/icon-button";
import {
  Sidebar,
  SIDEBAR_OFFCANVAS_MOTION_CLASS,
  SidebarProvider,
  SidebarRail,
} from "~/components/ui/sidebar";
import { CHAT_SURFACE_HEADER_ROW_CLASS_NAME } from "~/components/chat/chatHeaderControls";
import { cn } from "~/lib/utils";
import type { HermsecReportPreview } from "../types";
import { MOCK_REPORTS } from "../mockData";

type HermsecRightPanelProps = {
  open: boolean;
  preview: HermsecReportPreview | null;
  onOpenChange: (open: boolean) => void;
  onClosePreview: () => void;
};

const RIGHT_PANEL_WIDTH = "28rem";

function resolvePreviewHtml(preview: HermsecReportPreview | null): string {
  if (!preview) return "";
  if (preview.html.trim()) return preview.html;
  const fallback = MOCK_REPORTS.find((report) => report.path === preview.path);
  return fallback?.html ?? MOCK_REPORTS[0]?.html ?? "";
}

export function HermsecRightPanel({
  open,
  preview,
  onOpenChange,
  onClosePreview,
}: HermsecRightPanelProps) {
  const html = useMemo(() => resolvePreviewHtml(preview), [preview]);

  return (
    <SidebarProvider
      defaultOpen={false}
      open={open}
      onOpenChange={onOpenChange}
      className="w-auto min-h-0 flex-none bg-transparent"
      style={{ "--sidebar-width": RIGHT_PANEL_WIDTH } as CSSProperties}
      data-sidebar-side="right"
    >
      <Sidebar
        side="right"
        collapsible="offcanvas"
        className={cn("text-foreground", SIDEBAR_OFFCANVAS_MOTION_CLASS)}
        gapClassName={SIDEBAR_OFFCANVAS_MOTION_CLASS}
        innerClassName="border-l border-[color:var(--app-surface-divider)] bg-background"
        transparentSurface
        resizable={{
          minWidth: 280,
          maxWidth: 640,
          storageKey: "hermsec:right-panel-width",
        }}
      >
        <div className="flex h-full min-h-0 flex-col">
          <div
            className={cn(
              CHAT_SURFACE_HEADER_ROW_CLASS_NAME,
              "shrink-0 border-b border-[color:var(--app-surface-divider)] px-2",
            )}
          >
            <div className="flex min-w-0 flex-1 items-center gap-2">
              <span className="truncate text-[11px] font-medium text-foreground/80">
                {preview?.title ?? "Report preview"}
              </span>
              {preview?.path ? (
                <span className="truncate text-[10px] text-muted-foreground/50">
                  {preview.path}
                </span>
              ) : null}
            </div>
            <div className="flex items-center gap-0.5">
              <IconButton
                label="Open externally"
                className="size-7 rounded-md text-muted-foreground/70"
                onClick={() => {
                  if (!preview?.path) return;
                  void window.desktopBridge?.showInFolder(preview.path);
                }}
              >
                <ExternalLinkIcon className="size-3.5" />
              </IconButton>
              <IconButton
                label="Close preview"
                className="size-7 rounded-md text-muted-foreground/70"
                onClick={onClosePreview}
              >
                <XIcon className="size-3.5" />
              </IconButton>
              <IconButton
                label="Collapse panel"
                className="size-7 rounded-md text-muted-foreground/70"
                onClick={() => onOpenChange(false)}
              >
                <PanelRightCloseIcon className="size-3.5" />
              </IconButton>
            </div>
          </div>

          <div className="min-h-0 flex-1 bg-background">
            {preview && html ? (
              <iframe
                title={preview.title}
                srcDoc={html}
                sandbox="allow-same-origin"
                className="h-full w-full border-0 bg-white"
              />
            ) : (
              <div className="flex h-full items-center justify-center px-6 text-center text-[11px] text-muted-foreground/55">
                Open a report from Automations or quick actions to preview HTML output here.
              </div>
            )}
          </div>
        </div>
        <SidebarRail placement="content-seam" />
      </Sidebar>
    </SidebarProvider>
  );
}
