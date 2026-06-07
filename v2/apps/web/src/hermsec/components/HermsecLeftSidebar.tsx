import { FolderIcon, ListChecksIcon, NewThreadIcon, SearchIcon, SettingsIcon } from "~/lib/icons";
import { HermsecLogo } from "~/components/HermsecLogo";
import {
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "~/components/ui/sidebar";
import { cn } from "~/lib/utils";
import type { HermsecMainView } from "../types";

type HermsecLeftSidebarProps = {
  activeView: HermsecMainView;
  onSelectView: (view: HermsecMainView) => void;
  onNewChat: () => void;
};

const NAV_ITEMS: Array<{
  id: HermsecMainView;
  label: string;
  icon: typeof NewThreadIcon;
}> = [
  { id: "chat", label: "New chat", icon: NewThreadIcon },
  { id: "search", label: "Search", icon: SearchIcon },
  { id: "automation", label: "Automations", icon: ListChecksIcon },
  { id: "projects", label: "Projects", icon: FolderIcon },
];

export function HermsecLeftSidebar({ activeView, onSelectView, onNewChat }: HermsecLeftSidebarProps) {
  return (
    <>
      <SidebarHeader className="h-10 shrink-0 border-b border-[color:var(--app-surface-divider)] px-2">
        <div className="flex h-full items-center gap-2">
          <HermsecLogo aria-label="Hermsec V2" className="size-4 text-foreground/85" />
          <span className="text-[11px] font-medium tracking-wide text-foreground/75">Hermsec</span>
        </div>
      </SidebarHeader>

      <SidebarContent className="gap-0 px-1.5 py-2">
        <SidebarGroup className="p-0">
          <SidebarMenu>
            {NAV_ITEMS.map((item) => {
              const Icon = item.icon;
              const isActive =
                item.id === "chat" ? activeView === "chat" : activeView === item.id;
              return (
                <SidebarMenuItem key={item.id}>
                  <SidebarMenuButton
                    isActive={isActive}
                    className={cn(
                      "h-7 gap-2 rounded-md px-2 text-[length:var(--app-font-size-ui,12px)]",
                      "text-muted-foreground hover:text-foreground data-active:text-foreground",
                    )}
                    onClick={() => {
                      if (item.id === "chat") {
                        onNewChat();
                      }
                      onSelectView(item.id);
                    }}
                  >
                    <Icon className="size-3.5 shrink-0 opacity-70" />
                    <span className="truncate">{item.label}</span>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              );
            })}
          </SidebarMenu>
        </SidebarGroup>
      </SidebarContent>

      <SidebarFooter className="border-t border-[color:var(--app-surface-divider)] p-1.5">
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton
              isActive={activeView === "settings"}
              className="h-7 gap-2 rounded-md px-2 text-[length:var(--app-font-size-ui,12px)]"
              onClick={() => onSelectView("settings")}
            >
              <SettingsIcon className="size-3.5 shrink-0 opacity-70" />
              <span>Settings</span>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarFooter>
    </>
  );
}
