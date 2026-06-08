import { Minus, Square, X } from "lucide-react";
import { getHermsecApi } from "@/lib/ipc";
import { cn } from "@/lib/cn";
import { HermsecLogo } from "@/components/branding/HermsecLogo";
import { Button } from "@/components/ui/Button";

const menuItems = ["File", "Edit", "View", "Help"];

export function TitleBar() {
  const api = getHermsecApi();

  return (
    <header className="drag-region flex h-9 shrink-0 items-center justify-between border-b border-border-subtle bg-background px-3">
      <div className="flex items-center gap-4">
        <div className="no-drag flex items-center gap-2">
          <HermsecLogo className="h-4 w-4 text-accent" aria-label="Hermsec" />
          <span className="text-xs font-medium tracking-wide text-muted">Hermsec</span>
        </div>
        <nav className="no-drag flex items-center gap-3">
          {menuItems.map((item) => (
            <button
              key={item}
              type="button"
              className="text-xs text-muted transition-colors hover:text-foreground"
            >
              {item}
            </button>
          ))}
        </nav>
      </div>
      <div className="no-drag flex items-center">
        <Button
          variant="ghost"
          size="icon"
          disabled={!api}
          onClick={() => api && void api.window.minimize()}
        >
          <Minus className="h-3.5 w-3.5" />
        </Button>
        <Button
          variant="ghost"
          size="icon"
          disabled={!api}
          onClick={() => api && void api.window.maximize()}
        >
          <Square className="h-3 w-3" />
        </Button>
        <Button
          variant="ghost"
          size="icon"
          disabled={!api}
          className={cn(!api && "opacity-30")}
          onClick={() => api && void api.window.close()}
        >
          <X className="h-3.5 w-3.5" />
        </Button>
      </div>
    </header>
  );
}
