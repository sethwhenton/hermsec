import type { ReactNode } from "react";
import { cn } from "~/lib/utils";

type HermsecPageShellProps = {
  children: ReactNode;
  className?: string;
  maxWidthClassName?: string;
};

export function HermsecPageShell({
  children,
  className,
  maxWidthClassName = "max-w-[1120px]",
}: HermsecPageShellProps) {
  return (
    <div className="flex min-h-full min-w-0 justify-center overflow-y-auto px-8 py-10">
      <div
        className={cn("w-full", maxWidthClassName, className)}
        data-hermsec-page-content
      >
        {children}
      </div>
    </div>
  );
}
