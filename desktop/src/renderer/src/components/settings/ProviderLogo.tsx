import { useState } from "react";
import { cn } from "@/lib/cn";

interface ProviderLogoProps {
  name: string;
  logoUrl?: string;
  className?: string;
}

export function ProviderLogo({ name, logoUrl, className }: ProviderLogoProps) {
  const [failed, setFailed] = useState(false);
  const initial = name.trim().slice(0, 1).toUpperCase() || "?";

  return (
    <div
      className={cn(
        "flex h-8 w-8 shrink-0 items-center justify-center overflow-hidden rounded-md border border-white/80 bg-white text-xs font-semibold text-zinc-950 shadow-[inset_0_0_0_1px_rgba(0,0,0,0.08)]",
        className,
      )}
    >
      {logoUrl && !failed ? (
        <img
          src={logoUrl}
          alt=""
          className="h-5 w-5 object-contain"
          onError={() => setFailed(true)}
        />
      ) : (
        <span>{initial}</span>
      )}
    </div>
  );
}
