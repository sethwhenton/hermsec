// FILE: HermsecLogo.tsx
// Purpose: Render the Hermsec V2 mark as an inline SVG that follows theme foreground color.
// Layer: Shared app branding primitive

import { useId, type SVGProps } from "react";
import {
  HERMSEC_LOGO_KEYHOLE_CIRCLE,
  HERMSEC_LOGO_KEYHOLE_PATH,
  HERMSEC_LOGO_OUTER_PATH,
  HERMSEC_LOGO_VIEWBOX,
} from "~/assets/hermsecLogoPath";
import { cn } from "~/lib/utils";

type HermsecLogoMode = "theme" | "light" | "dark";

interface HermsecLogoProps extends SVGProps<SVGSVGElement> {
  mode?: HermsecLogoMode;
}

export function HermsecLogo({ className, mode = "theme", ...props }: HermsecLogoProps) {
  const ariaLabel = props["aria-label"];
  const maskId = useId().replace(/:/g, "");
  const fill = mode === "light" ? "#07080A" : mode === "dark" ? "#37E6EE" : "currentColor";

  return (
    <svg
      viewBox={HERMSEC_LOGO_VIEWBOX}
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden={ariaLabel ? undefined : true}
      {...props}
      className={cn("shrink-0 text-foreground", className)}
    >
      <defs>
        <mask id={maskId} maskUnits="userSpaceOnUse">
          <rect width="577" height="580" fill="white" />
          <circle
            cx={HERMSEC_LOGO_KEYHOLE_CIRCLE.cx}
            cy={HERMSEC_LOGO_KEYHOLE_CIRCLE.cy}
            r={HERMSEC_LOGO_KEYHOLE_CIRCLE.r}
            fill="black"
          />
          <path d={HERMSEC_LOGO_KEYHOLE_PATH} fill="black" />
        </mask>
      </defs>
      <path d={HERMSEC_LOGO_OUTER_PATH} fill={fill} mask={`url(#${maskId})`} />
    </svg>
  );
}
