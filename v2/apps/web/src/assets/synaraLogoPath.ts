// FILE: synaraLogoPath.ts
// Purpose: Compatibility exports for inherited Synara call sites.

import {
  HERMSEC_LOGO_KEYHOLE_PATH,
  HERMSEC_LOGO_OUTER_PATH,
} from "./hermsecLogoPath";

export const SYNARA_LOGO_PATHS = [HERMSEC_LOGO_OUTER_PATH, HERMSEC_LOGO_KEYHOLE_PATH] as const;
