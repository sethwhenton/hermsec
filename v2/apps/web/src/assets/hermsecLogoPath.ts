// FILE: hermsecLogoPath.ts
// Purpose: Shared SVG path data for the Hermsec V2 H/keyhole mark.

export const HERMSEC_LOGO_VIEWBOX = "0 0 577 580";

export const HERMSEC_LOGO_OUTER_PATH =
  "M116 40L238 114V260H339V114L461 40V530L339 456V342H238V456L116 530V40Z";

export const HERMSEC_LOGO_KEYHOLE_CIRCLE = {
  cx: 313,
  cy: 365,
  r: 51,
} as const;

export const HERMSEC_LOGO_KEYHOLE_PATH = "M278 411H346L386 566H238L278 411Z";
