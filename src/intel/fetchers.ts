import type { IntelFetcher } from "./schema.js";
import { cisaKevFetcher } from "./sources/cisaKev.js";
import { githubAdvisoryFetcher } from "./sources/githubAdvisory.js";
import { nvdFetcher } from "./sources/nvd.js";
import { osvFetcher } from "./sources/osv.js";

export function defaultIntelFetchers(): IntelFetcher[] {
  return [cisaKevFetcher, osvFetcher, githubAdvisoryFetcher, nvdFetcher];
}
