// FILE: ChatEmptyStateHero.tsx
// Purpose: Render the centered empty-state hero for blank transcripts.
// Layer: Chat presentation
// Depends on: the caller-supplied project display name.

import { memo } from "react";
import { HermsecLogo } from "~/components/HermsecLogo";
import { HermsecQuickActions } from "~/hermsec/HermsecQuickActions";

export const ChatEmptyStateHero = memo(function ChatEmptyStateHero({
  projectName,
}: {
  projectName: string | undefined;
}) {
  return (
    <div className="flex flex-col items-center gap-5 select-none">
      <HermsecLogo aria-label="Hermsec V2 logo" className="size-10" />

      <div className="flex flex-col items-center gap-0.5">
        <h1 className="text-2xl font-semibold text-foreground/90">What should Hermsec investigate?</h1>
        {projectName && <span className="text-lg text-muted-foreground/40">{projectName}</span>}
      </div>

      <HermsecQuickActions />
    </div>
  );
});
