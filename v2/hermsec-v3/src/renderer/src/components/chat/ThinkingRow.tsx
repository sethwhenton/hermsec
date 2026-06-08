import { AnimatePresence, motion } from "framer-motion";
import Spiral5x5 from "@/components/ui/Spiral5x5";

interface ThinkingRowProps {
  visible: boolean;
  status?: string;
}

export function ThinkingRow({ visible, status = "Thinking..." }: ThinkingRowProps) {
  return (
    <AnimatePresence>
      {visible && (
        <motion.div
          className="flex justify-start"
          initial={{ opacity: 0, y: 4 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -4 }}
          transition={{ duration: 0.15 }}
        >
          <div className="flex items-center gap-3 rounded-2xl border border-border bg-surface-elevated px-4 py-3">
            <Spiral5x5 glow size={18} gap={2} />
            <span className="text-xs text-muted">{status}</span>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
