import type { CSSProperties } from "react";

const spiralOrder = [0, 1, 2, 3, 4, 9, 14, 19, 24, 23, 22, 21, 20, 15, 10, 5, 6, 7, 8, 13, 18, 17, 16, 11, 12];

interface Spiral5x5Props {
  glow?: boolean;
  tone?: "dark" | "light";
  className?: string;
  size?: number;
  gap?: number;
}

export default function Spiral5x5({
  glow = false,
  tone = "dark",
  className,
  size = 28,
  gap = 2,
}: Spiral5x5Props) {
  return (
    <>
      <style>{`
        .loader-spiral-5x5 {
          display: grid;
          grid-template-columns: repeat(5, 1fr);
          gap: var(--spiral-gap, 2px);
          width: var(--spiral-size, 28px);
          height: var(--spiral-size, 28px);
        }
        .loader-spiral-5x5 .dot {
          aspect-ratio: 1;
          border-radius: 50%;
          background-color: currentColor;
          opacity: 0.05;
          transform: scale(0.72);
          transform-origin: center;
          animation: spiral-5x5-chase 3s ease-in-out infinite;
          animation-delay: calc(var(--d) * 0.1s);
          will-change: opacity, transform;
        }
        .loader-spiral-5x5.glow .dot {
          animation-name: spiral-5x5-chase-glow;
          will-change: opacity, transform, box-shadow;
        }
        .loader-spiral-5x5.glow.light .dot {
          animation-name: spiral-5x5-chase-light-glow;
        }
        @keyframes spiral-5x5-chase {
          0%, 100% { opacity: 0.05; transform: scale(0.72); }
          12% { opacity: 0.6; transform: scale(0.95); }
          20%, 30% { opacity: 1; transform: scale(1.1); }
          50% { opacity: 0.05; transform: scale(0.72); }
        }
        @keyframes spiral-5x5-chase-glow {
          0%, 100% { opacity: 0.05; transform: scale(0.72); box-shadow: 0 0 0 currentColor; }
          12% { opacity: 0.6; transform: scale(0.95); box-shadow: 0 0 3px currentColor; }
          20%, 30% { opacity: 1; transform: scale(1.1); box-shadow: 0 0 4px currentColor, 0 0 10px currentColor; }
          50% { opacity: 0.05; transform: scale(0.72); box-shadow: 0 0 2px currentColor; }
        }
        @keyframes spiral-5x5-chase-light-glow {
          0%, 100% { opacity: 0.05; transform: scale(0.72); box-shadow: 0 0 0 currentColor; }
          12% { opacity: 0.6; transform: scale(0.95); box-shadow: 0 0 1px rgb(0 0 0 / 0.2), 0 0 0 2px rgb(0 0 0 / 0.04); }
          20%, 30% { opacity: 1; transform: scale(1.1); box-shadow: 0 0 2px rgb(0 0 0 / 0.22), 0 0 0 4px rgb(0 0 0 / 0.05); }
          50% { opacity: 0.05; transform: scale(0.72); box-shadow: 0 0 1px rgb(0 0 0 / 0.12); }
        }
      `}</style>
      <div
        className={`loader-spiral-5x5 text-foreground ${glow ? "glow" : ""} ${tone === "light" ? "light" : ""} ${className ?? ""}`}
        style={{ "--spiral-size": `${size}px`, "--spiral-gap": `${gap}px` } as CSSProperties}
      >
        {Array.from({ length: 25 }).map((_, i) => (
          <div key={i} className="dot" style={{ "--d": spiralOrder.indexOf(i) } as CSSProperties} />
        ))}
      </div>
    </>
  );
}
