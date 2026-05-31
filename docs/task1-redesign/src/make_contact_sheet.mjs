import fs from "node:fs";
import path from "node:path";
import sharp from "file:///C:/Users/whent/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/sharp/lib/index.js";

const dir = "scratch/previews-pptx";
const files = fs.readdirSync(dir).filter((f) => f.endsWith(".png")).sort();
const thumbW = 480;
const thumbH = 270;
const gap = 20;
const labelH = 34;
const cols = 3;
const rows = Math.ceil(files.length / cols);
const bg = { r: 248, g: 250, b: 252, alpha: 1 };
const composites = [];

for (let i = 0; i < files.length; i += 1) {
  const file = path.join(dir, files[i]);
  const x = (i % cols) * (thumbW + gap) + gap;
  const y = Math.floor(i / cols) * (thumbH + labelH + gap) + gap;
  const img = await sharp(file).resize(thumbW, thumbH, { fit: "contain", background: bg }).png().toBuffer();
  composites.push({ input: img, left: x, top: y });
  const label = files[i].replace(".png", "");
  const svg = `<svg width="${thumbW}" height="${labelH}" xmlns="http://www.w3.org/2000/svg"><text x="0" y="24" font-family="Arial" font-size="18" fill="#64748B">${label}</text></svg>`;
  composites.push({ input: Buffer.from(svg), left: x, top: y + thumbH + 6 });
}

await sharp({
  create: {
    width: cols * (thumbW + gap) + gap,
    height: rows * (thumbH + labelH + gap) + gap,
    channels: 4,
    background: bg,
  },
})
  .composite(composites)
  .png()
  .toFile("scratch/pptx-preview-contact-sheet.png");

console.log("scratch/pptx-preview-contact-sheet.png");
