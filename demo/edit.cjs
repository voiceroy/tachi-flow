// Cut the waits out of raw.webm and encode tachi-flow-demo.mp4.
// Long cuts get a short "skipped N min" marker so the jump is honest.
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const dir = __dirname;
const raw = path.join(dir, 'raw.webm');
const out = path.join(dir, 'tachi-flow-demo.mp4');
const cuts = JSON.parse(fs.readFileSync(path.join(dir, 'cuts.json'), 'utf8'));
const dur = parseFloat(execFileSync('ffprobe', ['-v', 'error', '-show_entries', 'format=duration', '-of', 'csv=p=0', raw]).toString());

// Keep a little of each wait so the screen change is visible.
const PAD = 0.4;
const keep = [];
// Skip the page load before the title card is up.
let from = 1.75;
const markers = [];
for (const [a, b] of cuts) {
  const s = a + PAD, e = b - PAD;
  if (e - s < 1) continue;
  keep.push([from, s]);
  const outAt = keep.reduce((t, [x, y]) => t + (y - x), 0);
  if (e - s > 20) markers.push([outAt, Math.round((e - s) / 60 * 10) / 10]);
  from = e;
}
keep.push([from, dur]);

const parts = keep.map(([a, b], i) => `[0:v]trim=start=${a.toFixed(3)}:end=${b.toFixed(3)},setpts=PTS-STARTPTS[v${i}]`);
let filter = parts.join(';') + ';' + keep.map((_, i) => `[v${i}]`).join('') + `concat=n=${keep.length}:v=1:a=0[cat]`;
const font = '/usr/share/fonts/inter/InterVariable.ttf';
let last = '[cat]';
markers.forEach(([t, mins], i) => {
  const label = `skipped ~${mins} min waiting for regtest blocks`;
  filter += `;${last}drawtext=fontfile=${font}:text='${label}':fontsize=26:fontcolor=0xf4c14e:box=1:boxcolor=0x080a0eE6:boxborderw=14:x=(w-tw)/2:y=36:enable='between(t,${t.toFixed(2)},${(t + 3).toFixed(2)})'[m${i}]`;
  last = `[m${i}]`;
});
filter += `;${last}format=yuv420p[out]`;

execFileSync('ffmpeg', ['-v', 'error', '-y', '-i', raw, '-filter_complex', filter, '-map', '[out]',
  '-c:v', 'libx264', '-preset', 'slow', '-crf', '20', '-r', '30', '-movflags', '+faststart', out], { stdio: 'inherit' });
const outDur = execFileSync('ffprobe', ['-v', 'error', '-show_entries', 'format=duration', '-of', 'csv=p=0', out]).toString().trim();
console.log(JSON.stringify({ out, seconds: Number(outDur), cuts: keep.length - 1, markers }));
