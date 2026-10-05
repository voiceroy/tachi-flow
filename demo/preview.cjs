// Cut a ~30 s preview from tachi-flow-demo.mp4: short scenes, cropped
// above the long burned-in captions, with short captions of its own.
const { execFileSync } = require('child_process');
const path = require('path');

const src = path.join(__dirname, 'tachi-flow-demo.mp4');
const out = path.join(__dirname, 'tachi-flow-preview.mp4');
const font = '/usr/share/fonts/inter/InterVariable.ttf';

// [start s in the full demo, length s, caption]
const scenes = [
  [0.4, 2.6, ''],
  [12.0, 2.8, 'Competing desks, bonded, with a public track record'],
  [27.2, 2.8, 'Every quote is signed by its desk'],
  [42.4, 3.2, 'Bitcoin → Tachi coins in minutes, not a week-long vault exit'],
  [57.4, 2.8, 'Big exits split across desks'],
  [71.8, 3.0, 'A real TAURUS vault, refunded with the quorum'],
  [76.0, 3.4, 'The desk verifies 5 of 7 validator co-signatures'],
  [84.4, 2.8, '…and pays the refund out now'],
  [96.2, 3.0, 'Collected at maturity, on-chain'],
  [105.6, 3.8, ''],
];

const esc = (t) => t.replace(/\\/g, '\\\\').replace(/'/g, "’").replace(/:/g, '\\:');
const parts = scenes.map(([s, len, cap], i) => {
  // 1280x720 window over the page, clear of the demo's caption bar.
  let f = `[0:v]trim=start=${s}:duration=${len},setpts=PTS-STARTPTS,crop=1280:720:80:28`;
  if (cap) {
    f += `,drawtext=fontfile=${font}:text='${esc(cap)}':fontsize=34:fontcolor=white:` +
      `box=1:boxcolor=0x080a0eE8:boxborderw=18:x=(w-tw)/2:y=h-th-48`;
  }
  f += `,fade=t=in:st=0:d=0.2,fade=t=out:st=${(len - 0.2).toFixed(2)}:d=0.2[v${i}]`;
  return f;
});
const filter = parts.join(';') + ';' + scenes.map((_, i) => `[v${i}]`).join('') +
  `concat=n=${scenes.length}:v=1:a=0,format=yuv420p[out]`;

execFileSync('ffmpeg', ['-v', 'error', '-y', '-i', src, '-filter_complex', filter, '-map', '[out]',
  '-c:v', 'libx264', '-preset', 'slow', '-crf', '19', '-r', '30', '-movflags', '+faststart', out], { stdio: 'inherit' });
const secs = execFileSync('ffprobe', ['-v', 'error', '-show_entries', 'format=duration', '-of', 'csv=p=0', out]).toString().trim();
console.log(JSON.stringify({ out, seconds: Number(secs) }));
