const fs = require('fs');
const s = fs.readFileSync('fpk/app/ui/index.html', 'utf8');
const scriptStart = s.indexOf('<' + 'script>') + 8;
const scriptEnd = s.lastIndexOf('</' + 'scr' + 'ipt>');
const js = s.slice(scriptStart, scriptEnd);
const lines = js.split('\n');
let d = 0;
for (let i = 0; i < lines.length; i++) {
  let inS = null;
  for (let j = 0; j < lines[i].length; j++) {
    const c = lines[i][j];
    if (inS === "'" || inS === '"') {
      if (c === '\\') { j++; continue; }
      if (c === inS) inS = null;
      continue;
    }
    if (c === '/' && lines[i][j + 1] === '/') break;
    if (c === "'" || c === '"') { inS = c; continue; }
    if (c === '(') d++;
    if (c === ')') {
      d--;
      if (d < 0) { console.log('NEG at JS line', i + 1); process.exit(0); }
    }
  }
  if (i >= 345 && i <= 365) process.stdout.write((i + 1) + ':' + d + ' ');
  if (i === 365) console.log('');
}
console.log('Final:', d);
