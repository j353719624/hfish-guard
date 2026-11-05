const fs = require('fs');
const s = fs.readFileSync('fpk/app/ui/index.html', 'utf8');
const js = s.slice(s.indexOf('<script>') + 8, s.lastIndexOf('</scr' + 'ipt>'));
const lines = js.split('\n');
let d = 0;
const marks = [];
for (let i = 0; i < lines.length; i++) {
  let inS = null;
  for (let j = 0; j < lines[i].length; j++) {
    const c = lines[i][j];
    if (inS === 'line') { if (c === '\n') inS = null; continue; }
    if (inS === "'" || inS === '"') {
      if (c === '\\') { j++; continue; }
      if (c === inS) inS = null;
      continue;
    }
    if (c === '/' && lines[i][j + 1] === '/') break;
    if (c === "'" || c === '"') { inS = c; continue; }
    if (c === '(') d++;
    if (c === ')') { d--; if (d < 0) { console.log('多出 ) 于 JS 行', i + 1); process.exit(0); } }
  }
  if (i % 20 === 0) marks.push('L' + (i + 1) + '=' + d);
}
console.log('深度轨迹:', marks.join(' '));
console.log('最终深度:', d);
