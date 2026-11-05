const fs = require('fs');
const s = fs.readFileSync('fpk/app/ui/index.html', 'utf8');
const js = s.slice(s.indexOf('<script>') + 8, s.lastIndexOf('</scr' + 'ipt>'));
const lines = js.split('\n');
let d = 0;
for (let i = 0; i < lines.length; i++) {
  const line = lines[i];
  for (let j = 0; j < line.length; j++) {
    if (line[j] === '(') d++;
    if (line[j] === ')') d--;
  }
  if (d < 0) { console.log('多出 ) 于 JS 行', i + 1, ':', line.trim().slice(0, 80)); break; }
}
if (d > 0) {
  // 找到深度归零的位置之后输出上下文
  for (let i = 0; i < lines.length; i++) {
    const before = lines.slice(0, i + 1).join('\n');
    let dd = 0;
    for (const ch of before) { if (ch === '(') d++; if (ch === ')') d--; }
    // 计算每行结束时的深度
  }
  // 重新逐行找深度=1 持续不变的行
  let dd = 0;
  const marks = [];
  for (let i = 0; i < lines.length; i++) {
    for (const ch of lines[i]) { if (ch === '(') d++; if (ch === ')') d--; }
    if (i % 20 === 0) marks.push({ line: i + 1, depth: d });
  }
  console.log('每 20 行深度:', JSON.stringify(marks.filter((_, i) => i < 40)));
}
