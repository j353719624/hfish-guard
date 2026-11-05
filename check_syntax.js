const fs = require('fs');
const s = fs.readFileSync('fpk/app/ui/index.html', 'utf8');
const scriptStart = s.indexOf('<' + 'script>') + 8;
const scriptEnd = s.lastIndexOf('</' + 'scr' + 'ipt>');
const js = s.slice(scriptStart, scriptEnd);
try {
  new Function(js);
  console.log('JS 语法 OK，', js.split('\n').length, '行');
} catch (e) {
  console.log('JS 语法错误：', e.message);
  // 打印出错行上下文
  const lines = js.split('\n');
  const match = e.stack.match(/<anonymous>:(\d+)/);
  if (match) {
    const lineNo = parseInt(match[1]);
    for (let i = Math.max(0, lines.length - 5); i < lines.length; i++) {
      console.log((i + 1) + ': ' + lines[i]);
    }
  }
}
