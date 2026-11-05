const fs = require('fs');
const s = fs.readFileSync('fpk/app/ui/index.html', 'utf8');
const js = s.slice(s.indexOf('<scr' + 'ipt>') + 8, s.lastIndexOf('</scr' + 'ipt>'));
// Write to temp file for node --check
fs.writeFileSync('/tmp/hguard_test.js', js);
console.log('written', js.length, 'chars');
