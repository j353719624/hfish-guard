#!/bin/sh
O=/diag/diag.txt
cp /et/machine-id /etc/machine-id 2>/dev/null
{
echo "=== A. unit file ==="
cat /et/systemd/system/hfish-guard.service 2>&1
echo "=== B. config.json ==="
cat /ad/config.json 2>&1
echo "=== C. guard.py 语法 ==="
/lh/x86_64-linux-gnu/ld-linux-x86-64.so.2 --library-path /lh/x86_64-linux-gnu:/uh/lib/x86_64-linux-gnu /uh/bin/python3 -c "import ast; ast.parse(open('/ab/guard.py',encoding='utf-8').read()); print('SYNTAX_OK')" 2>&1
echo "=== D. journalctl ==="
/lh/x86_64-linux-gnu/ld-linux-x86-64.so.2 --library-path /lh/x86_64-linux-gnu:/uh/lib/x86_64-linux-gnu /uh/bin/journalctl -D /vl/journal -u hfish-guard -n 30 --no-pager 2>&1
echo "=== E. 容器内实跑 guard.py 8 秒 ==="
/lh/x86_64-linux-gnu/ld-linux-x86-64.so.2 --library-path /lh/x86_64-linux-gnu:/uh/lib/x86_64-linux-gnu /uh/bin/python3 /ab/guard.py 2>&1 &
P=$!
sleep 8
kill $P 2>/dev/null
sleep 1
echo "=== F. 目录 ==="
ls -la /ab 2>&1
ls -la /ad 2>&1
} > "$O" 2>&1
echo DONE >> "$O"
