#!/bin/sh
O=/diag/diag2.txt
cp /et/machine-id /etc/machine-id 2>/dev/null
{
echo "=== A. patched guard.py 语法 ==="
/lh/x86_64-linux-gnu/ld-linux-x86-64.so.2 --library-path /lh/x86_64-linux-gnu:/uh/lib/x86_64-linux-gnu:/uh/lib/systemd /uh/bin/python3 -c "import ast; ast.parse(open('/appc/bin/guard.py', encoding='utf-8').read()); print('SYNTAX_OK')" 2>&1
echo "=== B. journalctl 最近 30 条 ==="
/lh/x86_64-linux-gnu/ld-linux-x86-64.so.2 --library-path /lh/x86_64-linux-gnu:/uh/lib/x86_64-linux-gnu:/uh/lib/systemd /uh/bin/journalctl -D /vl/journal -u hfish-guard -n 30 --no-pager 2>&1
echo "=== C. iptables 陷阱在吗 ==="
/lh/x86_64-linux-gnu/ld-linux-x86-64.so.2 --library-path /lh/x86_64-linux-gnu:/uh/lib/x86_64-linux-gnu /uh/bin/iptables -C INPUT -p tcp -m multiport --dports 6379,9200,9000,8080,8081,9198,9080,9092,2022,7878 -m set ! --match-set hfish_guard_white src -j SET --add-set hfish_guard_seen src 2>&1; echo "trap_rc=$?"
} > "$O" 2>&1
echo DONE >> "$O"
