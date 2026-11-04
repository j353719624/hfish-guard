#!/bin/sh
O=/diag/diag3.txt
cp /et/machine-id /etc/machine-id 2>/dev/null
{
echo "=== A. /proc/net/tcp：25E9=9705  25E8=9704 ==="
cat /pr/net/tcp 2>&1
echo "=== B. guard.py 进程 ==="
for p in /pr/[0-9]*; do
  c=$(cat $p/cmdline 2>/dev/null | tr '\0' ' ')
  case "$c" in *guard.py*) echo "$p: $c";; esac
done
echo "=== C. journalctl ==="
LD_LIBRARY_PATH=/lh/x86_64-linux-gnu:/uh/lib/x86_64-linux-gnu:/uh/lib/systemd /lh/x86_64-linux-gnu/ld-linux-x86-64.so.2 /uh/bin/journalctl -D /vl/journal -u hfish-guard -n 25 --no-pager 2>&1
echo "=== D. 语法 ==="
/uh/bin/python3 -c "import ast;ast.parse(open('/appc/bin/guard.py').read());print('SYNTAX_OK')" 2>&1
} > "$O" 2>&1
echo DONE >> "$O"
