#!/bin/sh
O=/diag/probe4.txt
{
echo "=== systemd unit 目录里的 guard 相关文件 ==="
ls -la /et/systemd/system/ 2>&1 | grep -iE "hfish|guard" || echo "unit 文件不存在"
echo "=== unit 内容 ==="
cat /et/systemd/system/hfish-guard.service 2>&1
echo "=== fnOS app 目录 ==="
ls -la /appc 2>&1
ls -la /ad 2>&1
} > "$O" 2>&1
echo DONE >> "$O"
