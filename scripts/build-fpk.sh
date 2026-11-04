#!/bin/bash
# 把 fpk/ 目录打成可安装的 hfish-guard.fpk
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/fpk"
OUT="$ROOT/dist"
mkdir -p "$OUT"

cd "$SRC"
# Windows 编辑可能引入 CRLF，统一洗成 LF
sed -i 's/\r$//' cmd/* app/bin/*.py app/ui/config 2>/dev/null || true
tar -czf app.tgz -C app .
chmod 755 cmd/* app/bin/*.py 2>/dev/null || true

cd "$SRC"
tar -czf "$OUT/hfish-guard.fpk" \
  app.tgz cmd config ICON.PNG ICON_256.PNG manifest

echo "built: $OUT/hfish-guard.fpk ($(stat -c %s "$OUT/hfish-guard.fpk") bytes)"
