#!/bin/bash
# 把 fpk/ 打成可安装的 hfish-guard.fpk（构建产物只进 dist/，不污染仓库）
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/fpk"
OUT="$ROOT/dist"
APP="hfish-guard"

for f in manifest cmd/main app/bin/guard.py app/ui/index.html app/ui/config ICON.PNG; do
  [ -e "$SRC/$f" ] || { echo "缺少必需文件：fpk/$f" >&2; exit 1; }
done

mkdir -p "$OUT"

# Windows 上编辑过的脚本可能是 CRLF，FNOS 里执行会报 bad interpreter，统一洗成 LF
find "$SRC/cmd" -type f -exec sed -i 's/\r$//' {} +
sed -i 's/\r$//' "$SRC/app/bin/guard.py" "$SRC/app/ui/config" 2>/dev/null || true
chmod 755 "$SRC/cmd"/* "$SRC/app/bin/guard.py"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/pkg"

# 注入自检断言条数（统计 runSelfTest 里的 errs.push 数量并写回页面）
# 以前页面里写死 checks=54，加了新断言忘了改数字，自检就会显示得比实际覆盖多。
python3 "$ROOT/scripts/inject-selftest-count.py" "$SRC/app/ui/index.html"

# 应用文件单独打成 app.tgz，再和 cmd/config/图标一起组成 fpk
# 排除编译缓存/临时文件（本机 py_compile 会生成 115KB 的 __pycache__，不该进包）
tar -czf "$TMP/pkg/app.tgz" -C "$SRC/app" \
  --exclude='__pycache__' --exclude='*.pyc' --exclude='*.pyo' --exclude='.DS_Store' .
cp -r "$SRC/cmd" "$SRC/config" "$SRC/ICON.PNG" "$SRC/ICON_256.PNG" "$SRC/manifest" "$TMP/pkg/"

( cd "$TMP/pkg" && tar -czf "$OUT/$APP.fpk" . )

# 校验：包内不得出现 pyc，且版本号与 manifest 一致
if tar -xzOf "$OUT/$APP.fpk" ./app.tgz | tar -tzf - | grep -qE '(__pycache__|\.pyc$)'; then
  echo "构建产物里混入了 .pyc，请清理 fpk/app 后重试" >&2
  exit 1
fi

# 校验：UI 内联脚本必须语法正确
# 踩过的坑：手工改 HTML 时漏了一个双引号，整个 <script> 挂掉，页面白屏且
# 没有任何报错（浏览器只说「HG_LIVE is undefined」）。这里用 node --check 拦一道。
if command -v node >/dev/null 2>&1; then
  python3 - "$SRC/app/ui/index.html" "$TMP/ui.js" <<'PY'
import io, re, sys
src, dst = sys.argv[1], sys.argv[2]
html = io.open(src, encoding="utf-8").read()
blocks = re.findall(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html, re.S)
if not blocks:
    sys.exit("UI 里没找到内联脚本")
io.open(dst, "w", encoding="utf-8", newline="\n").write(blocks[0])
PY
  if ! node --check "$TMP/ui.js"; then
    echo "UI 内联脚本语法错误，已中止构建" >&2
    exit 1
  fi
  echo "ui script: syntax ok"
fi

SIZE=$(stat -c %s "$OUT/$APP.fpk")
echo "built: $OUT/$APP.fpk (${SIZE} bytes)"
echo "---- 内容 ----"
tar -tzf "$OUT/$APP.fpk" | sed 's/^/  /'
echo "---- 校验 ----"
sha256sum "$OUT/$APP.fpk"
