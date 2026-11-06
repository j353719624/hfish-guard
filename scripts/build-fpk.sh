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

# 校验 + 构建前端
# v1.8 起前端是 Vue 3 + Vite 工程（ui/ 目录），产物输出到 fpk/app/ui。
# 构建在这里跑：NAS 上不需要 Node，构建产物随 fpk 一起分发（与 fnOS/HFish 同构）。
#
# 踩过的坑保留在这里提醒：手工改 HTML 时漏一个双引号，整个 <script> 挂掉，
# 页面白屏且没有任何报错。现在由 vue-tsc + Vite 在构建期拦这类问题。
UI_SRC="$ROOT/ui"
if [ -d "$UI_SRC" ]; then
  if ! command -v node >/dev/null 2>&1; then
    echo "未找到 node，无法构建 Vue 前端（ui/ 目录存在但缺少 node）" >&2
    exit 1
  fi
  echo "---- 构建 Vue 前端 ----"
  ( cd "$UI_SRC" && npm run build )
  # 产物必须存在，否则装上去是白屏
  if [ ! -f "$SRC/app/ui/index.html" ] || [ ! -f "$SRC/app/ui/assets/guard.js" ]; then
    echo "前端构建产物缺失（index.html / assets/guard.js）" >&2
    exit 1
  fi
  # 产物里不能有 sourcemap 或 node_modules
  if find "$SRC/app/ui" \( -name "*.map" -o -name "node_modules" \) 2>/dev/null | grep -q .; then
    echo "前端产物里混入了 sourcemap 或 node_modules，请清理后重试" >&2
    exit 1
  fi
  echo "ui build: ok"
fi

# 注入自检断言条数（老版单文件 HTML 用的；Vue 版会自动跳过）
# 以前页面里写死 checks=54，加了新断言忘了改数字，自检就会显示得比实际覆盖多。
python3 "$ROOT/scripts/inject-selftest-count.py" "$SRC/app/ui/index.html"

# 前端构建完成后再打 app.tgz —— 否则包里带的是上一次构建的旧产物
# 排除编译缓存/临时文件（本机 py_compile 会生成 115KB 的 __pycache__，不该进包）
tar -czf "$TMP/pkg/app.tgz" -C "$SRC/app" \
  --exclude='__pycache__' --exclude='*.pyc' --exclude='*.pyo' --exclude='.DS_Store' .
cp -r "$SRC/cmd" "$SRC/config" "$SRC/ICON.PNG" "$SRC/ICON_256.PNG" "$SRC/manifest" "$TMP/pkg/"

( cd "$TMP/pkg" && tar -czf "$OUT/$APP.fpk" . )

# 校验：包内不得出现 pyc
if tar -xzOf "$OUT/$APP.fpk" ./app.tgz | tar -tzf - | grep -qE '(__pycache__|\.pyc$)'; then
  echo "构建产物里混入了 .pyc，请清理 fpk/app 后重试" >&2
  exit 1
fi

SIZE=$(stat -c %s "$OUT/$APP.fpk")
echo "built: $OUT/$APP.fpk (${SIZE} bytes)"
echo "---- 内容 ----"
tar -tzf "$OUT/$APP.fpk" | sed 's/^/  /'
echo "---- 校验 ----"
sha256sum "$OUT/$APP.fpk"
