# -*- coding: utf-8 -*-
"""把自检断言条数写回 UI 页面。

以前页面里写死 `checks=54`，加了新断言忘了改数字，自检就会显示得比实际覆盖多。
构建时统计 runSelfTest 里的 errs.push 数量并注入，数字永远对得上。

用法：python3 scripts/inject-selftest-count.py fpk/app/ui/index.html
"""
import io
import re
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "fpk/app/ui/index.html"
html = io.open(path, encoding="utf-8").read()

m = re.search(r"function runSelfTest\(\)\{(.*?)\n\}\n", html, re.S)
if not m:
    # Vue 版前端：自检逻辑在 ui/src/ 里，构建产物里没有 runSelfTest。
    # 这种情况下不做注入，直接跳过（不阻塞构建）。
    print("ui selftest: skipped（未找到 runSelfTest，Vue 版自检在源码侧）")
    sys.exit(0)

n = len(re.findall(r"errs\.push\(", m.group(1)))
if n <= 0:
    print("ui selftest: skipped（runSelfTest 里没有 errs.push 断言）")
    sys.exit(0)

new, cnt = re.subn(r"var SELFTEST_CHECKS=\d+;",
                   "var SELFTEST_CHECKS=%d;" % n, html, count=1)
if cnt == 0:
    print("ui selftest: skipped（页面里没有 SELFTEST_CHECKS 声明）")
    sys.exit(0)

io.open(path, "w", encoding="utf-8", newline="\n").write(new)
print("ui selftest checks: %d" % n)
