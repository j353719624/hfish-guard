#!/bin/bash
# HFish 卫生巡检：防止「扫描感知 / 上报日志」把 NAS 拖垮
#
# 背景（2026-11-06 实测）：HFish 扫描感知开着时，ECS 客户端每扫一次就向
# NAS 上报一次（POST /api/v1/report/scan），NAS 侧逐条写 scanners/scans/ip_profile
# 三张表并打 INFO 日志 —— 一小时 55 万条、783MB 噪声数据、日志涨到 338MB，
# HFish server 常驻 30% CPU、MySQL 12.9%、IO 压力 full avg60=7.6%，
# 面板查询要几十秒（表现为「老是卡死」）。
#
# 本脚本每小时跑一次：只在超阈值时清理，正常时零开销。
# 清理对象全是扫描噪声（scanners/scans）与纯日志，不碰 infos/flows（真攻击记录）。
#
# 撤销：rm /etc/cron.d/hive-hygiene && rm /usr/local/bin/hive-hygiene.sh
set -u

LOG=/var/log/hive-hygiene.log
MAX_ROWS=200000          # scanners + scans 合计行数阈值
MAX_LOG_MB=200           # 单个日志文件大小阈值（MB）
TMP=$(mktemp)

note() { echo "$(date '+%F %T') $*" >> "$LOG"; }

# MySQL 口令从容器环境变量取，不写死在脚本里
DBPASS=$(docker inspect mysql --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null \
         | sed -n 's/^MYSQL_ROOT_PASSWORD=//p' | head -1)
if [ -z "$DBPASS" ]; then
  note "取不到 MySQL 口令，跳过数据库检查"
  exit 0
fi

q() { docker exec mysql mysql -uroot -p"$DBPASS" -D HFish -N -e "$1" 2>/dev/null; }

ROWS=$(q "select (select count(*) from scanners)+(select count(*) from scans);")
if [ -n "${ROWS:-}" ] && [ "$ROWS" -gt "$MAX_ROWS" ] 2>/dev/null; then
  q "truncate table scanners; truncate table scans;" >/dev/null
  q "optimize table scanners; optimize table scans;" >/dev/null
  note "扫描噪声表超阈值($ROWS > $MAX_ROWS)，已清理"
fi

for f in /vol2/@appdata/hive/hfish.log /vol2/@appdata/hive/hfish-data/logs/server.log; do
  [ -f "$f" ] || continue
  MB=$(( $(stat -c %s "$f" 2>/dev/null || echo 0) / 1048576 ))
  if [ "$MB" -gt "$MAX_LOG_MB" ]; then
    tail -c 2000000 "$f" > "$f.keep" 2>/dev/null || true
    : > "$f"
    cat "$f.keep" >> "$f" 2>/dev/null || true
    rm -f "$f.keep"
    note "日志 $f 超限(${MB}MB > ${MAX_LOG_MB}MB)，已截断至尾部 2MB"
  fi
done

rm -f "$TMP"
exit 0
