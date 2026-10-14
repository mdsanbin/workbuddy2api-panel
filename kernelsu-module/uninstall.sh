#!/system/bin/sh
# WorkBuddy2API —— 卸载模块时停掉守护与网关
# 注意：账号与配置保留在 /data/adb/workbuddy2api，不会自动删除。
#       确需彻底清理请手动执行： rm -rf /data/adb/workbuddy2api

DATA_DIR=/data/adb/workbuddy2api

kill_pidfile() {
  f="$1"
  [ -f "$f" ] || return 0
  p=$(cat "$f" 2>/dev/null)
  case "$p" in
    ''|*[!0-9]*) rm -f "$f"; return 0 ;;
  esac
  kill "$p" 2>/dev/null
  sleep 1
  kill -9 "$p" 2>/dev/null
  rm -f "$f"
}

# 先停守护：否则它会把网关重新拉起来，卸载后还占着端口
kill_pidfile "$DATA_DIR/watcher.pid"
kill_pidfile "$DATA_DIR/wb2api.pid"

# 兜底：按进程名再清一次
pkill -f "wb2api -config" 2>/dev/null
pkill -f "watcher.sh" 2>/dev/null

# 清掉可能残留的更新锁与重启请求
rm -rf "$DATA_DIR/.update.lock" 2>/dev/null
rm -f "$DATA_DIR/restart_request" 2>/dev/null
