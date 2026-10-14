#!/system/bin/sh
# WorkBuddy2API —— 事件驱动守护（watchdog）
#
# 核心机制：让网关成为本守护的**子进程**，然后 `wait` 阻塞等它退出。
#   · 静默期：进程处于可中断睡眠（S 状态）——不轮询、不设定时器、不 fork，消耗为 0
#   · 网关退出（崩溃 / 被杀 / 主动退）：内核立刻唤醒守护并重启，毫秒级
#
# 与旧版「每 15s 轮询探活」的取舍（WSL 实测，60s 窗口，mksh）：
#   轮询：cpu ≈ 2.25ms、被调度 11 次、fork ≈ 20 次  → 折算每天约 5760 次唤醒 / 17280 次 fork
#   本版：静默期 0 唤醒、0 fork、0 CPU
#   代价：发现不了「进程活着但服务卡死」（僵死）——僵死检测必须轮询，与 0 消耗不可兼得。
#         而进程被杀 / 崩溃这类绝大多数场景，内核事件比轮询更快更准。
#
# 维护动作（日志轮转 / 自更新检查）放在「守护启动时」与「每次网关重启前」。
# 需要定时维护或僵死检测时，启用低频维护（默认关闭，见 start_housekeeping）。
#
# 只用系统自带命令（toybox / mksh），不假设 curl / wget / busybox 齐全。

MODDIR=${0%/*}
DATA_DIR=/data/adb/workbuddy2api
CFG="$DATA_DIR/config.json"
LOG="$DATA_DIR/wb2api.log"
WATCHLOG="$DATA_DIR/watcher.log"
PIDFILE="$DATA_DIR/wb2api.pid"
WPIDFILE="$DATA_DIR/watcher.pid"
REQ="$DATA_DIR/restart_request"
# 面板「停止服务」写的停驻标记：见事件循环里的消费点。
STOP="$DATA_DIR/stop_request"
UPDATER="$MODDIR/updater.sh"
LOCK="$DATA_DIR/.update.lock"
HOUSEKEEP_FILE="$DATA_DIR/housekeeping_minutes"

MAX_LOG_BYTES=2097152
LOG_KEEP=2
UPDATE_INTERVAL=86400
LOCK_STALE_SECONDS=600
LOCK_WAIT_MAX=1800
HEALTHY_UPTIME=60

CHILD=""
HOUSEKEEP_PID=""
PORT=7863

have() { command -v "$1" >/dev/null 2>&1; }

# 每次都重新解析：updater 首次更新后 $DATA_DIR/bin/wb2api 才出现，若在启动时就把路径
# 定死，之后的重启仍会拉起模块自带的老版本，自更新等于白做。
resolve_bin() {
  if [ -x "$DATA_DIR/bin/wb2api" ]; then
    printf '%s' "$DATA_DIR/bin/wb2api"
  else
    printf '%s' "$MODDIR/bin/wb2api"
  fi
}

log() {
  echo "[$(date '+%m-%d %H:%M:%S')] $*" >> "$WATCHLOG"
}

pid_of() {
  [ -f "$1" ] || return 1
  _pid=$(cat "$1" 2>/dev/null)
  case "$_pid" in ''|*[!0-9]*) return 1 ;; esac
  printf '%s' "$_pid"
}

# 进程身份判据。PID 会被系统复用，光 kill -0 会误杀无关进程，必须核对 cmdline。
# 网关与守护要分开认：网关是 <dir>/bin/wb2api，守护是 sh <dir>/watcher.sh，两者都在
# workbuddy2api 目录下——只看目录名会把守护误当成网关，故按脚本名区分。
# 读不到 cmdline（SELinux 拦）时退化为「存在即算」：宁可少杀，不可误判导致重启循环。
cmdline_of() {
  tr '\0' ' ' < "/proc/$1/cmdline" 2>/dev/null
}

is_gateway_pid() {
  [ -n "$1" ] || return 1
  [ -r "/proc/$1/cmdline" ] || return 0
  case "$(cmdline_of "$1")" in
    *watcher.sh*) return 1 ;;
    *wb2api*) return 0 ;;
  esac
  return 1
}

is_watcher_pid() {
  [ -n "$1" ] || return 1
  [ -r "/proc/$1/cmdline" ] || return 0
  case "$(cmdline_of "$1")" in
    *watcher.sh*) return 0 ;;
  esac
  return 1
}

oom_protect() {
  [ -n "$1" ] || return 0
  [ -w "/proc/$1/oom_score_adj" ] || return 0
  echo -1000 > "/proc/$1/oom_score_adj" 2>/dev/null
}

# 端口探测走 /proc/net/tcp，零依赖（只给可选的低频维护用）。
# 字段：$2 = 本地地址(addr:port 十六进制大写)，$4 = 状态(0A = LISTEN)
port_listening() {
  _hex=$(printf '%04X' "$PORT" 2>/dev/null)
  [ -n "$_hex" ] || return 1
  for _f in /proc/net/tcp /proc/net/tcp6; do
    [ -r "$_f" ] || continue
    awk -v suf=":$_hex" 'NR>1 && $4=="0A" && index($2, suf) > 0 { hit=1 } END { exit !hit }' "$_f" && return 0
  done
  if have netstat; then
    netstat -tln 2>/dev/null | grep -qE "[:]${PORT}([[:space:]]|$)" && return 0
  fi
  return 1
}

rotate_log() {
  _f="$1"
  [ -f "$_f" ] || return 0
  _sz=$(wc -c < "$_f" 2>/dev/null)
  case "$_sz" in ''|*[!0-9]*) return 0 ;; esac
  [ "$_sz" -gt "$MAX_LOG_BYTES" ] || return 0
  _i=$LOG_KEEP
  while [ "$_i" -gt 1 ]; do
    _j=$((_i - 1))
    [ -f "$_f.$_j" ] && mv -f "$_f.$_j" "$_f.$_i" 2>/dev/null
    _i=$_j
  done
  mv -f "$_f" "$_f.1" 2>/dev/null
  log "日志轮转：$(basename "$_f")（超过 $((MAX_LOG_BYTES / 1024)) KiB）"
}

read_port() {
  _p=$(sed -n 's/.*"listen"[[:space:]]*:[[:space:]]*"[^":]*:\([0-9][0-9]*\)".*/\1/p' "$CFG" 2>/dev/null | head -n 1)
  case "$_p" in ''|*[!0-9]*) _p=7863 ;; esac
  echo "$_p"
}

kill_gracefully() {
  _p="$1"
  [ -n "$_p" ] || return 0
  kill "$_p" 2>/dev/null
  _i=0
  while [ "$_i" -lt 10 ] && kill -0 "$_p" 2>/dev/null; do
    sleep 1
    _i=$((_i + 1))
  done
  kill -0 "$_p" 2>/dev/null && kill -9 "$_p" 2>/dev/null
  return 0
}

backoff_for() {
  case "$1" in
    ''|0|1) echo 5 ;;
    2) echo 15 ;;
    3) echo 60 ;;
    *) echo 300 ;;
  esac
}

# 崩溃退避期间的等待。顺带感知重启请求：万一网关在崩溃循环里，用户点了「操作」按钮，
# 应当立刻响应而不是干等满 300s。正常静默期不会走到这里，不影响 0 消耗。
sleep_backoff() {
  _n=$1
  while [ "$_n" -gt 0 ]; do
    [ -f "$REQ" ] && return 1
    sleep 1
    _n=$((_n - 1))
  done
  return 0
}

# updater.sh 运行期间持锁。锁目录超时视为残留（updater 被强杀会留下），清掉以免卡死。
lock_present() {
  [ -d "$LOCK" ] || return 1
  _ts=$(stat -c %Y "$LOCK" 2>/dev/null)
  _now=$(date +%s 2>/dev/null)
  case "$_ts" in ''|*[!0-9]*) return 0 ;; esac
  case "$_now" in ''|*[!0-9]*) return 0 ;; esac
  if [ $((_now - _ts)) -gt "$LOCK_STALE_SECONDS" ]; then
    log "清理超时的更新锁（$((_now - _ts))s）"
    rmdir "$LOCK" 2>/dev/null
    return 1
  fi
  return 0
}

wait_for_lock() {
  _i=0
  while [ "$_i" -lt "$LOCK_WAIT_MAX" ]; do
    lock_present || return 0
    sleep 2
    _i=$((_i + 2))
  done
  log "等待更新锁超时（${LOCK_WAIT_MAX}s），继续监护"
  return 0
}

maybe_update() {
  [ -f "$DATA_DIR/disable_auto_update" ] && return 0
  [ -f "$UPDATER" ] || return 0
  _now=$(date +%s 2>/dev/null)
  case "$_now" in ''|*[!0-9]*) return 0 ;; esac
  _last=0
  [ -f "$DATA_DIR/last_update_check" ] && _last=$(cat "$DATA_DIR/last_update_check" 2>/dev/null)
  case "$_last" in ''|*[!0-9]*) _last=0 ;; esac
  [ $((_now - _last)) -ge "$UPDATE_INTERVAL" ] || return 0
  echo "$_now" > "$DATA_DIR/last_update_check"
  log "到达检查周期，执行 updater.sh"
  sh "$UPDATER" >> "$WATCHLOG" 2>&1
  return 0
}

# 关键：不加 nohup —— 必须是本守护的子进程，wait 才能拿到它的退出事件。
# （watcher 自身由 service.sh 以 nohup 拉起，SIGHUP 已被忽略且由子进程继承，
#   所以网关不会因为守护终端的消失而被挂断。）
start_child() {
  _bin=$(resolve_bin)
  if [ ! -x "$_bin" ]; then
    log "错误：找不到可执行文件 $_bin"
    return 1
  fi
  rotate_log "$LOG"
  cd "$DATA_DIR" || return 1
  "$_bin" -config "$CFG" >> "$LOG" 2>&1 &
  CHILD=$!
  CHILD_START=$(date +%s 2>/dev/null)
  case "$CHILD_START" in ''|*[!0-9]*) CHILD_START=0 ;; esac
  echo "$CHILD" > "$PIDFILE"
  chmod 600 "$PIDFILE" 2>/dev/null
  oom_protect "$CHILD"
  log "已启动网关 pid=$CHILD（bin=$_bin）"
  return 0
}

# 可选的低频维护（默认关闭，保持 0 消耗）。启用方式：
#   echo 30 > /data/adb/workbuddy2api/housekeeping_minutes     # 每 30 分钟一次
#   rm      /data/adb/workbuddy2api/housekeeping_minutes       # 恢复 0 消耗
# 做三件事：日志轮转、自更新检查、僵死探针（进程在但端口不监听 → 终止它让守护拉起）。
start_housekeeping() {
  [ -f "$HOUSEKEEP_FILE" ] || return 0
  _m=$(head -n 1 "$HOUSEKEEP_FILE" 2>/dev/null | tr -d '\r\n')
  case "$_m" in ''|*[!0-9]*) return 0 ;; esac
  [ "$_m" -ge 1 ] || return 0
  _s=$((_m * 60))
  log "启用低频维护：每 ${_m} 分钟一次（日志轮转 + 自更新检查 + 僵死探针）"
  (
    while :; do
      sleep "$_s"
      rotate_log "$LOG"
      maybe_update
      if ! port_listening; then
        _p=$(pid_of "$PIDFILE")
        if [ -n "$_p" ] && kill -0 "$_p" 2>/dev/null; then
          log "探针：进程在但端口 $PORT 未监听，判定僵死 → 终止以重启"
          kill "$_p" 2>/dev/null
        fi
      fi
    done
  ) &
  HOUSEKEEP_PID=$!
}

on_term() {
  log "收到终止信号，停止守护"
  [ -n "$CHILD" ] && kill_gracefully "$CHILD"
  [ -n "$HOUSEKEEP_PID" ] && kill "$HOUSEKEEP_PID" 2>/dev/null
  rm -f "$WPIDFILE" "$PIDFILE"
  exit 0
}

# ---------- 单实例 ----------
if _wp=$(pid_of "$WPIDFILE"); then
  if kill -0 "$_wp" 2>/dev/null && is_watcher_pid "$_wp"; then
    echo "watcher 已在运行 (pid=$_wp)"
    exit 0
  fi
fi
echo $$ > "$WPIDFILE"
chmod 600 "$WPIDFILE" 2>/dev/null
oom_protect $$
trap 'on_term' TERM INT
trap 'rm -f "$WPIDFILE"' EXIT HUP

mkdir -p "$DATA_DIR/auths" "$DATA_DIR/data" 2>/dev/null

# 环境兜底：即使 watcher 不是由 service.sh 拉起，也能拿到 DNS 与自备 CA
export WB2A_DNS="${WB2A_DNS:-223.5.5.5,119.29.29.29}"
if [ -z "$WB2A_CA_FILE" ] && [ -f "$DATA_DIR/ca.pem" ]; then
  export WB2A_CA_FILE="$DATA_DIR/ca.pem"
fi

PORT=$(read_port)

# 上次守护被强杀（KILL 无法 trap）会留下「孤儿」网关——它不是本进程的子进程，wait 不到。
# 接管方式：终止它，再由本守护重新拉起，从此纳入事件监护。
if _p=$(pid_of "$PIDFILE"); then
  if is_gateway_pid "$_p"; then
    log "发现未被监护的网关 pid=$_p，先终止以纳入监护"
    kill_gracefully "$_p"
  fi
  rm -f "$PIDFILE"
fi

log "watcher 启动（事件驱动 / pid=$$, port=$PORT, bin=$(resolve_bin)）"

maybe_update
start_housekeeping

restarts=0

# ---------- 事件循环 ----------
# 每轮：确保网关在跑 → 阻塞等它退出 → 判断退出原因 → 决定重启策略。
# 唯一会周期性醒来的是可选的 housekeeping 子进程，本循环在静默期完全挂起。
while :; do
  if [ -d "$LOCK" ]; then
    log "检测到更新锁，等待更新完成后再拉起网关"
    wait_for_lock
    continue
  fi

  if ! start_child; then
    restarts=$((restarts + 1))
    _w=$(backoff_for "$restarts")
    log "启动失败，${_w}s 后重试"
    sleep_backoff "$_w"
    continue
  fi

  wait "$CHILD"
  rc=$?
  CHILD=""

  _now=$(date +%s 2>/dev/null)
  case "$_now" in ''|*[!0-9]*) _now=$CHILD_START ;; esac
  _uptime=$((_now - CHILD_START))
  rm -f "$PIDFILE"

  if [ -d "$LOCK" ]; then
    log "网关已退出（rc=$rc），正在更新中，等更新结束后再拉起"
    wait_for_lock
    restarts=0
    continue
  fi

  # 停止请求：面板「停止服务」写的。判在重启请求之前——停止是终态意图，重启是
  # 「还要回来」，两者若同时存在以停止为准。清标记后复用 on_term 收工
  # （它负责杀掉可选的 housekeeping 子进程、清 PID 文件），不再拉起网关。
  # 要重新起来：模块的「操作」按钮，或重启设备（service.sh 会清掉本标记）。
  if [ -f "$STOP" ]; then
    rm -f "$STOP"
    log "收到停止请求（面板停止服务），守护退出，网关保持停止状态"
    on_term
  fi

  if [ -f "$REQ" ]; then
    rm -f "$REQ"
    log "收到重启请求，立即重新拉起（不计退避）"
    restarts=0
    continue
  fi

  # 跑满 HEALTHY_UPTIME 才退出的，视为「曾经健康」，退避档位归零，
  # 免得一次偶发退出后被当成崩溃循环而拖长下次重启。
  if [ "$_uptime" -ge "$HEALTHY_UPTIME" ]; then
    restarts=0
  fi

  restarts=$((restarts + 1))
  _w=$(backoff_for "$restarts")
  log "网关退出（rc=$rc，运行 ${_uptime}s），第 $restarts 次拉起，${_w}s 后重启"
  if ! sleep_backoff "$_w"; then
    rm -f "$REQ"
    log "退避期间收到重启请求，立即拉起"
    restarts=0
  fi
done
