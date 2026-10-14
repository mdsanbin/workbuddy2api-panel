#!/system/bin/sh
# WorkBuddy2API —— KernelSU 管理器里的「操作」按钮
#   重启网关 → 等端口真正就绪 → 自动用浏览器打开管理面板
#
# 重启优先委托 watcher.sh（它持有唯一重启权，避免和守护同时拉起同一端口）；
# watcher 不在时才自己动手。
# 不想自动弹浏览器？执行一次即可关掉（删除该文件即恢复）：
#   touch /data/adb/workbuddy2api/disable_auto_open_panel

MODDIR=${0%/*}
DATA_DIR=/data/adb/workbuddy2api
CFG="$DATA_DIR/config.json"
LOG="$DATA_DIR/wb2api.log"
PIDFILE="$DATA_DIR/wb2api.pid"
WPIDFILE="$DATA_DIR/watcher.pid"
REQ="$DATA_DIR/restart_request"
NO_OPEN_FLAG="$DATA_DIR/disable_auto_open_panel"

mkdir -p "$DATA_DIR/auths" "$DATA_DIR/data" 2>/dev/null
[ -f "$CFG" ] || cp -f "$MODDIR/config/config.json" "$CFG" 2>/dev/null

export WB2A_DNS="${WB2A_DNS:-223.5.5.5,119.29.29.29}"
if [ -z "$WB2A_CA_FILE" ] && [ -f "$DATA_DIR/ca.pem" ]; then
  export WB2A_CA_FILE="$DATA_DIR/ca.pem"
fi

have() { command -v "$1" >/dev/null 2>&1; }

cfg_get() {
  sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$CFG" 2>/dev/null | head -n 1
}

pid_of() {
  [ -f "$1" ] || return 1
  _p=$(cat "$1" 2>/dev/null)
  case "$_p" in ''|*[!0-9]*) return 1 ;; esac
  printf '%s' "$_p"
}

# 进程身份判据：守护是 sh <dir>/watcher.sh，网关是 <dir>/bin/wb2api。两者同在
# workbuddy2api 目录下，只用目录名区分会把守护误判成网关，故按脚本名区分。
# 读不到 cmdline（SELinux 拦）时退化为「存在即算」，否则会误判守护缺席。
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

# 自更新落在 $DATA_DIR/bin/wb2api（覆盖层），它优先；否则用模块自带的那份。
# 不这样写的话，自更新之后手动重启会把老版本又拉起来。
resolve_bin() {
  if [ -x "$DATA_DIR/bin/wb2api" ]; then
    printf '%s' "$DATA_DIR/bin/wb2api"
  else
    printf '%s' "$MODDIR/bin/wb2api"
  fi
}

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

LISTEN=$(cfg_get listen)
PORT=$(printf '%s' "$LISTEN" | sed -n 's/.*:\([0-9][0-9]*\)$/\1/p')
case "$PORT" in ''|*[!0-9]*) PORT=7863 ;; esac

# ---------- 1) 重启网关 ----------
# 守护现在阻塞在 wait 上（事件驱动，不做轮询），看不到文件变化。通知方式是
# 「先留标记、再终止网关子进程」：网关一退出，内核立刻唤醒守护，它看到标记就
# 立即拉起新进程（不计退避）。网关若已死也无妨——守护照样会重启。
DELEGATED=0
if _w=$(pid_of "$WPIDFILE"); then
  if kill -0 "$_w" 2>/dev/null && is_watcher_pid "$_w"; then
    : > "$REQ"
    _c=$(pid_of "$PIDFILE")
    if [ -n "$_c" ]; then
      kill "$_c" 2>/dev/null
    fi
    DELEGATED=1
    echo "已请求守护进程重启网关"
  fi
fi

if [ "$DELEGATED" = "0" ]; then
  if _p=$(pid_of "$PIDFILE"); then
    if is_gateway_pid "$_p"; then
      kill "$_p" 2>/dev/null
      sleep 1
      kill -9 "$_p" 2>/dev/null
    fi
  fi
  _bin=$(resolve_bin)
  if [ ! -x "$_bin" ]; then
    echo "找不到可执行文件 $_bin"
    exit 1
  fi
  cd "$DATA_DIR" || exit 1
  nohup "$_bin" -config "$CFG" >> "$LOG" 2>&1 &
  _new=$!
  echo "$_new" > "$PIDFILE"
  chmod 600 "$PIDFILE" 2>/dev/null
  [ -w "/proc/$_new/oom_score_adj" ] && echo -1000 > "/proc/$_new/oom_score_adj" 2>/dev/null
  # 守护缺席通常是「已关掉常驻守护」，说明一下免得被当成故障
  if [ -f "$DATA_DIR/disable_watcher" ]; then
    echo "网关已重启 (pid=$_new，常驻守护已关闭，不会自动拉起)"
  else
    echo "网关已重启 (pid=$_new，守护不在，本次由本脚本直接拉起)"
  fi
fi

# ---------- 2) 等端口真正 listen（最多 30s）----------
# 委托守护重启时，守护最长要等一个探活片（5s）才处理请求，再叠加停+起，故留宽些。
READY=0
i=0
while [ "$i" -lt 30 ]; do
  if port_listening; then
    READY=1
    break
  fi
  sleep 1
  i=$((i + 1))
done

PANEL_URL="http://127.0.0.1:${PORT}/panel/"
echo "本机面板: $PANEL_URL"

# 只有监听非环回地址时，「局域网可访问」才成立——否则打出来的地址在别的设备上
# 是打不开的，属于误导。
case "$LISTEN" in
  ""|127.0.0.1:*|localhost:*|"[::1]:"*) ;;
  *)
    IP=$(ip route get 1 2>/dev/null | awk '{for(n=1;n<=NF;n++) if($n=="src") print $(n+1)}' | head -1)
    [ -n "$IP" ] && echo "局域网面板: http://$IP:$PORT/panel/"
    ;;
esac

KEY=$(cfg_get api_key)
[ -n "$KEY" ] && echo "面板密钥: $KEY（首次访问时输入一次，之后浏览器会记住）"

[ "$READY" = "1" ] || echo "(端口 $PORT 尚未就绪，页面可能需稍后刷新)"

# ---------- 3) 自动跳转到面板 ----------
if [ -f "$NO_OPEN_FLAG" ]; then
  echo "(已启用 disable_auto_open_panel，跳过自动打开)"
  exit 0
fi

AM=/system/bin/am
[ -x "$AM" ] || AM=am

# 多用户设备（分身/工作资料）要指定当前用户，否则会打到 user 0
CUR_USER=$("$AM" get-current-user 2>/dev/null)
case "$CUR_USER" in ''|*[!0-9]*) CUR_USER=0 ;; esac

if "$AM" start --user "$CUR_USER" -a android.intent.action.VIEW -d "$PANEL_URL" >/dev/null 2>&1; then
  echo "已在浏览器打开面板"
else
  echo "自动打开失败，请手动访问上面的地址"
fi
