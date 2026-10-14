#!/system/bin/sh
# WorkBuddy2API —— 开机自启（KernelSU / Magisk 在 late_start service 阶段以 root 执行）
#
# 本脚本只负责「等系统就绪 → 初始化数据目录 → 安全兜底」，然后把网关交给
# watcher.sh 常驻守护。启动 / 探活 / 重启 / 自更新全部由 watcher 承担，
# 保证重启权单一，不会出现两处同时拉起同一个端口。
#
# ---------- 关掉常驻守护（省电优先） ----------
#   touch /data/adb/workbuddy2api/disable_watcher   # 关掉守护
#   rm    /data/adb/workbuddy2api/disable_watcher   # 恢复（重启后生效）
# 关掉后网关照常开机自启、转发功能完全一致，只是失去：崩溃自愈、oom 保护、
# 日志轮转、每 24h 自更新检查。操作按钮仍可直接重启网关。

MODDIR=${0%/*}
DATA_DIR=/data/adb/workbuddy2api
CFG="$DATA_DIR/config.json"
WATCHLOG="$DATA_DIR/watcher.log"
WPIDFILE="$DATA_DIR/watcher.pid"
LOG="$DATA_DIR/wb2api.log"
PIDFILE="$DATA_DIR/wb2api.pid"
NO_WATCH_FLAG="$DATA_DIR/disable_watcher"

# 等系统启动完成，避免网络栈还没就绪就起服务
i=0
while [ "$(getprop sys.boot_completed)" != "1" ] && [ "$i" -lt 120 ]; do
  sleep 2
  i=$((i + 1))
done

mkdir -p "$DATA_DIR/auths" "$DATA_DIR/data" 2>/dev/null

# 清掉上次「停止服务」留下的停驻标记：能走到这里就说明用户要服务跑起来
# （开机自启 / 重装模块），不该被上一次的停止意图拦住。
rm -f "$DATA_DIR/stop_request" 2>/dev/null

# 首次运行：落地默认配置（关键：含 Android 必需的 dns_servers）
if [ ! -f "$CFG" ]; then
  cp -f "$MODDIR/config/config.json" "$CFG" 2>/dev/null
fi

# Android 没有 /etc/resolv.conf，必须显式指定 DNS，否则解析全落本机 :53 而失败
export WB2A_DNS="${WB2A_DNS:-223.5.5.5,119.29.29.29}"

# 面板「停止服务」的停驻标记：网关退出前写它，watcher 见标记就跟着退出、不再拉起。
# 新装的 config.json 里已有这个键，但**老用户升级模块时配置文件不会被覆盖**（只在
# 文件不存在时才复制新的），于是他们的配置里没有该键 —— 那样点「停止服务」只会让
# 进程退出、随即被 watcher 拉回来，看起来像没停掉。这里用环境变量兜底：
# 仅当配置里确实没有这个键时才注入（用户显式配了就以配置为准）。
if [ -f "$CFG" ] && ! grep -q '"shutdown_marker"' "$CFG" 2>/dev/null; then
  export WB2A_SHUTDOWN_MARKER="$DATA_DIR/stop_request"
fi

# 出站 TLS：手机 VPN / 抓包工具的中间人 CA 装在「用户级」证书库
# (/data/misc/user/0/cacerts-added)，而 Go 静态二进制只读系统级证书目录，
# 于是出站一律报 x509: certificate signed by unknown authority。
# 把代理 CA 的 PEM 汇总到 $DATA_DIR/ca.pem（多条可拼接）后，此处自动并入信任池：
#   cat /data/misc/user/0/cacerts-added/*.0 > /data/adb/workbuddy2api/ca.pem
if [ -z "$WB2A_CA_FILE" ] && [ -f "$DATA_DIR/ca.pem" ]; then
  export WB2A_CA_FILE="$DATA_DIR/ca.pem"
fi

# ---------- 安全兜底 ----------
# 监听非环回地址（:7863 / 0.0.0.0:7863）却没设 api_key，等于把账号额度公开给整个
# 局域网。这种组合下自动生成一个随机密钥写回配置，并把密钥打印出来。
ensure_api_key() {
  [ -f "$CFG" ] || return 0
  listen=$(sed -n 's/.*"listen"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$CFG" 2>/dev/null | head -n 1)
  case "$listen" in
    ""|127.0.0.1:*|localhost:*|"[::1]:"*) return 0 ;;
  esac
  key=$(sed -n 's/.*"api_key"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$CFG" 2>/dev/null | head -n 1)
  [ -n "$key" ] && return 0

  raw=$(od -An -tx1 -N 18 /dev/urandom 2>/dev/null | tr -d ' \n')
  [ -n "$raw" ] || return 0
  newkey="sk-$raw"
  if sed -i "s|\"api_key\"[[:space:]]*:[[:space:]]*\"\"|\"api_key\": \"$newkey\"|" "$CFG" 2>/dev/null; then
    echo "[workbuddy2api] listen=$listen 会暴露到局域网，已自动生成 api_key：$newkey"
  fi
}
ensure_api_key

# ---------- 二进制路径 ----------
# 自更新落在 $DATA_DIR/bin/wb2api（覆盖层），它优先；其次用模块自带的那份。
# 与 watcher.sh 的 resolve_bin 保持一致，否则自更新后会被拉回老版本。
resolve_bin() {
  if [ -x "$DATA_DIR/bin/wb2api" ]; then
    printf '%s' "$DATA_DIR/bin/wb2api"
  else
    printf '%s' "$MODDIR/bin/wb2api"
  fi
}

# 无守护时直接拉起（与 watcher 的 start_service 等价，少一层看门狗）。
start_gateway_direct() {
  _bin=$(resolve_bin)
  if [ ! -x "$_bin" ]; then
    echo "[workbuddy2api] 找不到可执行文件 $_bin" >> "$WATCHLOG"
    return 1
  fi
  cd "$DATA_DIR" || return 1
  nohup "$_bin" -config "$CFG" >> "$LOG" 2>&1 &
  _new=$!
  echo "$_new" > "$PIDFILE"
  chmod 600 "$PIDFILE" 2>/dev/null
  # 少了一层守护，oom 保护更要保住（低内存时别被 LMK 直接回收）
  [ -w "/proc/$_new/oom_score_adj" ] && echo -1000 > "/proc/$_new/oom_score_adj" 2>/dev/null
  echo "[workbuddy2api] gateway started without watcher (pid=$_new, bin=$_bin)" >> "$WATCHLOG"
  return 0
}

# ---------- 交给守护（或直接拉起） ----------
# PID 由 watcher 自己写（它要做单实例检测），这里不代写——否则会把一个已退出
# 进程的 pid 记进 watcher.pid，让后续判断全部失真。
if [ -f "$NO_WATCH_FLAG" ]; then
  echo "[workbuddy2api] 检测到 disable_watcher，跳过常驻守护，直接拉起网关" >> "$WATCHLOG"
  start_gateway_direct
elif [ -f "$MODDIR/watcher.sh" ]; then
  nohup sh "$MODDIR/watcher.sh" >> "$WATCHLOG" 2>&1 &
  sleep 2
  wp=$(cat "$WPIDFILE" 2>/dev/null)
  if [ -n "$wp" ] && kill -0 "$wp" 2>/dev/null; then
    echo "[workbuddy2api] watcher started (pid=$wp)"
  else
    echo "[workbuddy2api] watcher 未就绪，见 $WATCHLOG"
  fi
else
  # 极端情况（模块被裁剪过）：退化为直接启动，至少保证服务可用
  echo "[workbuddy2api] 缺少 watcher.sh，退化为直接启动网关" >> "$WATCHLOG"
  start_gateway_direct
fi
