#!/system/bin/sh
# WorkBuddy2API —— 模块内自更新
#
# 这是 CI（magisk-release.yml）那条链路的「拉」的一端：CI 每次 push main 都会把
# 三平台二进制 + 校验和 + 清单 latest.txt 传到 Release，这里把它取回来。
#
# 流程：
#   1. 取锁 → 下载 latest.txt → 与本地 bin/version.txt 折算出的 versionCode 比较
#   2. 更新可用则下载对应架构的二进制，校验 sha256 与 ELF 头
#   3. 停服务 → 备份 → 原子替换到 $DATA_DIR/bin/wb2api → 记录新版本 → 重启
#   4. 重启后自检端口；起不来就回滚到上一版并重启
#
# 为什么装到 $DATA_DIR/bin 而不是直接覆盖模块目录：
#   a) 部分 ROM 上模块目录是只读挂载；
#   b) 升级 / 卸载模块不会把已更新的二进制带走，也不会让模块包的校验和失真。
#   watcher.sh 会优先使用这个覆盖层。
#
# 用法：
#   sh updater.sh          # 检查并更新
#   sh updater.sh check    # 只检查，不下载
# 更新源（默认指向本 fork 的 Release，可换成镜像以加速）：
#   echo 'https://gh-proxy.com/https://github.com/mdsanbin/workbuddy2api-panel/releases/latest/download' \
#     > /data/adb/workbuddy2api/update_base
#   也可用环境变量 WB2A_UPDATE_BASE 覆盖。

MODDIR=${0%/*}
DATA_DIR=/data/adb/workbuddy2api
BIN_DIR="$DATA_DIR/bin"
BIN="$BIN_DIR/wb2api"
NEW="$BIN_DIR/wb2api.new"
PREV="$BIN_DIR/wb2api.prev"
VERFILE="$BIN_DIR/version.txt"
LOG="$DATA_DIR/updater.log"
LOCK="$DATA_DIR/.update.lock"
CFG="$DATA_DIR/config.json"
PIDFILE="$DATA_DIR/wb2api.pid"
WPIDFILE="$DATA_DIR/watcher.pid"

PACKAGED_BIN="$MODDIR/bin/wb2api"
PACKAGED_VER="$MODDIR/bin/version.txt"

DEFAULT_BASE="https://github.com/mdsanbin/workbuddy2api-panel/releases/latest/download"
MAX_LOG_BYTES=524288

MODE="${1:-update}"

have() { command -v "$1" >/dev/null 2>&1; }

say() {
  echo "$*"
  echo "[$(date '+%m-%d %H:%M:%S')] $*" >> "$LOG" 2>/dev/null
}

tmo() {
  if have timeout; then timeout 120 "$@"; else "$@"; fi
}

# 下载：curl → wget → magisk/ksu 自带 busybox，逐级回退
fetch() {
  _url="$1"
  _out="$2"
  rm -f "$_out" 2>/dev/null
  if have curl; then
    tmo curl -fsSL --retry 2 -o "$_out" "$_url" && return 0
  fi
  if have wget; then
    tmo wget -q -O "$_out" "$_url" && return 0
  fi
  for _bb in /data/adb/ksu/bin/busybox /data/adb/magisk/busybox; do
    [ -x "$_bb" ] || continue
    tmo "$_bb" wget -q -O "$_out" "$_url" && return 0
  done
  return 1
}

sha_of() {
  if have sha256sum; then
    sha256sum "$1" 2>/dev/null | awk '{print $1}'
    return 0
  fi
  for _bb in /data/adb/ksu/bin/busybox /data/adb/magisk/busybox; do
    [ -x "$_bb" ] || continue
    "$_bb" sha256sum "$1" 2>/dev/null | awk '{print $1}'
    return 0
  done
  return 1
}

# ELF 头校验：防止把错误页 / 重定向页当成二进制装上去
is_elf() {
  [ -f "$1" ] || return 1
  head -c 4 "$1" 2>/dev/null | od -An -tx1 2>/dev/null | tr -d ' \n' | grep -qi '^7f454c46'
}

# 与 CI 同一套折算：a*10000 + b*100 + c（"1.13.0-panel" → 11300）
version_code() {
  _v=${1%%-*}
  _a=${_v%%.*}
  _rest=${_v#*.}
  # 只有真的存在第三段时才取它：否则 "1.2" 会落到 10202，与 CI 的 10200 不一致
  case "$_rest" in
    *.*) _b=${_rest%%.*}; _c=${_rest#*.} ;;
    *)   _b=$_rest;        _c=0 ;;
  esac
  case "$_a" in ''|*[!0-9]*) _a=0 ;; esac
  case "$_b" in ''|*[!0-9]*) _b=0 ;; esac
  case "$_c" in ''|*[!0-9]*) _c=0 ;; esac
  echo $((_a * 10000 + _b * 100 + _c))
}

local_version() {
  if [ -f "$VERFILE" ]; then
    head -n 1 "$VERFILE" 2>/dev/null | tr -d '\r\n'
    return 0
  fi
  if [ -f "$PACKAGED_VER" ]; then
    head -n 1 "$PACKAGED_VER" 2>/dev/null | tr -d '\r\n'
    return 0
  fi
  # 老模块没有 version.txt：从二进制里捞出形如 1.13.0-panel 的版本串
  _bin="$BIN"
  [ -x "$_bin" ] || _bin="$PACKAGED_BIN"
  [ -f "$_bin" ] || return 1
  grep -a -oE '[0-9]+\.[0-9]+\.[0-9]+-panel' "$_bin" 2>/dev/null | head -n 1
}

pid_of() {
  [ -f "$1" ] || return 1
  _pid=$(cat "$1" 2>/dev/null)
  case "$_pid" in ''|*[!0-9]*) return 1 ;; esac
  printf '%s' "$_pid"
}

# 进程身份判据：守护是 sh <dir>/watcher.sh，网关是 <dir>/bin/wb2api。两者同在
# workbuddy2api 目录下，只用目录名区分会把守护误判成网关，故按脚本名区分。
# 读不到 cmdline（SELinux 拦）时退化为「存在即算」。
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

watcher_running() {
  _w=$(pid_of "$WPIDFILE") || return 1
  kill -0 "$_w" 2>/dev/null || return 1
  is_watcher_pid "$_w" || return 1
  return 0
}

read_port() {
  _p=$(sed -n 's/.*"listen"[[:space:]]*:[[:space:]]*"[^":]*:\([0-9][0-9]*\)".*/\1/p' "$CFG" 2>/dev/null | head -n 1)
  case "$_p" in ''|*[!0-9]*) _p=7863 ;; esac
  echo "$_p"
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

stop_direct() {
  _p=$(pid_of "$PIDFILE") || { rm -f "$PIDFILE"; return 0; }
  if is_gateway_pid "$_p"; then
    kill "$_p" 2>/dev/null
    _i=0
    while [ "$_i" -lt 10 ] && kill -0 "$_p" 2>/dev/null; do
      sleep 1
      _i=$((_i + 1))
    done
    kill -0 "$_p" 2>/dev/null && kill -9 "$_p" 2>/dev/null
  fi
  rm -f "$PIDFILE"
}

start_direct() {
  _bin="$BIN"
  [ -x "$_bin" ] || _bin="$PACKAGED_BIN"
  cd "$DATA_DIR" || return 1
  nohup "$_bin" -config "$CFG" >> "$DATA_DIR/wb2api.log" 2>&1 &
  _new=$!
  echo "$_new" > "$PIDFILE"
  chmod 600 "$PIDFILE" 2>/dev/null
  [ -w "/proc/$_new/oom_score_adj" ] && echo -1000 > "/proc/$_new/oom_score_adj" 2>/dev/null
  return 0
}

# 有守护时这里什么都不用做：更新期间守护被 LOCK 按住不会重启，锁一释放它就会拉起
# 新二进制（这正是「重启权单一」）。只有守护缺席（disable_watcher）时才自己停+起。
restart_gateway() {
  if watcher_running; then
    say "重启交由守护处理（锁已释放，它将拉起新版本）"
    return 0
  fi
  stop_direct
  start_direct
  return 0
}

verify_started() {
  _i=0
  while [ "$_i" -lt 30 ]; do
    port_listening && return 0
    sleep 1
    _i=$((_i + 1))
  done
  return 1
}

# ---------- 主流程 ----------
if ! mkdir "$LOCK" 2>/dev/null; then
  say "另一个更新正在进行，退出"
  exit 0
fi
trap 'rmdir "$LOCK" 2>/dev/null' EXIT INT TERM HUP

mkdir -p "$BIN_DIR" 2>/dev/null

# 日志轮转（量很小，超阈值直接挪走一份）
_sz=$(wc -c < "$LOG" 2>/dev/null)
case "$_sz" in ''|*[!0-9]*) ;; *)
  [ "$_sz" -gt "$MAX_LOG_BYTES" ] && mv -f "$LOG" "$LOG.1" 2>/dev/null
  ;;
esac

BASE="$DEFAULT_BASE"
[ -n "$WB2A_UPDATE_BASE" ] && BASE="$WB2A_UPDATE_BASE"
if [ -f "$DATA_DIR/update_base" ]; then
  _b=$(head -n 1 "$DATA_DIR/update_base" 2>/dev/null | tr -d '\r\n')
  [ -n "$_b" ] && BASE="$_b"
fi
BASE="${BASE%/}"

case "$(uname -m)" in
  aarch64|arm64) ASSET="wb2api-linux-arm64"; SHAKEY="sha256_linux_arm64" ;;
  x86_64|amd64)  ASSET="wb2api-linux-amd64"; SHAKEY="sha256_linux_amd64" ;;
  *) say "不支持的架构 $(uname -m)，跳过自更新"; exit 0 ;;
esac

CUR_VER=$(local_version)
[ -n "$CUR_VER" ] || CUR_VER="未知"
CUR_CODE=$(version_code "$CUR_VER")

say "本地版本：$CUR_VER (code=$CUR_CODE)  来源=$BASE"

TMP_MANIFEST="$BIN_DIR/.latest.txt"
if ! fetch "$BASE/latest.txt" "$TMP_MANIFEST"; then
  say "清单下载失败（$BASE/latest.txt）——网络不通或该仓库尚未跑过 CI 发布"
  exit 0
fi

read_key() { grep -m1 "^$1=" "$TMP_MANIFEST" 2>/dev/null | cut -d= -f2- | tr -d '\r\n'; }
NEW_VER=$(read_key version)
NEW_CODE=$(read_key versioncode)
NEW_SHA=$(read_key "$SHAKEY")

if [ -z "$NEW_VER" ] || [ -z "$NEW_CODE" ]; then
  say "清单格式异常，放弃（内容首行：$(head -n 1 "$TMP_MANIFEST" 2>/dev/null)）"
  exit 0
fi

case "$NEW_CODE" in ''|*[!0-9]*) NEW_CODE=$(version_code "$NEW_VER") ;; esac

say "远端版本：$NEW_VER (code=$NEW_CODE)"

if [ "$MODE" = "check" ]; then
  if [ "$NEW_CODE" -gt "$CUR_CODE" ]; then
    say "有可用更新：$CUR_VER → $NEW_VER"
  else
    say "已是最新"
  fi
  exit 0
fi

if [ "$NEW_CODE" -le "$CUR_CODE" ]; then
  say "已是最新，无需更新"
  exit 0
fi

if [ -z "$NEW_SHA" ]; then
  say "清单里没有 $SHAKEY 校验和，为安全起见放弃更新"
  exit 1
fi

say "开始下载 $ASSET（$NEW_VER）"
if ! fetch "$BASE/$ASSET" "$NEW"; then
  say "二进制下载失败"
  rm -f "$NEW"
  exit 1
fi

GOT_SHA=$(sha_of "$NEW")
case "$GOT_SHA" in
  ''|*[!0-9a-fA-F]*) say "无法计算校验和（缺 sha256sum？）"; rm -f "$NEW"; exit 1 ;;
esac

if [ "$(echo "$GOT_SHA" | tr 'A-Z' 'a-z')" != "$(echo "$NEW_SHA" | tr 'A-Z' 'a-z')" ]; then
  say "校验和不匹配，放弃：期望 $NEW_SHA 实际 $GOT_SHA"
  rm -f "$NEW"
  exit 1
fi

if ! is_elf "$NEW"; then
  say "下载到的不是 ELF 可执行文件，放弃"
  rm -f "$NEW"
  exit 1
fi

chmod 755 "$NEW" 2>/dev/null

say "校验通过（sha256=${GOT_SHA}），开始替换"
CUR_BIN="$BIN"
[ -x "$CUR_BIN" ] || CUR_BIN="$PACKAGED_BIN"
[ -f "$CUR_BIN" ] && cp -f "$CUR_BIN" "$PREV" 2>/dev/null

# 必须让网关先退出：正在运行的可执行文件无法替换（ETXTBSY），rename 也救不了。
# 事件驱动守护这时会被 wait 唤醒，但它看到 LOCK 还在，会按住不重启，等我们放锁。
stop_direct

if ! mv -f "$NEW" "$BIN" 2>/dev/null; then
  say "替换失败（$BIN 不可写？）"
  rm -f "$NEW"
  rmdir "$LOCK" 2>/dev/null
  restart_gateway
  exit 1
fi

echo "$NEW_VER" > "$VERFILE"
say "已更新到 $NEW_VER"

# 先放锁再自检：守护必须等锁消失才会拉起新版本，自检放在放锁之后才有意义。
rmdir "$LOCK" 2>/dev/null
trap - EXIT INT TERM HUP
restart_gateway

if verify_started; then
  say "更新完成并已通过启动自检：$CUR_VER → $NEW_VER"
  exit 0
fi

say "新版本启动自检失败，回滚到 $CUR_VER"
if [ -f "$PREV" ]; then
  # 重新取锁：回滚期间不能让守护抢先拉起那份启动失败的二进制
  mkdir "$LOCK" 2>/dev/null
  trap 'rmdir "$LOCK" 2>/dev/null' EXIT INT TERM HUP
  stop_direct
  mv -f "$PREV" "$BIN" 2>/dev/null
  echo "$CUR_VER" > "$VERFILE"
  rmdir "$LOCK" 2>/dev/null
  trap - EXIT INT TERM HUP
  restart_gateway
  sleep 3
  if verify_started; then
    say "已回滚，网关恢复正常"
  else
    say "回滚后仍未能启动，请查看 $DATA_DIR/wb2api.log"
  fi
else
  say "没有可用备份，请重新刷入模块"
fi
exit 1
