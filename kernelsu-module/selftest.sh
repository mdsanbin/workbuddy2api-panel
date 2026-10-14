#!/bin/sh
# WorkBuddy2API 模块自检
#
# 把 Android 上会跑到的关键逻辑用等价输入在本地跑一遍。改完脚本跑一次，能挡住
# 「sed 表达式写错 / 版本折算与 CI 不一致 / 端口解析失效」这类不会报错、只会静默
# 失灵的改动。版本折算与端口解析是直接从脚本里抽真函数来测的，不会测到副本。
#
#   sh kernelsu-module/selftest.sh

cd "$(dirname "$0")" || exit 1
MOD="."
CFG="$MOD/config/config.json"

PY=""
for c in python3 python py; do
  if command -v "$c" >/dev/null 2>&1; then
    PY="$c"
    break
  fi
done

TMP=${TMPDIR:-/tmp}/wb2a_selftest.$$
rm -f "$TMP"/* 2>/dev/null
mkdir -p "$TMP"

pass=0
fail=0
ck() {
  if [ "$2" = "$3" ]; then
    echo "  PASS  $1"
    pass=$((pass + 1))
  else
    echo "  FAIL  $1  |  期望=[$2]  实际=[$3]"
    fail=$((fail + 1))
  fi
}

echo "== 1. 从 config.json 解析 listen / api_key =="
LISTEN=$(sed -n 's/.*"listen"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$CFG" | head -n 1)
ck "listen = 环回地址" "127.0.0.1:7863" "$LISTEN"
ck "从 listen 解析端口" "7863" "$(printf '%s' "$LISTEN" | sed -n 's/.*:\([0-9][0-9]*\)$/\1/p')"
ck "模板 api_key 为空" "" "$(sed -n 's/.*"api_key"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$CFG" | head -n 1)"
ck "省略 host 的 listen 也能解析" "7863" "$(printf '%s' ":7863" | sed -n 's/.*:\([0-9][0-9]*\)$/\1/p')"

echo "== 2. read_port（从 updater.sh 抽真函数）=="
eval "$(sed -n '/^read_port() {/,/^}/p' "$MOD/updater.sh")"
if command -v read_port >/dev/null 2>&1; then
  ck "read_port 读到端口" "7863" "$(read_port)"
else
  echo "  FAIL  未能提取 read_port"
  fail=$((fail + 1))
fi

echo "== 3. 非环回 + 空 key 的自动兜底（sed -i 写回）=="
cp "$CFG" "$TMP/c.json"
sed -i 's|"listen": "127.0.0.1:7863"|"listen": ":7863"|' "$TMP/c.json" 2>/dev/null ||
  sed -i '' 's|"listen": "127.0.0.1:7863"|"listen": ":7863"|' "$TMP/c.json"
newkey="sk-deadbeefcafe1234"
sed -i "s|\"api_key\"[[:space:]]*:[[:space:]]*\"\"|\"api_key\": \"$newkey\"|" "$TMP/c.json" 2>/dev/null ||
  sed -i '' "s|\"api_key\"[[:space:]]*:[[:space:]]*\"\"|\"api_key\": \"$newkey\"|" "$TMP/c.json"
ck "空 key 被替换" "$newkey" "$(sed -n 's/.*"api_key"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$TMP/c.json" | head -n 1)"
if [ -n "$PY" ]; then
  if "$PY" -c "import json,sys; json.load(open(sys.argv[1],encoding='utf-8'))" "$TMP/c.json" 2>/dev/null; then
    echo "  PASS  改写后仍是合法 JSON"
    pass=$((pass + 1))
  else
    echo "  FAIL  改写后 JSON 被破坏"
    fail=$((fail + 1))
  fi
else
  echo "  SKIP  本机无 python，跳过 JSON 校验"
fi

echo "== 4. 版本号折算（从 updater.sh 抽真函数，须与 CI 一致）=="
eval "$(sed -n '/^version_code() {/,/^}/p' "$MOD/updater.sh")"
if command -v version_code >/dev/null 2>&1; then
  echo "  PASS  已提取 version_code"
  pass=$((pass + 1))
else
  echo "  FAIL  未能提取 version_code"
  fail=$((fail + 1))
fi
ck "1.13.0-panel" "11300" "$(version_code 1.13.0-panel)"
ck "1.14.0-panel" "11400" "$(version_code 1.14.0-panel)"
ck "2.0.1" "20001" "$(version_code 2.0.1)"
ck "1.2（两段，不能算成 10202）" "10200" "$(version_code 1.2)"

echo "== 5. latest.txt 清单解析 =="
cat > "$TMP/latest.txt" <<'EOF'
version=1.14.0-panel
versioncode=11400
sha256_linux_arm64=0123456789abcdef
EOF
rk() { grep -m1 "^$1=" "$TMP/latest.txt" 2>/dev/null | cut -d= -f2- | tr -d '\r\n'; }
ck "读 version" "1.14.0-panel" "$(rk version)"
ck "读 versioncode" "11400" "$(rk versioncode)"
ck "读 sha256_linux_arm64" "0123456789abcdef" "$(rk sha256_linux_arm64)"

echo "== 6. 端口 LISTEN 探测（/proc/net/tcp 解析，等价假数据）=="
{
  printf '%s\n' "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"
  printf '%s\n' "   0: 00000000:1EB7 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1"
} > "$TMP/tcp"
{ printf '%s\n' "  sl  local_address rem_address   st"; printf '%s\n' "   0: 00000000:1EB7 00000000:0000 06 0 0"; } > "$TMP/tcp_tw"
hex=$(printf '%04X' 7863)
hex2=$(printf '%04X' 9999)
awk -v suf=":$hex" 'NR>1 && $4=="0A" && index($2, suf) > 0 { hit=1 } END { exit !hit }' "$TMP/tcp" &&
  { echo "  PASS  7863 的 LISTEN 行被识别"; pass=$((pass + 1)); } ||
  { echo "  FAIL  7863 的 LISTEN 行未被识别"; fail=$((fail + 1)); }
awk -v suf=":$hex2" 'NR>1 && $4=="0A" && index($2, suf) > 0 { hit=1 } END { exit !hit }' "$TMP/tcp" &&
  { echo "  FAIL  未监听的端口被误判"; fail=$((fail + 1)); } ||
  { echo "  PASS  未监听的端口不误判"; pass=$((pass + 1)); }
awk -v suf=":$hex" 'NR>1 && $4=="0A" && index($2, suf) > 0 { hit=1 } END { exit !hit }' "$TMP/tcp_tw" &&
  { echo "  FAIL  TIME_WAIT 被当成 LISTEN"; fail=$((fail + 1)); } ||
  { echo "  PASS  TIME_WAIT 不算监听"; pass=$((pass + 1)); }

echo "== 7. 保活开关与事件循环 =="
# 7.1 resolve_bin：自更新覆盖层（$DATA_DIR/bin/wb2api）必须优先于模块自带的，
# 否则自更新后重启（无守护时由 service.sh / action.sh 直接拉起）会退回老版本。
# 从 service.sh 与 watcher.sh 各抽一份真函数，顺带断言两者行为一致。
# 先探测「可执行位」在本环境是否真的生效：Windows 的 /tmp 是 noacl 挂载，
# chmod 无效且 [ -x ] 恒假，此时上面那两条判据不可能通过——那是判据失效而非
# 逻辑有错。不探测就会得到假红（Windows）或假绿（夹具碰巧命中），两者都要避免。
_probe="$TMP/xprobe"
printf x > "$_probe" 2>/dev/null
chmod 755 "$_probe" 2>/dev/null
if [ -x "$_probe" ]; then
  eval "$(sed -n '/^resolve_bin() {/,/^}/p' "$MOD/service.sh")"
  MODDIR="/fake/moddir"
  DATA_DIR="$TMP/data"
  mkdir -p "$DATA_DIR/bin" 2>/dev/null
  : > "$DATA_DIR/bin/wb2api"
  ck "覆盖层存在但不可执行 → 回落模块目录" "$MODDIR/bin/wb2api" "$(resolve_bin)"
  chmod 755 "$DATA_DIR/bin/wb2api" 2>/dev/null
  _svc=$(resolve_bin)
  ck "覆盖层可执行 → 覆盖层优先（service.sh）" "$DATA_DIR/bin/wb2api" "$_svc"
  # 再抽 watcher.sh 里的同名函数：两份实现都在用，必须不漂移
  eval "$(sed -n '/^resolve_bin() {/,/^}/p' "$MOD/watcher.sh")"
  ck "覆盖层可执行 → 覆盖层优先（watcher.sh 同判）" "$DATA_DIR/bin/wb2api" "$(resolve_bin)"
else
  echo "  SKIP  本机文件系统不支持可执行位（noacl/NTFS）"
  echo "        → resolve_bin 的 -x 分支在本机【未验证】，请到 Android / Linux / WSL 上跑同一脚本"
  : > "$TMP/skipped"
fi

# 7.2 崩溃退避与「退避中的重启请求」：事件驱动守护平时完全不轮询，退避是唯一会主动
# sleep 的路径（崩溃循环时），而那时用户更需要能一键把它捞回来。
eval "$(sed -n '/^backoff_for() {/,/^}/p' "$MOD/watcher.sh")"
eval "$(sed -n '/^sleep_backoff() {/,/^}/p' "$MOD/watcher.sh")"
ck "退避档位：第 1 次 5s" "5" "$(backoff_for 1)"
ck "退避档位：第 2 次 15s" "15" "$(backoff_for 2)"
ck "退避档位：第 3 次 60s" "60" "$(backoff_for 3)"
ck "退避档位：第 4 次起 300s" "300" "$(backoff_for 9)"

# 注意两点（都踩过）：
#   1) stub 的计数器**不能**叫 _n —— sleep_backoff 内部就用 _n 做倒计时，
#      同名会让 stub 的 +1 与函数的 -1 相互抵消，直接死循环；
#   2) 两个用例各用一个**全新文件名**，不要靠 rm 清理：删除类命令在 Windows 侧会被
#      安全保护拦下（SAFE_DELETE_INVALID_PATH），清理失败会让第二个用例读到残留状态。
REQ="$TMP/req1"
_calls=0
sleep() {
  _calls=$((_calls + 1))
  if [ "$_calls" -gt 200 ]; then
    echo "  FAIL  sleep 被调用超过 200 次，疑似死循环"
    exit 1
  fi
  [ "$_calls" -ge 2 ] && : > "$REQ"
}
sleep_backoff 30
_rc=$?
_mid_calls=$_calls

REQ="$TMP/req2"
_calls=0
sleep() {
  _calls=$((_calls + 1))
  if [ "$_calls" -gt 200 ]; then
    echo "  FAIL  sleep 被调用超过 200 次，疑似死循环"
    exit 1
  fi
}
sleep_backoff 3
_rc_full=$?
_full_calls=$_calls
unset -f sleep 2>/dev/null
ck "退避中出现的重启请求会中断等待" "1" "$_rc"
ck "  且在第二个 1s 片前就感知（2 次 sleep 后退出）" "2" "$_mid_calls"
ck "无请求时按秒睡满（返回 0）" "0" "$_rc_full"
ck "  确实睡满 3 秒" "3" "$_full_calls"

# 7.3 实现约定回归锁：守护必须真的走「父进程等子进程」，不能悄悄退回轮询
_n_wait=$(grep -c 'wait "\$CHILD"' "$MOD/watcher.sh")
ck "watcher 用 wait 阻塞等子进程退出" "1" "$_n_wait"
_n_poll=$(grep -c 'sleep 15' "$MOD/watcher.sh")
ck "watcher 不应再有固定 15s 探活轮询" "0" "$_n_poll"
_n_si=$(grep -c 'sleep_interval' "$MOD/watcher.sh")
ck "watcher 不应再引用 sleep_interval" "0" "$_n_si"

# 7.4 进程身份判据：守护是 sh <dir>/watcher.sh，网关是 <dir>/bin/wb2api，两者同在
# workbuddy2api 目录下——只用目录名区分会把守护误判成网关（踩过：action.sh 因此
# 认为守护缺席、绕过委托自己拉起，形成双重启动的竞态）。
# 先用一个带标记的探针确认 /proc/<pid>/cmdline 可用，不可用（MSYS 等）就跳过，
# 否则会假失败。
_probe_cmd() {
  sh -c 'sleep 5; :' zz-cmdline-probe &
  _pp=$!
  sleep 1
  _cc=$(tr '\0' ' ' < "/proc/$_pp/cmdline" 2>/dev/null)
  kill "$_pp" 2>/dev/null
  case "$_cc" in
    *zz-cmdline-probe*) return 0 ;;
  esac
  return 1
}

if _probe_cmd; then
  eval "$(sed -n '/^cmdline_of() {/,/^}/p' "$MOD/watcher.sh")"
  eval "$(sed -n '/^is_gateway_pid() {/,/^}/p' "$MOD/watcher.sh")"
  eval "$(sed -n '/^is_watcher_pid() {/,/^}/p' "$MOD/watcher.sh")"
  # 注意 '; :' —— dash 对「-c 里的最后一条命令」会做 exec 优化，会让 cmdline 丢掉标记
  sh -c 'sleep 20; :' wb2api-fake &
  _gp=$!
  sh -c 'sleep 20; :' watcher.sh &
  _wp2=$!
  sh -c 'sleep 20; :' unrelated &
  _up=$!
  sleep 1
  _yn() { if "$@"; then echo yes; else echo no; fi; }
  ck "网关进程被认作网关" "yes" "$(_yn is_gateway_pid "$_gp")"
  ck "网关进程不被认作守护" "no" "$(_yn is_watcher_pid "$_gp")"
  ck "守护进程被认作守护" "yes" "$(_yn is_watcher_pid "$_wp2")"
  ck "守护进程不被认作网关" "no" "$(_yn is_gateway_pid "$_wp2")"
  ck "无关进程不被认作网关" "no" "$(_yn is_gateway_pid "$_up")"
  ck "无关进程不被认作守护" "no" "$(_yn is_watcher_pid "$_up")"
  kill "$_gp" "$_wp2" "$_up" 2>/dev/null
else
  echo "  SKIP  本机 /proc/<pid>/cmdline 不可用，进程身份判据未验证"
  : > "$TMP/skipped"
fi

echo "== 8. shell 语法 =="
for f in "$MOD"/*.sh; do
  if sh -n "$f" 2>"$TMP/err"; then
    echo "  PASS  $(basename "$f")"
    pass=$((pass + 1))
  else
    echo "  FAIL  $(basename "$f") :: $(cat "$TMP/err")"
    fail=$((fail + 1))
  fi
done

echo "== 9. 行尾必须为 LF =="
if [ -n "$PY" ]; then
  "$PY" - "$MOD" <<'PY'
import pathlib, sys
d = pathlib.Path(sys.argv[1])
bad = [str(p) for p in sorted(d.rglob("*"))
       if p.is_file() and p.name not in ("wb2api",) and b"\r" in p.read_bytes()]
print("  PASS  含 CR 的文件：无" if not bad else f"  FAIL  含 CR：{bad}")
PY
else
  echo "  SKIP  本机无 python，跳过"
fi

echo
echo "==================== 汇总 ===================="
echo "通过 $pass 项，失败 $fail 项"
if [ -f "$TMP/skipped" ]; then
  echo "注意：有判据在本机被跳过（见上方 SKIP），本机结论不完整，别当成全绿"
fi
rm -f "$TMP"/* 2>/dev/null
rmdir "$TMP" 2>/dev/null
[ "$fail" -eq 0 ] || exit 1
