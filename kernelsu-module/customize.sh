#!/system/bin/sh
# WorkBuddy2API KernelSU / Magisk 模块 —— 安装脚本
# 由 KernelSU / Magisk 在刷入时以 root 执行，MODPATH 指向解压后的模块目录。

# 管理器（KernelSU / Magisk）自带 ui_print；只有在没有时才补一个兜底实现。
# 注意：不能先定义再 unset——那会把管理器自带的那个一起删掉，之后满屏 not found。
if ! command -v ui_print >/dev/null 2>&1; then
  ui_print() { echo "$1"; }
fi

SKIPUNZIP=0

VER=$(sed -n 's/^version=//p' "$MODPATH/module.prop" 2>/dev/null | head -n 1)
[ -n "$VER" ] || VER="?"

ui_print "*******************************"
ui_print " WorkBuddy2API 网关"
ui_print " 模块版本: $VER"
ui_print "*******************************"

# 兜底：如果刷入环境没提供 set_perm（非 Magisk 系），用 chmod 顶上
if ! command -v set_perm >/dev/null 2>&1; then
  set_perm() { chmod "$4" "$1" 2>/dev/null; }
fi

# 二进制与脚本必须有可执行位（zip 里已带 0755，这里再兜一次）
set_perm "$MODPATH/bin/wb2api"     0 0 0755
set_perm "$MODPATH/service.sh"     0 0 0755
set_perm "$MODPATH/watcher.sh"     0 0 0755
set_perm "$MODPATH/updater.sh"     0 0 0755
set_perm "$MODPATH/action.sh"      0 0 0755
set_perm "$MODPATH/uninstall.sh"   0 0 0755
set_perm "$MODPATH/customize.sh"   0 0 0755

# 数据目录（账号 / 配置 / 日志都放这里，升级模块不会丢）
mkdir -p /data/adb/workbuddy2api/auths /data/adb/workbuddy2api/data 2>/dev/null
chmod 700 /data/adb/workbuddy2api 2>/dev/null

ui_print "- 安装完成，重启后自动启动（由 watcher.sh 常驻守护，崩溃会自动拉起）"
ui_print "- 点本模块的「操作」按钮即可打开面板"
