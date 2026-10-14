# WorkBuddy2API · KernelSU / Magisk 模块

把 WorkBuddy / CodeBuddy 账号转成 **OpenAI 兼容 API** 的多账号网关，**开机自启**，
并带一个常驻守护进程负责崩溃自愈与自更新。不需要 Docker、不需要电脑，装上手机就能用。

- 上游项目：<https://github.com/linguo2625469/workbuddy2api-panel>
- 本模块：把上游 `cmd/server` 交叉编译为 Android/arm64 静态二进制，外加 KernelSU 模块外壳
- 内置网关版本：**1.13.0-panel**（打包时由 `build.py` 从二进制里读出，写进 `bin/version.txt`）
- 模块版本：**1.14.0**

模块自身的演进：
**v1.13.1** 内置 TLS 信任配置与 CA 自动加载；
**v1.13.2** 面板 TLS 诊断页 `/panel/tls`；
**v1.13.3** 出站 TLS 自动修；
**v1.13.4** 出站 ALPN 显式锁定 `http/1.1`；
**v1.14.0** 常驻守护（`watcher.sh`）、模块内自更新（`updater.sh`）、默认只监听 `127.0.0.1`、
打包防呆（架构 / 行尾 / 版本号校验）。

## 安装

1. 把 zip 传到手机
2. KernelSU 管理器 → **模块** → **从本地安装** → 选择 zip
3. 重启手机

## 使用

| 用途 | 地址 |
| --- | --- |
| 手机上打开面板（默认） | `http://127.0.0.1:7863/panel/` |
| 同一 WiFi 下其它设备 | `http://<手机IP>:7863/panel/`（需先开放监听，见下） |
| OpenAI 兼容接口 | `http://<手机IP>:7863/v1` |

默认只监听 `127.0.0.1`（仅手机本机能访问），开箱即用且不会把账号额度暴露给局域网。
要让同一 WiFi 下的其它设备访问，改 `/data/adb/workbuddy2api/config.json`：

```json
"listen": ":7863"
```

重启网关即可。**若此时 `api_key` 仍为空，开机脚本会自动生成一个随机密钥填进去**
（否则等于把额度公开给整个局域网），面板首次访问会要求输入，之后浏览器会记住。

首次使用：进面板 → 添加账号（OAuth 设备授权）→ 账号入池后即可调用
`/v1/chat/completions`，现有 OpenAI SDK / 客户端零改造接入。

## 操作按钮

KernelSU 管理器里点本模块的「**操作**」按钮：

1. 重启网关。**优先委托守护进程**（`watcher.sh`）去做，避免两处同时拉起同一个端口；
   守护不在时才自己动手
2. 从 `config.json` 读出 `listen` 端口，**轮询等端口真正进入 LISTEN**（最多 20s）
3. **自动用浏览器打开管理面板** `http://127.0.0.1:<端口>/panel/`
4. 回显本机地址；**仅当监听非环回时**才回显局域网地址（否则那个地址在别的设备上打不开，
   属于误导）
5. 若配置了 `api_key`，把密钥一并打印出来，方便首次访问时填入

端口是从配置里解析的，所以你把 `listen` 改成别的端口，按钮也会跟着跳对地址。

### 关掉自动弹浏览器

只重启、不弹窗：

```sh
touch /data/adb/workbuddy2api/disable_auto_open_panel    # 关闭自动打开
rm    /data/adb/workbuddy2api/disable_auto_open_panel    # 恢复自动打开
```

> 自动打开走的是系统 `am start`（多用户设备会自动取当前用户）。个别 ROM 会拦截后台弹出
> Activity，此时脚本会打印提示，手动访问上面的地址即可。

## 可靠性：事件驱动守护（静默期 0 消耗）

`watcher.sh` 在开机时由 `service.sh` 后台拉起。它**不轮询**——而是把网关作为自己的**子进程**，
再用 `wait` 阻塞等它退出：

```
watcher ── wait（内核挂起：0 CPU / 0 fork / 无定时器）──► 网关
   ▲                                                      │
   └────────── 网关一退出，内核立刻唤醒 ◄─────────────────┘
```

静默期进程处于可中断睡眠（S 状态），不做任何检查；网关一旦崩溃或被系统杀掉，**内核直接
唤醒守护**把它拉回来，毫秒级——比每 15s 轮询一轮更及时。

实测（WSL 真 Linux，mksh，用等价的长跑进程替代网关）：

| 方案 | 60 秒窗口 | 180 秒窗口 |
| --- | --- | --- |
| 旧：每 15s 轮询探活 | 2.25 ms CPU / 被调度 11 次 | **5.89 ms / 27 次**（随时长线性增长） |
| 新：事件驱动 `wait` | 0.27 ms / 3 次 | **0.29 ms / 3 次**（纹丝不动） |

再在**真 watcher 进程**上测静默 60 秒：**自身 CPU 增量 0 ns、被调度增量 0 次**。
旧方案折算每天约 5760 次唤醒 / 17280 次 fork；新方案的静默开销是**常量**，跑多久都一样。

| 能力 | 做法 |
| --- | --- |
| 自愈 | 网关退出（崩溃 / 被杀 / 主动退）由内核事件触发，毫秒级重启 |
| 退避 | 崩溃循环时按 5s → 15s → 60s → 300s 递增；网关跑满 60s 再退出视为「曾经健康」，退避归零 |
| 防杀 | 给网关与守护自身设 `oom_score_adj=-1000` |
| 轮转 | 日志超 2 MiB 轮转（守护启动时 + 每次重启前执行） |
| 集中重启 | 「操作」按钮先留 `restart_request` 标记、再终止网关；守护醒来见标记即**不计退避**立刻拉起 |
| 接管 | 守护被强杀会留下「孤儿」网关（`wait` 不到），下次启动时先终止再纳入监护 |

**代价（明确讲清）**：`wait` 只能感知进程退出，**发现不了「进程活着但服务卡死」**（僵死）。
僵死检测必须轮询，与 0 消耗不可兼得；而进程被杀 / 崩溃 / OOM 这类绝大多数场景都由内核事件
覆盖，且比轮询更及时。真要僵死检测，用下面的低频维护。

看守护是否在跑：

```sh
cat /data/adb/workbuddy2api/watcher.pid
tail -f /data/adb/workbuddy2api/watcher.log
```

### 需要定时维护或僵死检测？

默认不做任何周期性动作（这正是「0 消耗」的含义），于是日志轮转与自更新检查只在「守护启动时」
和「每次网关重启前」发生——网关要是稳定跑几个月不重启，日志就会一直涨。需要定时维护时：

```sh
echo 30 > /data/adb/workbuddy2api/housekeeping_minutes    # 每 30 分钟一次
rm      /data/adb/workbuddy2api/housekeeping_minutes      # 回到 0 消耗（重启后生效）
```

它每 N 分钟做三件事：日志轮转、自更新检查、僵死探针（进程在但端口不监听 → 终止它让守护拉起）。
代价是每天 `1440/N` 次唤醒——填 30 即每天 48 次，仍远低于旧方案的 5760 次。

只想立刻清一次日志：`: > /data/adb/workbuddy2api/wb2api.log`

### 关掉常驻守护

连那点内存也不想占（守护约 1 MB 级 RSS，是本方案唯一的常数成本）：

```sh
touch /data/adb/workbuddy2api/disable_watcher    # 关掉（重启后生效）
rm    /data/adb/workbuddy2api/disable_watcher    # 恢复（重启后生效）
```

**关掉它不影响网关功能**——转发、面板、账号管理全部照旧，只是失去：崩溃自愈、oom 保护、
日志轮转、自更新定时检查。「操作」按钮在守护缺席时会**自己完成重启**（不再委托），
手动重启依然是一键的。

## 更新：模块内自更新

CI 每次 push main 都会把二进制、校验和、清单发到 GitHub Release，模块内的
`updater.sh` 就是这条链路的「拉」的一端：

1. 下载 `latest.txt`，与本机 `bin/version.txt` 折算出的 `versionCode` 比较
2. 有新版则下载对应架构二进制，校验 **sha256** 与 **ELF 头**
3. 停服务 → 备份 → **原子替换**到 `/data/adb/workbuddy2api/bin/wb2api` → 记录版本 → 重启
4. 重启后自检端口；**起不来自动回滚**到上一版并重启

几点设计取舍：

- 更新的二进制落在 `/data/adb/workbuddy2api/bin/`（**覆盖层**），不碰模块目录。
  部分 ROM 上模块目录是只读挂载；而且这样升级 / 卸载模块都不会把它带走。
  守护每次重启时现算该用哪份二进制，所以首次更新后立刻生效。
- 检查时机：**守护启动时**与**每次网关重启前**（按 24 小时节流）。所以网关长期不重启就不会
  检查——想定时检查请开「低频维护」，或手动跑一次。关掉：`touch /data/adb/workbuddy2api/disable_auto_update`。
- 手动跑（加 `check` 只检查不下载）：

```sh
sh /data/adb/modules/workbuddy2api/updater.sh
sh /data/adb/modules/workbuddy2api/updater.sh check
```

**更新源默认指向本 fork 的 Release**，而 fork 的 Actions 默认是关的。首次使用请确认
仓库已经跑过一次发布，否则 `latest.txt` 会 404（日志里会写「清单下载失败」）。
国内下载慢的话可以换镜像：

```sh
echo 'https://gh-proxy.com/https://github.com/mdsanbin/workbuddy2api-panel/releases/latest/download' \
  > /data/adb/workbuddy2api/update_base
```

也可以用环境变量 `WB2A_UPDATE_BASE` 覆盖（桌面 / Docker 部署）。

## 文件位置

| 路径 | 说明 |
| --- | --- |
| `/data/adb/workbuddy2api/config.json` | 配置（`api_key`、`listen`、`dns_servers`、`tls_ca_file`、`tls_auto_trust` 等） |
| `/data/adb/workbuddy2api/ca.pem` | 中间人代理的 CA（PEM，多条可拼接），存在即自动信任；开启自动修后由网关自己写入 |
| `/data/adb/workbuddy2api/auths/` | 账号凭证 |
| `/data/adb/workbuddy2api/data/` | 状态 / 用量 / 请求归档 |
| `/data/adb/workbuddy2api/bin/` | 自更新下载的网关二进制（覆盖层，优先于模块自带的那份） |
| `/data/adb/workbuddy2api/update_base` | 可选：自定义更新源前缀（一行 URL） |
| `/data/adb/workbuddy2api/disable_watcher` | 可选：存在即关闭常驻守护（见「关掉常驻守护」） |
| `/data/adb/workbuddy2api/disable_auto_update` | 可选：存在即停止每 24h 的自动更新检查 |
| `/data/adb/workbuddy2api/disable_auto_open_panel` | 可选：存在即不自动弹浏览器 |
| `/data/adb/workbuddy2api/housekeeping_minutes` | 可选：填分钟数即启用低频维护（日志轮转 + 自更新检查 + 僵死探针），默认为无 |
| `/data/adb/workbuddy2api/wb2api.log` | 网关运行日志（守护开启时超 2 MiB 自动轮转） |
| `/data/adb/workbuddy2api/watcher.log` | 守护日志（含自更新输出） |
| `/data/adb/workbuddy2api/updater.log` | 自更新日志 |
| `/data/adb/workbuddy2api/wb2api.pid` / `watcher.pid` | 进程号 |

**升级模块不会覆盖这个目录**（账号不会丢）。卸载模块也不删它，要彻底清理请手动
`rm -rf /data/adb/workbuddy2api`。

## 安全提醒

模块模板默认 `listen` 是 **`127.0.0.1:7863`**——只允许手机本机访问，局域网里看不到它。

只有当你把 `listen` 改成 `:7863` / `0.0.0.0:7863` 去开放局域网时才有暴露风险。
针对这种组合，开机脚本会**自动兜底**：检测到「监听非环回地址」且「`api_key` 为空」，
就生成一个随机密钥写回 `config.json` 并打印出来。所以手动开放局域网也不会裸奔。

仍建议自己确认一遍：

- `api_key` 非空（面板首次访问会要求输入，之后浏览器记住）；或
- 保持 `listen` 为 `127.0.0.1:7863`，只在本机用。

> 旧版本模块用的是 `:7863` 且 `api_key` 为空，升级后开机脚本会自动补上密钥。

## Android 适配说明

- 二进制是 `linux/arm64` 静态编译（`CGO_ENABLED=0`），不依赖 libc，Android 可直接执行
- Android 没有 `/etc/resolv.conf`：模块已通过 `config.json` 的 `dns_servers`
  与 `WB2A_DNS` 环境变量双向指定 DNS（223.5.5.5 / 119.29.29.29），否则解析会全落本机 `:53` 而失败
- `service.sh` 会等待 `sys.boot_completed=1` 再启动守护，避免网络栈未就绪
- 守护探活走 `/proc/net/tcp` 解析端口状态，不依赖 curl / wget / busybox 是否齐全
- 所有脚本必须保持 **LF 行尾**（Android 用 mksh，CRLF 会报 `not found`）。
  仓库根 `.gitattributes` 已锁死；`build.py` 打包时还会再归一化一次

## 排障：证书错误

**症状**

```
auth state (upstream 0): Post "https://copilot.tencent.com/v2/plugin/auth/state?platform=CLI":
tls: failed to verify certificate: x509: certificate signed by unknown authority
```

**原因**

手机上有中间人代理（VPN / 抓包 / 企业网关）替换了 HTTPS 证书。这类工具的 CA 装在
**用户级**证书库 `/data/misc/user/0/cacerts-added/`，而 Go 编译出的静态二进制
（`CGO_ENABLED=0`）只读**系统级**证书目录，所以全部出站请求都因证书不受信任而失败。
这与 DNS / 防火墙无关——报错文本很容易让人误判成「网络不通」。

**修法**

> **默认已经自动修好了。** 模块 v1.13.3 起内置「出站 TLS 自动修」（`tls_auto_trust`，默认开启）：
> 网关启动后会在**后台**探测上游证书链，一旦发现系统证书池不信任（正是中间人代理的特征），
> 就把对端**实际出示**的整条链写入 `/data/adb/workbuddy2api/ca.pem` 并热加载生效。
> **不需要你做任何操作** —— 装好重启后，面板「添加账号」直接可用。
>
> 日志（`/data/adb/workbuddy2api/wb2api.log`）里会看到：
>
> ```
> TLS 自动修：已信任 copilot.tencent.com 出示的证书链（新增 1 张，复验通过）→ /data/adb/workbuddy2api/ca.pem
> ```
>
> 除了启动时修，**请求撞上证书错误时还会现场再修一次并重试**（覆盖「先开网关、后连 VPN」
> 这类启动时环境还没就绪的情况）。修不好时每 5 分钟重试一次，最多 6 轮，之后停止。
>
> 关掉它：`"tls_auto_trust": false`（或用 `WB2A_TLS_AUTO_TRUST=0` 启动）。
> 注意这是 **TOFU（首次使用即信任）**：它信任「第一次握手见到的证书」，若此刻恰好存在
> 攻击者，等于把凭证交给对方。默认清单只含本服务本来就要访问的腾讯域名，也正是这个原因。
>
> 下面 A~E 是**手动兜底**路径 —— 自动修没成功（日志有 `复验未通过` / `暂不可达`）时再用。

**A. 面板一键诊断信任**（手动，最省事）

打开面板的 TLS 诊断页：

```
http://127.0.0.1:7863/panel/tls
```

点「探测证书」→ 页面列出对端**实际出示**的证书链（签发者、有效期、是否自签、
SHA256 指纹），并直接给出结论：系统证书池是否信任、当前配置是否已通过、失败原因是什么。

再点「信任并保存」——整条链写入 `/data/adb/workbuddy2api/ca.pem` 并**热加载生效**，
无需重启；页面会复验一次并告诉你是否已通。

> 这个页面走的是服务自己的出站链路（含 `dns_servers`），所以 Android 上也能正常探测。
> 若代理对每个域名用了不同 CA，对其余报错域名各探测一次即可（改主机名重探）。

**C. 让代理 CA 被信任**（不降低安全性）

在手机终端（Termux 或 `adb shell`，需 root）执行：

```sh
cat /data/misc/user/0/cacerts-added/*.0 > /data/adb/workbuddy2api/ca.pem
chmod 644 /data/adb/workbuddy2api/ca.pem
```

然后重启网关（KernelSU 里点「操作」按钮，或重启手机）。模块检测到 `ca.pem`
会自动并入出站信任池，日志里会出现：

```
TLS: 出站信任池已并入自备 CA /data/adb/workbuddy2api/ca.pem
```

不用 `ca.pem` 也行，直接改 `/data/adb/workbuddy2api/config.json`：

```json
"tls_ca_file": "/data/adb/workbuddy2api/ca.pem"
```

> 该 CA 与系统根证书**求并集**，所以不需要走代理的直连域名不受影响。

**D. 让这些域名走直连**（最干净）

在 VPN / 代理 App 的分流规则里，把下面两个域名设为 **DIRECT / 直连**：

```
copilot.tencent.com
www.workbuddy.ai
```

它们是腾讯国内域名，本来就不需要代理；直连后没有中间人，证书问题自然消失。

**E. 最后手段：跳过校验**

不建议，仅在拿不到 CA 时临时用：

```json
"tls_insecure_skip_verify": true
```

或在启动前 `export WB2A_TLS_INSECURE=1`。这等于对上游放弃中间人防护。

## 排障：国际版查询失败（协议错配，不是证书问题）

症状：面板上只有**国际版**账号查询失败，报错形如

```
国际版显示查询失败：Post "https://www.workbuddy.ai/billing/meter/get-user-resource":
net/http: HTTP/1.x transport connection broken: malformed HTTP response
"\x00\x00\x12\x04\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x80..."
```

关键在开头那串 `\x00\x00\x12\x04`：这是 **HTTP/2 的 SETTINGS 帧头**（长度 0x12、类型
0x04），后面还会跟一个 PING 帧。也就是说对端在讲 **HTTP/2**，而客户端在按
**HTTP/1.x** 解析——**这是协议错配，跟证书、DNS、防火墙都没关系**，所以上次那套
`/panel/tls` 一键信任对它无效。

为什么只有国际版炸：实测（本机直连）

| 域名 | 客户端广告 `http/1.1` | 客户端广告 `h2` |
| --- | --- | --- |
| `www.workbuddy.ai` | 正常回 HTTP/1.1 | **严格回 h2 帧** |
| `www.codebuddy.cn` / `copilot.tencent.com` | 正常 | 网关宽容，无视 ALPN 仍回 HTTP/1.1 |

国际版严格按 ALPN 办事，国内网关宽容——所以同一个错配只在国际版上暴露。

本模块从 **v1.13.4** 起把出站 ALPN **显式锁定为 `http/1.1`**（此前只是"恰好在 TLS
层不广告任何协议"，属于隐式行为，一旦被中间盒影响就会退化成上面的错配）。

**如果仍报这个错**，说明你所在网络（VPN / 企业网关 / 运营商中间盒）无视 ALPN
径自按 h2 回帧，此时客户端说什么都没用，唯有真的讲 h2。改
`/data/adb/workbuddy2api/config.json`：

```json
"tls_alpn": "h2"
```

然后重启网关（KernelSU 里点「操作」，或重启手机），日志里会出现：

```
TLS: 出站 ALPN 已切换到 h2
```

也可以 `export WB2A_TLS_ALPN=h2`（桌面 / Docker 部署用；手机模块的开机脚本是 root
直接拉起二进制、不继承外部 shell 变量，所以手机上请改 `config.json`）。
`credit` 命令行工具同样认这个环境变量。

> `tls_alpn` 只接受 `"http/1.1"`（默认）与 `"h2"`；写别的值一律按默认档处理，
> 不会出现"广告 h2 却不会讲 h2"的半吊子状态。

## 重新构建

```sh
# 1) 交叉编译 arm64 二进制（在仓库根目录）
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 \
  go build -trimpath -ldflags "-s -w" -o kernelsu-module/bin/wb2api ./cmd/server

# 2) 打包模块 zip（会先做防呆校验，见下）
python kernelsu-module/build.py
```

`build.py` 在打包前会拦住这几类「装到手机上才发现」的错误：

- `bin/wb2api` 不是 ELF aarch64（本机是 amd64，**漏跑交叉编译时最容易踩**）
- `module.prop` 的 `versionCode` 与 `version` 折算值不一致
- `config/config.json` 不是合法 JSON
- 文本文件带 CRLF（会自动归一为 LF 并报告）

同时它会把二进制里的网关版本串抽出来写成 `bin/version.txt`，
`updater.sh` 靠它判断「本地是哪个版本」。

## 免责声明

本模块仅为个人管理自己的 WorkBuddy / CodeBuddy 账号而做的自用封装，
不提供任何账号额度，也不支持批量注册或对外售卖接口配额。
