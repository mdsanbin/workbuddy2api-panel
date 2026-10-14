// config.go 加载 JSON 配置 + 环境变量覆盖。
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/prompt"
)

// Config 顶层配置。
type Config struct {
	Listen    string `json:"listen"`     // ":7863"
	APIKey    string `json:"api_key"`    // 空 = 不鉴权
	AuthDir   string `json:"auth_dir"`   // ./auths
	StateFile string `json:"state_file"` // ./data/state.json
	// ShutdownMarker 面板「停止服务」时写入的标记文件路径（空 = 不写）。
	//
	// KernelSU 模块部署把它指到 $DATA_DIR/stop_request：模块的 watcher.sh 会在网关
	// 退出后发现该标记并自行退出，不再把网关拉起来。留空 = 只停进程（直接跑二进制的
	// 场景没有守护进程，本来就不需要这个信号）。
	ShutdownMarker string `json:"shutdown_marker,omitempty"`
	// DNSServers 出站解析用的 DNS 服务器（空 = 系统解析器）；也可用 WB2A_DNS 覆盖。
	// Android/magisk 模块里没有 /etc/resolv.conf，必须显式指定，否则解析全落本机 :53。
	DNSServers []string `json:"dns_servers,omitempty"`
	// TLSCAFile 出站 HTTPS 额外信任的 CA（PEM 文件路径，可含多张证书）；也可用 WB2A_CA_FILE 覆盖。
	//
	// 用于中间人代理场景：代理 CA 装在「用户级」证书库（Android 用户证书
	// /data/misc/user/0/cacerts-added、浏览器私有库等）时，Go 的默认根池
	// （Android/Linux 的 /system/etc/security/cacerts、Windows 系统证书库）取不到它，
	// 于是所有上游请求一律报
	//   tls: failed to verify certificate: x509: certificate signed by unknown authority
	// 填代理 CA 的 PEM 即可（与系统根求并集，不降低直连域名的安全性）。
	// 留空 = 完全保持默认行为（仅系统根池）。
	TLSCAFile string `json:"tls_ca_file,omitempty"`
	// TLSInsecureSkipVerify 跳过出站 HTTPS 证书校验（默认 false）；也可用 WB2A_TLS_INSECURE=1 覆盖。
	// 最后手段：等于对上游放弃中间人防护，仅在拿不到代理 CA 时临时使用。
	TLSInsecureSkipVerify bool `json:"tls_insecure_skip_verify,omitempty"`

	// TLSAutoTrust 出站 TLS 自动修（默认 true）：启动后在后台探测上游证书链，若系统
	// 根池不信任（= 中间人代理自签 CA），就把对端实际出示的链写入 ca.pem 并热加载
	// 生效——无需人工导出或指定 CA；请求撞上证书错误时也会现场再修一次并重试。
	//
	// 安全说明：这是 TOFU（首次使用即信任）——信任「第一次握手见到的证书」，若此刻
	// 恰好存在攻击者，等于把凭证交给对方。故内置清单只含本服务本来就要访问的腾讯
	// 域名（见 autoTrustHosts），且可用 tls_auto_trust=false 整体关闭。
	// 注意：不加 omitempty —— 默认 true，用户显式设 false 时必须能被序列化出来。
	TLSAutoTrust bool `json:"tls_auto_trust"`
	// TLSAutoTrustHosts 自动修探测的目标主机清单；空 = 内置默认（CN 上游 + global 上游）。
	// 显式配置即完全替换内置清单（不合并），避免误信任无关主机。
	// 也可用 WB2A_TLS_AUTO_TRUST_HOSTS=a.com,b.com 覆盖。
	TLSAutoTrustHosts []string `json:"tls_auto_trust_hosts,omitempty"`
	// TLSAutoTrustRetryMinutes 首轮未修好时的后台重试间隔（分钟）；<=0 = 只试一次。
	// 设备上「代理尚未就绪」（VPN 刚连上、网关刚下发策略）很常见，故默认 5 分钟一轮。
	// 也可用 WB2A_TLS_AUTO_TRUST_RETRY_MINUTES 覆盖。
	TLSAutoTrustRetryMinutes int `json:"tls_auto_trust_retry_minutes"`

	// TLSALPN 出站 ALPN 档位（TLS 层向对端「广告」的应用协议，必须与 transport 层
	// 「认识哪些协议」同调，否则会得到 malformed HTTP response——对端回 HTTP/2 帧、
	// 本客户端按 HTTP/1.x 解析；成因与实证见 internal/upstream/alpn.go）。
	//
	//	"http/1.1"（默认）只广告 http/1.1，与出站禁 h2 的既有策略同调；
	//	"h2"             广告 h2+http/1.1 并真正启用 h2。
	//
	// 什么时候需要改成 "h2"：中间盒 / VPN / 企业网关无视 ALPN 径自按 h2 回帧时，
	// 客户端说什么都没用，唯有真的讲 h2 才通。典型症状是国际版（workbuddy.ai）
	// 查询报 `malformed HTTP response "\x00\x00\x12\x04..."`，而国内域名正常
	// （国内网关宽容，无视 ALPN 也回 HTTP/1.1）。
	// 也可用 WB2A_TLS_ALPN 覆盖。
	TLSALPN string `json:"tls_alpn,omitempty"`

	Panel struct {
		// PackageDetailLimit 积分构成页单账号默认展示的最近到期包数；<=0 回落 5。
		PackageDetailLimit int `json:"package_detail_limit"`
	} `json:"panel"`

	Logging struct {
		// RequestArchiveEnabled 请求元数据 JSONL 归档开关，缺省 true。
		RequestArchiveEnabled bool `json:"request_archive_enabled"`
		// RequestRetentionDays 归档保留天数，缺省 7；<=0 回落默认。
		RequestRetentionDays int `json:"request_retention_days"`
		// RequestArchiveMaxMB 归档总上限（MiB），缺省 100；<=0 回落默认。
		RequestArchiveMaxMB int `json:"request_archive_max_mb"`
		// RequestClientInfo 是否在请求日志（归档事件 + stdout 流水行 + 面板运行
		// 日志）里记录调用来源：客户端 IP 与 User-Agent。缺省 true。
		//
		// 为什么做成开关而不是恒开：来源信息是排查"谁在打网关"的第一手线索，
		// 但它比 token 计数敏感（IP 属个人信息），共享部署/多租户场景可能需要
		// 关掉。关闭后 Event.ClientIP/UserAgent 保持为空，归档里不出现该字段。
		// 热生效（经 livecfg 快照），无需重启。
		RequestClientInfo bool `json:"request_client_info"`
	} `json:"logging"`

	Server struct {
		// ReadTimeout 入站请求读取（含 body 上传）总时长上限（issue #100）。
		// http.Server 的 ReadTimeout 覆盖整个请求读取：大上下文/文件块请求经
		// 反代链转发时上传可超过旧固定值 60s，被掐后客户端拿到
		// 400 "read body: ... i/o timeout"。缺省 "300s"；"0" = 不限制
		//（慢速 body 可无限占用连接，自担风险）；改动需重启进程。
		ReadTimeout string `json:"read_timeout"` // "300s"；"0" = 不限制
	} `json:"server"`

	Cooldown struct {
		// hard_credit / err_threshold / err_cooldown 三个历史键已退役：
		// 硬冷却固定为次日 04:00（CooldownUntilTomorrow4AM），连续错误语义并入熔断器。
		// 旧 config 中的这些键因 JSON 未知字段而自然忽略，不报错。
		SoftRate string `json:"soft_rate"` // "600s"，软限流冷却基数
		// SoftRateMax 软冷却指数退避的封顶，默认 "2h"。
		// 空值回落默认，非法值报错（处理风格同 soft_rate）。
		SoftRateMax string `json:"soft_rate_max"` // "2h"
	} `json:"cooldown"`

	Schedule struct {
		CheckinHours   []int `json:"checkin_hours"`   // [9,21]
		TravelHours    []int `json:"travel_hours"`    // [9,21]
		ActivityHours  []int `json:"activity_hours"`  // [10]
		KeepaliveHours []int `json:"keepalive_hours"` // [22]
		BlackcatHours  []int `json:"blackcat_hours"`  // [23] 夜猫子窗口（23:00–08:00 计数）
		GrowthHours    []int `json:"growth_hours"`    // [1] 成长任务队列（Sequential 族每日零点解锁，01:00 自动扫描执行）
		// CheckinEnabled/TravelEnabled/ActivityEnabled/KeepaliveEnabled/BlackcatEnabled 显式禁用开关（缺省 true）。
		//
		// 为什么用独立 bool 而不是空数组/哨兵值表意"禁用"：
		//   - 空数组与 null 在老语义里已被"未配置 → 回落默认"占用，改判会静默翻转
		//     所有老 config 的行为（用户只想删掉一行，结果关掉了签到）；bool 缺省 true
		//     则对老配置零影响，向后完全兼容。
		//   - 开关与取值解耦：禁用时仍保留用户显式配的小时，重新启用无需补配。
		//   - 无需猜测哨兵（[-1] 之类），非法小时一律报错并提示改用本开关。
		// 旧 config 里的该键因 JSON 未知字段而自然忽略，不报错。
		CheckinEnabled   bool `json:"checkin_enabled"`   // 缺省 true；false = 关签到
		TravelEnabled    bool `json:"travel_enabled"`    // 缺省 true；false = 完全停猫猫旅行
		ActivityEnabled  bool `json:"activity_enabled"`  // 缺省 true；false = 停活跃上报
		KeepaliveEnabled bool `json:"keepalive_enabled"` // 缺省 true；false = 关 token 保活
		BlackcatEnabled  bool `json:"blackcat_enabled"`  // 缺省 true；false = 关夜猫子
		GrowthEnabled    bool `json:"growth_enabled"`    // 缺省 true；false = 关成长任务自动排程

		// IncludeDisabledInTasks 让「保号类」定时任务（签到 / 活跃上报 / token 保活 /
		// 余额刷新）对**已禁用（disabled）**的账号也执行。
		//
		// 为什么需要它：面板「禁用」的语义是「不再参与选号」（见面板确认文案），但这四类
		// 任务此前一律 `if st.Disabled { continue }`，等于把「停用流量」放大成「停止一切
		// 上游保号行为」——被禁用的号拿不到签到积分、不续 token、余额也不再刷新；而
		// ReenableIfCredits 明确不复活 disabled 账号（见 pool.state.go），于是签到这条唯一
		// 的自动回血路径也断了，账号只能靠人工「解冻」回来。
		//
		// 对「一次只放开一个号、用禁用做流量开关」的轮换用法（同 IP 多号防风控），闲置
		// 待命的号恰恰是最需要签到的那批——本开关即为该用法提供出口。
		//
		// 缺省 false = 保持既有行为，对老配置零影响。打开后禁用号仍会签到 / 保活，但
		// **依旧不参与选号**：pool 选号侧的 disabled 过滤不受本开关影响。
		IncludeDisabledInTasks bool `json:"include_disabled_in_tasks"`

		// 余额后台周期刷新：两次签到时点之间 credits 也能保持新鲜（面板/状态观测用）。
		// 解冻语义同签到（余额 > 0 的冷却账号自动解冻），但不做签到不刷 token。
		BalanceRefreshEnabled bool `json:"balance_refresh_enabled"` // 缺省 true；false = 关闭
		BalanceRefreshMinutes int  `json:"balance_refresh_minutes"` // 缺省 5；<=0 回落 5
	} `json:"schedule"`

	Global struct {
		// Enabled global realm 路由开关。缺省 true：Realm() 正常把 realm=global/
		// domain=workbuddy.ai 的账号判为 global 并路由 global base/路径。
		// 显式 "enabled": false 关闭（逃生门，纯 CN 锁定：即便 auth 写了 realm=global
		// 也不路由，auth.Realm() 双保险的第一道闸）。纯 CN 部署行为不变：CN 账号
		// 恒判 cn，global base 只在 realm=global 的账号上被使用。
		Enabled bool `json:"enabled"`
		// ChatBase / BillingBase 国际版上游 base 覆盖；空 = 回落内置默认
		// https://www.workbuddy.ai（internal/upstream.defaultGlobalBase）。
		ChatBase    string `json:"chat_base"`
		BillingBase string `json:"billing_base"`
	} `json:"global"`

	Upstream struct {
		// TimeoutSeconds 短 RPC（refresh/checkin/balance/FetchModels）总时长上限，默认 120。
		TimeoutSeconds int `json:"timeout_seconds"`
		// HeaderTimeoutSeconds 聊天 SSE 首字节前（响应头）上限；<=0 回落 TimeoutSeconds。
		HeaderTimeoutSeconds int `json:"header_timeout_seconds"`
		// IdleTimeoutSeconds 聊天 SSE 流中空闲上限（活跃吐数据续命不掐）；<=0 回落默认 300。
		IdleTimeoutSeconds int `json:"idle_timeout_seconds"`
		// UserAgent 出站 User-Agent 显式覆盖（非空时全路径生效，优先于默认三段式）。
		// 全部出站请求生效：chat/refresh/checkin/balance/report/travel/FetchModels。
		// 默认值已对齐官方 WorkBuddy 桌面形态（三段式），用户仍可配完全自定义值改写。
		UserAgent string `json:"user_agent"`
		// ClientVersion WorkBuddy 客户端版本段（出站 UA 的 `WorkBuddy/<ver>` 与归属头
		// X-IDE-Version）。空 = 内置默认（对齐官方 5.5.4 分发包）。
		ClientVersion string `json:"client_version"`
		// CliVersion 出站 UA 中 `CLI/<ver>` 段的版本。空 = 内置默认（官方内置 CLI 2.137.1）。
		CliVersion string `json:"cli_version"`
		// ClientName 用量归属头取值（X-Product / X-IDE-Name / X-IDE-Type / X-IDE-Version）。
		// 空 = 旧行为 X-Product="SaaS" 不设 X-IDE-*；配 "WorkBuddy" 则四头跟随。
		ClientName string `json:"client_name"`
		// DeviceToken 设备风控 Token（X-Device-Token 头）全局兜底；空 = 不注入。
		// 每号 auth 文件的 device_token 键优先于本项。
		DeviceToken string `json:"device_token"`
		// DeviceTokenFile device token 文件路径兜底（宿主落盘的桌面端 token，5 分钟读取缓存）。
		DeviceTokenFile string `json:"device_token_file"`
		// PassthroughIP 是否透传客户端 IP 给上游（默认 false，反代安全边界）。
		PassthroughIP bool `json:"passthrough_ip"`
	} `json:"upstream"`

	Features struct {
		// SanitizeBlacklistFingerprints 出站请求体黑名单指纹脱敏（默认 true；false 完全还原）。
		SanitizeBlacklistFingerprints bool `json:"sanitize_blacklist_fingerprints"`
	} `json:"features"`

	Prompt struct {
		// Mode passthrough（默认）= 透传客户端原始 system（降级重试仍会切到 Degraded）；
		// custom = 网关用自有系统提示词替换客户端 system/developer；
		// append = 两者并用：开头连续 system/developer 块后插网关 system，既有消息逐字不动（issue #129）。
		Mode string `json:"mode"` // "passthrough" / "custom" / "append"
		// File 提示词文件路径；空 = 内置默认 defaultprompt.md；
		// 路径非空但不可读 → 启动报错（fail fast，避免静默回落到内置默认）。
		File string `json:"file"`
	} `json:"prompt"`

	// PromptText 解析后的系统提示词文本（custom/append 模式使用）。
	PromptText string `json:"-"`

	Upstash struct {
		URL   string `json:"url"`   // 空 = 纯内存模式；支持完整 rediss:// URL 或 https://xxx.upstash.io host
		Token string `json:"token"` // url 非完整连接串时用于组装 rediss://default:<token>@<host>:6379
	} `json:"upstash"`

	Pool struct {
		MaxInFlight        int    `json:"max_in_flight"`        // 单账号最大在途请求数，0 = 不限
		MaxInFlightGlobal  int    `json:"max_in_flight_global"` // global 域单账号在途上限（WAF 风控紧域压低并发），0 = 回落默认 2
		BreakerThreshold   int    `json:"breaker_threshold"`    // 连续失败次数触发熔断，默认 3
		BreakerCooldown    string `json:"breaker_cooldown"`     // 基础熔断时长，默认 "30m"
		BreakerCooldownMax string `json:"breaker_cooldown_max"` // 指数退避封顶，默认 "6h"
		// 连败降权（issue #114）：ErrClient/传输层这类「不罚号」失败连续计数，达阈
		// 临时出池。与冷却/熔断并存取更长者不叠加。默认 5 次 / 10m。
		DegradeThreshold   int     `json:"degrade_threshold"`    // 连败次数触发降权，默认 5
		DegradeCooldown    string  `json:"degrade_cooldown"`     // 降权时长（固定，非指数退避），默认 "10m"
		DegradeCooldownMax string  `json:"degrade_cooldown_max"` // 降权时长的上限钳制，默认 "2h"（仅当 cooldown 超该值才钳制）
		IdleWeightPerHour  float64 `json:"idle_weight_per_hour"` // 闲置补偿：每小时未用 +0.5 权重
		IdleWeightMax      float64 `json:"idle_weight_max"`      // 闲置补偿封顶，默认 5.0
		// PreferExpiring 快过期积分加权开关，默认 true。开启且 expiring_soon 窗口内
		// 存在有效批次时，该账号选号权重 ×3（虚拟实例，见 pool 路由加权）；
		// 不按到期时间排序、与批次金额无关（issue #101 对齐实现口径）。
		// 关闭后完全不使用到期信息选号。
		PreferExpiring bool `json:"prefer_expiring"`
		// ExpiringSoon 快过期积分窗口（如 "168h"=7天）：签到/余额刷新时，到期时间在
		// 此窗口内的批次令账号命中上述 ×3 加权；窗口开大 → 命中账号变多、
		// 偏好被稀释。空/0 = 禁用该加权门槛。
		ExpiringSoon string `json:"expiring_soon"`
		// CostExploreInterval costTier 条件探索窗口（issue #136 方案 a′）：tier 0
		// 垄断层存在且 tier 1 有成员时，距上次探索 ≥ 窗口则本次 pick 生效层切
		// tier 1-only（探索=搭车改道，零新增上游请求；成功即毕业，失败走既有
		// 错误策略）。默认 "30m"（≤48 次/天/模型）；"0" 关停（完全回到现状行为）；
		// 空值回落默认。
		CostExploreInterval string `json:"cost_explore_interval"`
		// CreditFloor 积分保底：账号余额低于该值时，对实测收费模型（tier 2）不再
		// 参与选号——防止收费请求把余额打穿、连免费模型都 402 冷却到次日签到。
		// tier 0（免费）/ tier 1（无观测）不受限；签到回血越过 floor 自动恢复。
		// 默认 0 = 关闭；负值钳 0。
		CreditFloor int64 `json:"credit_floor"`
	} `json:"pool"`

	SessionSticky struct {
		Enabled    bool   `json:"enabled"`     // 默认 true
		TTL        string `json:"ttl"`         // 会话绑定 TTL，默认 "30m"
		GCInterval string `json:"gc_interval"` // 会话 GC 周期，默认 "5m"
	} `json:"session_sticky"`

	// Trae TRAE SOLO（TraeWork）侧配置：与 WorkBuddy 完全平行的第二套账号池。
	//
	// 形态是「单进程双池」而不是「统一池」：两侧的凭证模型 / 上游协议 / 风控字段
	// 都不同（Trae 侧是 x-machine-id + x-device-id 硬校验，WorkBuddy 侧是
	// X-Device-Token），共用一个池等于把两套状态机揉在一起。这里让它们各自持有
	// 独立的 auth 目录 / state 文件 / upstream client / 调度器，只在同一个二进制、
	// 同一个 Web 面板和同一份配置里共存，接口面走 /trae/* 前缀与本体的 /v1/* 并列。
	Trae struct {
		// Enabled 是否装配 Trae 侧（缺省 true）。
		// 关闭时不加载任何 Trae 账号、不注册 /trae/* 路由、不起 Trae 调度器。
		//
		// 为什么默认开：Trae 侧只在 auths/ 里存在 trae-*.json 时才有账号可加载，
		// 没有凭证时它只是一个空池 + 一条 /trae/ 路由，成本可忽略；而默认关闭会让
		// 用户导入凭证后还得再翻配置打开开关，多一道无谓的坎。要关显式写 false。
		Enabled bool `json:"enabled"`

		// AuthDir Trae 凭证目录（扫 trae-*.json）。空 = 复用主 auth_dir。
		//
		// 复用是安全的：两侧的 glob 模式不重叠（workbuddy*.json vs trae-*.json），
		// 同一目录天然互不污染。默认取空值即是为了让用户把 trae-*.json 直接丢进
		// 现有 auths/ 就能被识别，不必再记一个新目录。需要严格隔离时显式配本键。
		AuthDir string `json:"auth_dir"`

		// StateFile Trae 池状态文件。空 = 与主 state_file 同目录的 state-trae.json。
		//
		// 必须与 WorkBuddy 的 state.json 分开：两侧的持久化结构不同（Trae 池没有
		// 熔断 / 连败降权 / 模型级冷却 / 成本台账这些字段），共用文件会让两边互相
		// 把对方的键洗掉。
		StateFile string `json:"state_file"`

		// DefaultModel 客户端未指定 model 时的缺省模型。空 = 回落内置 glm-5.2。
		DefaultModel string `json:"default_model"`

		// CallbackPort Trae 网页登录的回调监听端口（监听 127.0.0.1）；"0" = 不起，
		// 降级为「手动粘贴回调链接」。与主服务的端口独立，避免与其它登录流程抢占。
		CallbackPort string `json:"callback_port"`

		Schedule struct {
			CheckinHours []int `json:"checkin_hours"` // [9]，空 = 回落默认
			RefreshHours []int `json:"refresh_hours"` // [3]，空 = 回落默认
			// CheckinEnabled/RefreshEnabled 显式禁用开关（缺省 true）。
			// 语义同主 schedule：bool 缺省 true 保证老配置零影响，只有显式 false 才关。
			CheckinEnabled bool `json:"checkin_enabled"`
			RefreshEnabled bool `json:"refresh_enabled"`
		} `json:"schedule"`

		// Cooldown 冷却参数。Trae 侧的冷却语义比 WorkBuddy 简单，只有三类：
		// 1005 plan 权益不足（长冷却）、429（短冷却）、连续错误（中冷却）。
		Cooldown struct {
			PlanCredit   string `json:"plan_credit"`   // "12h"
			SoftRate     string `json:"soft_rate"`     // "60s"
			ErrThreshold int    `json:"err_threshold"` // 3
			ErrCooldown  string `json:"err_cooldown"`  // "10m"
		} `json:"cooldown"`

		Upstream struct {
			TimeoutSeconds int `json:"timeout_seconds"` // 120
		} `json:"upstream"`

		// RefreshSkew token 预刷新窗口（缺省 24h）：Trae 的 access token 有效期短，
		// 提前量给足，避免请求打到过期 token 上。空/非法回落默认。
		RefreshSkew string `json:"refresh_skew"`
	} `json:"trae"`

	// Tunnel 按需开启的公网隧道（Cloudflare Tunnel）。
	//
	// 设计取向是「默认关、用时开」：它**不改本机任何网络配置**（纯出站——cloudflared
	// 主动连 Cloudflare 边缘，不监听入站端口、不动路由表 / DNS / 防火墙），但会把面板
	// 暴露到公网，所以不该默认开着。装好 cloudflared 后在面板「配置 → 远程访问」里
	// 打开开关即可，无需重启进程。
	Tunnel struct {
		// Enabled 是否启动隧道。缺省 false（按需开启）。
		Enabled bool `json:"enabled"`

		// Mode 隧道模式：
		//   "quick"  临时公网地址（xxx.trycloudflare.com），无需 Cloudflare 账号，
		//            每次启动地址都不同，适合临时用一次；
		//   "token"  用 Zero Trust 里建好的 tunnel token，地址固定。
		Mode string `json:"mode"`

		// Token token 模式的凭据（cloudflared tunnel run --token）。
		Token string `json:"token"`

		// Binary cloudflared 可执行文件路径。空 = 走 PATH 查找。
		Binary string `json:"binary"`

		// Target 隧道指向的本地地址。空 = 自动取当前监听端口拼 127.0.0.1，
		// 避免用户手填写错端口（回源走环回，不必也不该绕本机对外 IP）。
		Target string `json:"target"`
	} `json:"tunnel"`

	// Trae 解析后的 duration
	TraePlanCreditDur  time.Duration `json:"-"`
	TraeSoftRateDur    time.Duration `json:"-"`
	TraeErrCooldownDur time.Duration `json:"-"`
	TraeRefreshSkewDur time.Duration `json:"-"`

	// 解析后
	SoftRateDur            time.Duration `json:"-"`
	SoftRateMaxDur         time.Duration `json:"-"`
	BreakerCooldownDur     time.Duration `json:"-"`
	BreakerCooldownMaxD    time.Duration `json:"-"`
	DegradeCooldownDur     time.Duration `json:"-"`
	DegradeCooldownMaxD    time.Duration `json:"-"`
	SessionTTL             time.Duration `json:"-"`
	SessionGCInterval      time.Duration `json:"-"`
	BalanceRefreshInterval time.Duration `json:"-"` // 0 = 不启动（enabled=false）
	ExpiringSoonDur        time.Duration `json:"-"`
	// CostExploreIntervalDur 解析后的 costTier 探索窗口（issue #136）；0 = 关停。
	CostExploreIntervalDur time.Duration `json:"-"`
	// ServerReadTimeoutDur 解析后的入站请求读取上限（issue #100）；0 = 不限制。
	ServerReadTimeoutDur time.Duration `json:"-"`
}

// Default 默认配置。
func Default() *Config {
	c := &Config{
		Listen:    ":7863",
		APIKey:    "",
		AuthDir:   "./auths",
		StateFile: "./data/state.json",
	}
	c.Cooldown.SoftRate = "600s"
	c.Cooldown.SoftRateMax = "2h"
	c.Server.ReadTimeout = "300s"
	c.Panel.PackageDetailLimit = 5
	c.Logging.RequestArchiveEnabled = true
	c.Logging.RequestRetentionDays = 7
	c.Logging.RequestArchiveMaxMB = 100
	// 缺省 true 靠显式赋值实现（同 Schedule 开关）：JSON 里键缺席时字段保留此值，
	// 只有显式 false 才关闭来源记录。
	c.Logging.RequestClientInfo = true
	c.Schedule.CheckinHours = []int{9, 21}
	c.Schedule.TravelHours = []int{9, 21}
	c.Schedule.ActivityHours = []int{10}
	c.Schedule.KeepaliveHours = []int{22}
	c.Schedule.BlackcatHours = []int{23}
	c.Schedule.GrowthHours = []int{1}
	// 开关「缺省 true」靠这几行实现：Load 先取 Default() 再 json.Unmarshal 覆盖，
	// 键缺席（或为 null）时字段原样保留 true，只有显式 false 才关。
	c.Schedule.CheckinEnabled = true
	c.Schedule.GrowthEnabled = true
	c.Schedule.TravelEnabled = true
	c.Schedule.ActivityEnabled = true
	c.Schedule.KeepaliveEnabled = true
	c.Schedule.BlackcatEnabled = true
	c.Schedule.BalanceRefreshEnabled = true
	c.Schedule.BalanceRefreshMinutes = 5
	c.Upstream.TimeoutSeconds = 120
	// HeaderTimeoutSeconds/IdleTimeoutSeconds 默认 0（未设置态），回落见 normalize()。
	c.Upstream.HeaderTimeoutSeconds = 0
	c.Upstream.IdleTimeoutSeconds = 0
	// 出站 TLS 自动修：默认开启（作用域由 autoTrustHosts 白名单约束）。
	c.TLSAutoTrust = true
	c.TLSAutoTrustRetryMinutes = 5
	// 出站 ALPN 缺省只广告 http/1.1（与 transport 禁 h2 同调）；h2 是逃生门。
	c.TLSALPN = "http/1.1"
	// Global.Enabled 缺省 true（纯 CN 行为不变：CN 账号恒判 cn，global base 不被使用）；
	// ChatBase/BillingBase 缺省空（回落内置默认）。
	c.Global.Enabled = true
	c.Features.SanitizeBlacklistFingerprints = true
	c.Prompt.Mode = "passthrough" // 缺省 passthrough：透传客户端原始 system（对齐上游；custom 由用户显式选择）
	c.Pool.MaxInFlight = 3
	// MaxInFlightGlobal 缺省 2：global 域 WAF 风控更紧，压低单号并发（WAF 403 修复
	// P1-1）；0/负数 normalize 回落默认（与 max_in_flight 的 0=不限语义不同，分档键
	// 的 0 没有合理语义，回退分档默认最稳）。
	c.Pool.MaxInFlightGlobal = 2
	c.Pool.BreakerThreshold = 3
	c.Pool.BreakerCooldown = "30m"
	c.Pool.BreakerCooldownMax = "6h"
	c.Pool.DegradeThreshold = 5
	c.Pool.DegradeCooldown = "10m"
	c.Pool.DegradeCooldownMax = "2h"
	c.Pool.IdleWeightPerHour = 0.5
	c.Pool.IdleWeightMax = 5.0
	c.Pool.PreferExpiring = true
	c.Pool.ExpiringSoon = "168h" // 快过期窗口默认 7 天：官方活动奖励积分多在两周内过期
	// costTier 探索默认 30m（issue #136：垄断破除 + 搭车改道零新增请求）；"0" 关停。
	c.Pool.CostExploreInterval = "30m"
	c.SessionSticky.Enabled = true
	c.SessionSticky.TTL = "30m"
	c.SessionSticky.GCInterval = "5m"
	// Tunnel 缺省关闭（按需开启）：它会把面板暴露到公网，不该默认开着。
	// Mode 缺省 quick —— 无需 Cloudflare 账号即可验证链路，先用起来再谈固定域名。
	// Binary 空 = 走 PATH 查找 cloudflared；Target 空 = 自动指向本机监听端口。
	c.Tunnel.Enabled = false
	c.Tunnel.Mode = "quick"

	// Trae 侧：Enabled 缺省 true（开箱即用；要关显式写 false）。之所以敢默认开：
	// Trae 侧只在 auths/ 里存在 trae-*.json 时才有账号可加载，没有凭证时它只是
	// 一个空池 + 一条 /trae/ 路由，成本可忽略；默认关闭反而会让用户导入凭证后
	// 还得再去翻配置打开开关。其余键给出与 trae2api-web 一致的推荐值。
	// AuthDir 缺省空 = 复用主 auth_dir；StateFile 缺省空 = 主 state 同目录的
	// state-trae.json（两者都在 normalizeTrae 里补齐）。
	c.Trae.Enabled = true
	c.Trae.DefaultModel = "glm-5.2"
	c.Trae.CallbackPort = "18080"
	c.Trae.Schedule.CheckinHours = []int{9}
	c.Trae.Schedule.RefreshHours = []int{3}
	c.Trae.Schedule.CheckinEnabled = true
	c.Trae.Schedule.RefreshEnabled = true
	c.Trae.Cooldown.PlanCredit = "12h"
	c.Trae.Cooldown.SoftRate = "60s"
	c.Trae.Cooldown.ErrThreshold = 3
	c.Trae.Cooldown.ErrCooldown = "10m"
	c.Trae.Upstream.TimeoutSeconds = 120
	c.Trae.RefreshSkew = "24h"
	return c
}

// Load 从文件读，再用 WB2A_* env 覆盖。
func Load(path string) (*Config, error) {
	c := Default()
	if path != "" {
		// 目录检查：Docker bind mount 在宿主机文件缺失时会静默创建同名目录，
		// 直接 ReadFile 会报 "Incorrect function" 之类晦涩错误，这里给出可操作提示。
		if st, statErr := os.Stat(path); statErr == nil && st.IsDir() {
			return nil, fmt.Errorf("config %s 是目录而非文件——"+
				"Docker 部署时若宿主机缺少 config.json，bind mount 会创建同名目录。"+
				"请先 `cp config.example.json config.json` 或删除该目录（程序会自动生成配置）", path)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}
		if _, err := ParseConfigInto(raw, c); err != nil {
			return nil, err
		}
	}
	applyEnv(c)
	if err := c.normalize(); err != nil {
		return nil, err
	}
	return c, nil
}

// ParseConfigInto 把 JSON 覆盖到 c 上并 normalize（不做 env、不读文件）。
// 面板保存配置走这条路径：与 Load 完全同一套解析/校验逻辑，避免两处漂移。
func ParseConfigInto(raw []byte, c *Config) (*Config, error) {
	if err := json.Unmarshal(raw, c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := c.normalize(); err != nil {
		return nil, err
	}
	return c, nil
}

// ParseConfig 基于默认值解析一段配置 JSON（等价于 Load 的文件分支，但不读环境变量）。
func ParseConfig(raw []byte) (*Config, error) {
	return ParseConfigInto(raw, Default())
}

// WriteDefault 在 path 落一份推荐配置（首次运行自动生成，双击即开免手工复制样例）。
// 值取自 Default()（含超时/熔断/签到排程等推荐值），api_key 用 crypto/rand 随机生成：
// 安全默认优于示例占位符（listen 绑定 0.0.0.0，空 key 会把网关裸暴露给局域网）。
// 返回生成的 key 供启动日志透出。已存在时经 O_EXCL 原子拒绝，绝不改写用户配置。
func WriteDefault(path string) (string, error) {
	raw := make([]byte, 18)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("gen api_key: %w", err)
	}
	key := "sk-" + base64.RawURLEncoding.EncodeToString(raw)
	c := Default()
	c.APIKey = key
	_ = c.normalize() // Default() 全合法，normalize 仅补齐 header/idle 超时的展示值
	out, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal config: %w", err)
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", fmt.Errorf("mkdir config dir: %w", err)
		}
	}
	// O_EXCL 原子拒绝覆盖：即使调用方漏判"不存在"，也绝不悄悄改写用户已有配置。
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("write config: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(out); err != nil {
		return "", fmt.Errorf("write config: %w", err)
	}
	return key, nil
}

func applyEnv(c *Config) {
	if v := os.Getenv("WB2A_LISTEN"); v != "" {
		c.Listen = v
	}
	if v := os.Getenv("WB2A_API_KEY"); v != "" {
		c.APIKey = v
	}
	if v := os.Getenv("WB2A_AUTH_DIR"); v != "" {
		c.AuthDir = v
	}
	if v := os.Getenv("WB2A_STATE_FILE"); v != "" {
		c.StateFile = v
	}
	if v := os.Getenv("WB2A_SOFT_RATE"); v != "" {
		c.Cooldown.SoftRate = v
	}
	if v := os.Getenv("WB2A_SOFT_RATE_MAX"); v != "" {
		c.Cooldown.SoftRateMax = v
	}
	if v := os.Getenv("WB2A_TIMEOUT_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.Upstream.TimeoutSeconds = n
		}
	}
	if v := os.Getenv("WB2A_HEADER_TIMEOUT_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.Upstream.HeaderTimeoutSeconds = n
		}
	}
	if v := os.Getenv("WB2A_IDLE_TIMEOUT_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.Upstream.IdleTimeoutSeconds = n
		}
	}
	if v := os.Getenv("WB2A_USER_AGENT"); v != "" {
		c.Upstream.UserAgent = v
	}
	if v := os.Getenv("WB2A_CLIENT_VERSION"); v != "" {
		c.Upstream.ClientVersion = v
	}
	if v := os.Getenv("WB2A_CLI_VERSION"); v != "" {
		c.Upstream.CliVersion = v
	}
	if v := os.Getenv("WB2A_CLIENT_NAME"); v != "" {
		c.Upstream.ClientName = v
	}
	if v := os.Getenv("WB2A_DEVICE_TOKEN"); v != "" {
		c.Upstream.DeviceToken = v
	}
	if v := os.Getenv("WB2A_DEVICE_TOKEN_FILE"); v != "" {
		c.Upstream.DeviceTokenFile = v
	}
	if v := os.Getenv("WB2A_PASSTHROUGH_IP"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			c.Upstream.PassthroughIP = b
		}
	}
	if v := os.Getenv("WB2A_SANITIZE_FINGERPRINTS"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			c.Features.SanitizeBlacklistFingerprints = b
		}
	}
	if v := os.Getenv("WB2A_PROMPT_MODE"); v != "" {
		c.Prompt.Mode = v
	}
	if v := os.Getenv("WB2A_PROMPT_FILE"); v != "" {
		c.Prompt.File = v
	}
	if v := os.Getenv("WB2A_EXPIRING_SOON"); v != "" {
		c.Pool.ExpiringSoon = v
	}
	if v := os.Getenv("WB2A_PREFER_EXPIRING"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			c.Pool.PreferExpiring = b
		}
	}
	if v := os.Getenv("WB2A_DNS"); v != "" {
		c.DNSServers = splitCSV(v)
	}
	if v := os.Getenv("WB2A_CA_FILE"); v != "" {
		c.TLSCAFile = v
	}
	if v := os.Getenv("WB2A_TLS_INSECURE"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			c.TLSInsecureSkipVerify = b
		}
	}
	if v := os.Getenv("WB2A_TLS_AUTO_TRUST"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			c.TLSAutoTrust = b
		}
	}
	if v := os.Getenv("WB2A_TLS_AUTO_TRUST_HOSTS"); v != "" {
		c.TLSAutoTrustHosts = splitCSV(v)
	}
	if v := os.Getenv("WB2A_TLS_AUTO_TRUST_RETRY_MINUTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.TLSAutoTrustRetryMinutes = n
		}
	}
	if v := os.Getenv("WB2A_TLS_ALPN"); v != "" {
		c.TLSALPN = v
	}
	// Trae 侧覆盖（KernelSU/Magisk 模块与容器部署惯用 env 注入，免改 config.json）。
	// 只给最常按部署环境变化的三项；其余（排程/冷却）留在配置文件里。
	if v := os.Getenv("WB2A_TRAE_ENABLED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			c.Trae.Enabled = b
		}
	}
	if v := os.Getenv("WB2A_TRAE_AUTH_DIR"); v != "" {
		c.Trae.AuthDir = v
	}
	if v := os.Getenv("WB2A_TRAE_STATE_FILE"); v != "" {
		c.Trae.StateFile = v
	}
	if v := os.Getenv("WB2A_TRAE_DEFAULT_MODEL"); v != "" {
		c.Trae.DefaultModel = v
	}
	// 停机标记：模块的 service.sh 在老版 config.json 缺少该键时用它兜底
	// （见其注释）。显式配了 shutdown_marker 的部署不会被覆盖。
	if v := os.Getenv("WB2A_SHUTDOWN_MARKER"); v != "" {
		c.ShutdownMarker = v
	}
	// Tunnel 侧覆盖（同样面向模块 / 容器部署，免改 config.json）。
	if v := os.Getenv("WB2A_TUNNEL_ENABLED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			c.Tunnel.Enabled = b
		}
	}
	if v := os.Getenv("WB2A_TUNNEL_MODE"); v != "" {
		c.Tunnel.Mode = v
	}
	if v := os.Getenv("WB2A_TUNNEL_TOKEN"); v != "" {
		c.Tunnel.Token = v
	}
	if v := os.Getenv("WB2A_TUNNEL_BINARY"); v != "" {
		c.Tunnel.Binary = v
	}
}

func (c *Config) normalize() error {
	var err error
	if c.Panel.PackageDetailLimit <= 0 {
		c.Panel.PackageDetailLimit = 5
	}
	if c.Logging.RequestRetentionDays <= 0 {
		c.Logging.RequestRetentionDays = 7
	}
	if c.Logging.RequestArchiveMaxMB <= 0 {
		c.Logging.RequestArchiveMaxMB = 100
	}
	// 入站读取上限（issue #100）：空值回落默认 300s；"0" 合法（不限制）；
	// 负值无语义，fail fast（静默钳 0 会把保护悄悄关掉）。
	if c.Server.ReadTimeout == "" {
		c.Server.ReadTimeout = "300s"
	}
	if c.ServerReadTimeoutDur, err = time.ParseDuration(c.Server.ReadTimeout); err != nil {
		return fmt.Errorf("server.read_timeout: %w", err)
	}
	if c.ServerReadTimeoutDur < 0 {
		return fmt.Errorf("server.read_timeout: 负时长 %q 无意义", c.Server.ReadTimeout)
	}
	if c.SoftRateDur, err = time.ParseDuration(c.Cooldown.SoftRate); err != nil {
		return fmt.Errorf("cooldown.soft_rate: %w", err)
	}
	// 空值回落默认 2h（Default() 已置值；此兜底覆盖显式 "" 与 Default() 被绕过的场景）。
	if c.Cooldown.SoftRateMax == "" {
		c.Cooldown.SoftRateMax = "2h"
	}
	if c.SoftRateMaxDur, err = time.ParseDuration(c.Cooldown.SoftRateMax); err != nil {
		return fmt.Errorf("cooldown.soft_rate_max: %w", err)
	}
	if c.BreakerCooldownDur, err = time.ParseDuration(c.Pool.BreakerCooldown); err != nil {
		return fmt.Errorf("pool.breaker_cooldown: %w", err)
	}
	if c.BreakerCooldownMaxD, err = time.ParseDuration(c.Pool.BreakerCooldownMax); err != nil {
		return fmt.Errorf("pool.breaker_cooldown_max: %w", err)
	}
	if c.DegradeCooldownDur, err = time.ParseDuration(c.Pool.DegradeCooldown); err != nil {
		return fmt.Errorf("pool.degrade_cooldown: %w", err)
	}
	if c.DegradeCooldownMaxD, err = time.ParseDuration(c.Pool.DegradeCooldownMax); err != nil {
		return fmt.Errorf("pool.degrade_cooldown_max: %w", err)
	}
	if c.SessionTTL, err = time.ParseDuration(c.SessionSticky.TTL); err != nil {
		return fmt.Errorf("session_sticky.ttl: %w", err)
	}
	if c.SessionGCInterval, err = time.ParseDuration(c.SessionSticky.GCInterval); err != nil {
		return fmt.Errorf("session_sticky.gc_interval: %w", err)
	}
	// 快过期窗口：空 = 禁用（ExpiringSoonDur 0）；非空必须可解析（拼写错误 fail fast）。
	if c.Pool.ExpiringSoon != "" {
		if c.ExpiringSoonDur, err = time.ParseDuration(c.Pool.ExpiringSoon); err != nil {
			return fmt.Errorf("pool.expiring_soon: %w", err)
		}
	}
	if c.ExpiringSoonDur < 0 {
		c.ExpiringSoonDur = 0
		c.Pool.ExpiringSoon = "0"
	}
	// costTier 探索窗口（issue #136）：空值回落默认 30m（Default 已置；此兜底覆盖
	// 显式 ""）；"0" 是合法值（关停，完全回到现状行为），不回落；负值钳 0 同关停
	//（"−5m" 无合理语义）。
	if c.Pool.CostExploreInterval == "" {
		c.Pool.CostExploreInterval = "30m"
	}
	if c.CostExploreIntervalDur, err = time.ParseDuration(c.Pool.CostExploreInterval); err != nil {
		return fmt.Errorf("pool.cost_explore_interval: %w", err)
	}
	if c.CostExploreIntervalDur < 0 {
		c.CostExploreIntervalDur = 0
	}
	// 积分保底：负值钳 0（= 关闭）。0 是合法默认（关闭），无需空值回落。
	if c.Pool.CreditFloor < 0 {
		c.Pool.CreditFloor = 0
	}
	if c.Pool.BreakerThreshold <= 0 {
		c.Pool.BreakerThreshold = 3
	}
	// 连败降权参数缺省归一（非法/未设置回落默认，与 breaker_threshold 同风格）。
	if c.Pool.DegradeThreshold <= 0 {
		c.Pool.DegradeThreshold = 5
	}
	if c.Pool.DegradeCooldown == "" {
		c.Pool.DegradeCooldown = "10m"
	}
	if c.Pool.DegradeCooldownMax == "" {
		c.Pool.DegradeCooldownMax = "2h"
	}
	// global 在途分档：0/负数视为未设置回落默认 2（WAF 403 修复 P1-1）。
	if c.Pool.MaxInFlightGlobal <= 0 {
		c.Pool.MaxInFlightGlobal = 2
	}
	if c.Pool.IdleWeightPerHour <= 0 {
		c.Pool.IdleWeightPerHour = 0.5
	}
	if c.Pool.IdleWeightMax <= 0 {
		c.Pool.IdleWeightMax = 5.0
	}
	if c.Upstream.TimeoutSeconds <= 0 {
		c.Upstream.TimeoutSeconds = 120
	}
	// header 缺省回落 timeout（保"首字节前换号"既有语义）；idle 缺省走内置大值。
	// 任务书约定：0 一律视为"未设置"走默认，真正的"禁用"留待后续（避免歧义）。
	if c.Upstream.HeaderTimeoutSeconds <= 0 {
		c.Upstream.HeaderTimeoutSeconds = c.Upstream.TimeoutSeconds
	}
	if c.Upstream.IdleTimeoutSeconds <= 0 {
		c.Upstream.IdleTimeoutSeconds = 300
	}
	// 自动修重试间隔：负值无语义，钳 0（= 只试一次）。0 是合法值（只试一次），
	// 故此处在归一时不回落默认——默认 5 分钟由 Default() 提供，用于区分
	// 「未配置」与「显式设 0」。
	if c.TLSAutoTrustRetryMinutes < 0 {
		c.TLSAutoTrustRetryMinutes = 0
	}
	if !strings.HasPrefix(c.Listen, ":") && !strings.Contains(c.Listen, ":") {
		c.Listen = ":" + c.Listen
	}
	// 空数组与 null 反序列化后覆盖掉 Default() 的排程值（键缺席才保留），在此补齐。
	// 空 = 未配置 → 回落默认；「禁用」一律走 *_enabled=false，两者互不混淆。
	if len(c.Schedule.CheckinHours) == 0 {
		c.Schedule.CheckinHours = []int{9, 21}
	}
	if len(c.Schedule.TravelHours) == 0 {
		c.Schedule.TravelHours = []int{9, 21}
	}
	if len(c.Schedule.ActivityHours) == 0 {
		c.Schedule.ActivityHours = []int{10}
	}
	if len(c.Schedule.KeepaliveHours) == 0 {
		c.Schedule.KeepaliveHours = []int{22}
	}
	if len(c.Schedule.BlackcatHours) == 0 {
		c.Schedule.BlackcatHours = []int{23}
	}
	if len(c.Schedule.GrowthHours) == 0 {
		c.Schedule.GrowthHours = []int{1}
	}
	// 余额后台刷新：启用时 minutes<=0 回落默认 5；关闭时 interval 保持 0（不启动）。
	if c.Schedule.BalanceRefreshEnabled {
		if c.Schedule.BalanceRefreshMinutes <= 0 {
			c.Schedule.BalanceRefreshMinutes = 5
		}
		c.BalanceRefreshInterval = time.Duration(c.Schedule.BalanceRefreshMinutes) * time.Minute
	}
	if err := c.validateScheduleHours(); err != nil {
		return err
	}
	if err := c.normalizeTrae(); err != nil {
		return err
	}
	if err := c.normalizeTunnel(); err != nil {
		return err
	}
	return c.normalizePrompt()
}

// normalizeTunnel 补齐/校验 tunnel 段。
//
// 与 trae 段同样的取向：即便 Enabled 为 false 也把字段补成合法值，否则用户在
// 面板里打开开关前看到的是一片空白。**不在这里校验 token 是否齐全**——那样配置
// 一脏整个进程就起不来，用户反而进不了面板去改；缺失交由 tunnel.Manager 在启动
// 时报错、由面板显示出来。
func (c *Config) normalizeTunnel() error {
	switch strings.ToLower(strings.TrimSpace(c.Tunnel.Mode)) {
	case "", "quick":
		c.Tunnel.Mode = "quick"
	case "token":
		c.Tunnel.Mode = "token"
	default:
		return fmt.Errorf("tunnel.mode %q 不支持（可选 quick / token）", c.Tunnel.Mode)
	}
	c.Tunnel.Token = strings.TrimSpace(c.Tunnel.Token)
	c.Tunnel.Binary = strings.TrimSpace(c.Tunnel.Binary)
	c.Tunnel.Target = strings.TrimSpace(c.Tunnel.Target)
	// Target 空 = 指向本机监听端口。listen 形如 ":7863" / "127.0.0.1:7863"，
	// 取最后一个冒号后的端口；取不到就留空，由 Manager 回落到 listen 原值。
	if c.Tunnel.Target == "" {
		if i := strings.LastIndex(c.Listen, ":"); i >= 0 {
			if port := strings.TrimSpace(c.Listen[i+1:]); port != "" {
				c.Tunnel.Target = "http://127.0.0.1:" + port
			}
		}
	}
	return nil
}

// normalizeTrae 补齐/校验 trae 段（仅 Enabled 为 true 时才做实质校验）。
//
// 关闭状态下也做「目录/状态文件回落 + duration 解析」：面板配置页要能展示一份
// 合法的 trae 段（否则用户打开开关前看到的是空白），且解析失败应尽早暴露而不是
// 等到启用那一刻才报错。
func (c *Config) normalizeTrae() error {
	// AuthDir 空 = 复用主 auth_dir：两侧 glob（workbuddy*.json / trae-*.json）
	// 不重叠，同目录互不污染。显式配置即完全独立。
	if strings.TrimSpace(c.Trae.AuthDir) == "" {
		c.Trae.AuthDir = c.AuthDir
	}
	// StateFile 空 = 主 state 同目录的 state-trae.json（跟随 state_file 迁移）。
	if strings.TrimSpace(c.Trae.StateFile) == "" {
		c.Trae.StateFile = stateSibling(c.StateFile, "state-trae.json")
	}
	if strings.TrimSpace(c.Trae.DefaultModel) == "" {
		c.Trae.DefaultModel = "glm-5.2"
	}
	// CallbackPort：空 → 默认 18080；显式 "0" → 不起回调 server（纯手动粘贴模式）。
	if strings.TrimSpace(c.Trae.CallbackPort) == "" {
		c.Trae.CallbackPort = "18080"
	}
	if len(c.Trae.Schedule.CheckinHours) == 0 {
		c.Trae.Schedule.CheckinHours = []int{9}
	}
	if len(c.Trae.Schedule.RefreshHours) == 0 {
		c.Trae.Schedule.RefreshHours = []int{3}
	}
	if err := checkHourRange("trae.schedule.checkin_hours", "trae.schedule.checkin_enabled", c.Trae.Schedule.CheckinHours); err != nil {
		return err
	}
	if err := checkHourRange("trae.schedule.refresh_hours", "trae.schedule.refresh_enabled", c.Trae.Schedule.RefreshHours); err != nil {
		return err
	}
	if c.Trae.Cooldown.ErrThreshold <= 0 {
		c.Trae.Cooldown.ErrThreshold = 3
	}
	if c.Trae.Upstream.TimeoutSeconds <= 0 {
		c.Trae.Upstream.TimeoutSeconds = 120
	}
	var err error
	if c.TraePlanCreditDur, err = parseDurDefault(c.Trae.Cooldown.PlanCredit, "trae.cooldown.plan_credit", 12*time.Hour); err != nil {
		return err
	}
	if c.TraeSoftRateDur, err = parseDurDefault(c.Trae.Cooldown.SoftRate, "trae.cooldown.soft_rate", 60*time.Second); err != nil {
		return err
	}
	if c.TraeErrCooldownDur, err = parseDurDefault(c.Trae.Cooldown.ErrCooldown, "trae.cooldown.err_cooldown", 10*time.Minute); err != nil {
		return err
	}
	if c.TraeRefreshSkewDur, err = parseDurDefault(c.Trae.RefreshSkew, "trae.refresh_skew", 24*time.Hour); err != nil {
		return err
	}
	return nil
}

// parseDurDefault 解析 duration 字段：空串回落到 def（并写回字段，供面板展示），
// 非法值报错并带上字段名（fail fast，不静默回落掩盖配置错误）。
func parseDurDefault(raw, field string, def time.Duration) (time.Duration, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return def, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", field, err)
	}
	return d, nil
}

// normalizePrompt 校验 prompt.mode 并按 file 加载提示词文本（custom/append 模式）。
//
// mode 非法（非 passthrough/custom/append）启动报错，避免静默回落到某一分支；
// custom/append 模式下 file 非空但不可读 → 报错（fail fast），file 空 → 用内置默认
// （两模式共用同一加载路径，PromptText 均非空）。
// passthrough 模式不加载文本（透传客户端原始 system，文本在降级时用 prompt.Degraded）。
func (c *Config) normalizePrompt() error {
	switch m := strings.ToLower(strings.TrimSpace(c.Prompt.Mode)); m {
	case "", "passthrough":
		c.Prompt.Mode = "passthrough"
	case "custom":
		c.Prompt.Mode = "custom"
	case "append":
		c.Prompt.Mode = "append"
	default:
		return fmt.Errorf("prompt.mode: %q 不是合法值（passthrough / custom / append）", c.Prompt.Mode)
	}
	if c.Prompt.Mode == "custom" || c.Prompt.Mode == "append" {
		text, err := prompt.Load(c.Prompt.Mode, c.Prompt.File)
		if err != nil {
			return err
		}
		c.PromptText = text
	}
	return nil
}

// validateScheduleHours 校验排程小时落在 0-23。
//
// 为什么不用 `[-1]` 之类的哨兵值表意"禁用"：非法小时被静默吞掉时，用户以为关掉了签到，
// 实际可能被当成另一个整点照常执行；这里直接快速失败，并在错误信息里指向正确的开关
// （checkin_enabled / keepalive_enabled），避免用户靠猜哨兵值来配。
func (c *Config) validateScheduleHours() error {
	if err := checkHourRange("schedule.checkin_hours", "checkin_enabled", c.Schedule.CheckinHours); err != nil {
		return err
	}
	if err := checkHourRange("schedule.travel_hours", "travel_enabled", c.Schedule.TravelHours); err != nil {
		return err
	}
	if err := checkHourRange("schedule.activity_hours", "activity_enabled", c.Schedule.ActivityHours); err != nil {
		return err
	}
	if err := checkHourRange("schedule.keepalive_hours", "keepalive_enabled", c.Schedule.KeepaliveHours); err != nil {
		return err
	}
	if err := checkHourRange("schedule.blackcat_hours", "blackcat_enabled", c.Schedule.BlackcatHours); err != nil {
		return err
	}
	return checkHourRange("schedule.growth_hours", "growth_enabled", c.Schedule.GrowthHours)
}

func checkHourRange(field, switchKey string, hours []int) error {
	for _, h := range hours {
		if h < 0 || h > 23 {
			return fmt.Errorf("%s: %d 不是合法小时（0-23）；如要关闭该任务请设 schedule.%s=false", field, h, switchKey)
		}
	}
	return nil
}

// splitCSV 逗号分隔 → 去空白、丢空项（WB2A_DNS 用）。
func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// autoTrustHosts 出站 TLS 自动修的目标主机清单。
//
// 显式配置 tls_auto_trust_hosts 即完全采用它（不与内置清单合并）——用户给出清单
// 就是明确意图，合并会让「我只想修这一个」的诉求失效，也会无谓扩大 TOFU 作用面。
//
// 内置默认只含本服务本来就要访问的腾讯域名：CN 上游 copilot.tencent.com，以及
// global 上游 base。global.enabled=false 时不加 global 主机——纯 CN 部署不该为一个
// 永不访问的主机反复探测（每轮都会 Unreachable，白等一轮重试间隔）。
func (c *Config) autoTrustHosts() []string {
	if len(c.TLSAutoTrustHosts) > 0 {
		return dedupeHosts(c.TLSAutoTrustHosts)
	}
	out := []string{"copilot.tencent.com"}
	if c.Global.Enabled {
		chat := strings.TrimSpace(c.Global.ChatBase)
		if chat == "" {
			chat = "https://www.workbuddy.ai"
		}
		out = append(out, hostOfURL(chat))
		if bill := strings.TrimSpace(c.Global.BillingBase); bill != "" {
			out = append(out, hostOfURL(bill))
		}
	}
	return dedupeHosts(out)
}

// hostOfURL 从 URL 取主机名（带端口则保留）；非 http(s) 或解析失败返回空串。
func hostOfURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	return u.Host
}

// dedupeHosts 去空白、去重、保持原顺序。
func dedupeHosts(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, h := range in {
		h = strings.TrimSpace(h)
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	return out
}
