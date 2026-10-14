// alpn.go 出站 ALPN 与 h2 认知的一致性约束（连接层不变量）。
//
// 为什么需要单独一层（实测复现，非推测）：
//
//	net/http.Transport 把「TLS 层广告哪些应用协议」和「HTTP 层认识哪些协议」
//	放在两处**互相独立**的状态里：
//	  · 广告：TLSClientConfig.NextProtos（nil / 空 = 不广告任何协议）
//	  · 认识：Transport.TLSNextProto 的键（空 map = 一个都不认识）
//
//	两者一旦不一致，就会出现：服务端按 ALPN 选出 h2 并回 HTTP/2 帧，客户端却
//	用 HTTP/1.x 解析器去读，于是得到
//
//	  Post "https://www.workbuddy.ai/billing/meter/get-user-resource":
//	  net/http: HTTP/1.x transport connection broken: malformed HTTP response
//	  "\x00\x00\x12\x04\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x80..."
//
//	首四个字节 \x00\x00\x12\x04 正是 HTTP/2 的 SETTINGS 帧头（长度 0x12、
//	类型 0x04），其后跟一个 PING 帧——所以这是**协议错配**，不是证书或网络问题。
//
//	本仓库出站策略本是「禁 h2」（防半死 h2 流复用造成
//	"http2: timeout awaiting response headers"，见 transport.go）。原来的做法是
//	把 TLSNextProto 置成**空但非 nil 的 map**；这确实让标准库不再注册 h2，ALPN
//	也**恰好**变空——但「恰好」是脆的：任何一处把 NextProtos 写成含 h2（或标准库
//	将来改动隐式行为），立刻退化成上面那个错配，且只在部分域名上暴露。
//
//	故这里把「恰好为空」升级为**显式只广告 http/1.1**，并用同一个函数同时决定
//	TLS 侧与 HTTP 侧，从构造上杜绝二者分叉。
//
// 为什么偏偏「国际版」炸：实测（2026-10-11，本机直连）
//
//	www.workbuddy.ai            ALPN=http/1.1 → HTTP/1.1 401；ALPN=h2 → h2 帧
//	www.codebuddy.cn            ALPN=h2       → 仍回 HTTP/1.1（网关宽容）
//	copilot.tencent.com         ALPN=h2       → 仍回 HTTP/1.1（网关宽容）
//
// 即国际版严格按 ALPN 办事，国内网关无视 ALPN 一律回 HTTP/1.1，于是同一个错配
// 只在国际版上暴露——这正是「国内正常、国际版查询失败」的成因。
package upstream

import (
	"crypto/tls"
	"net/http"
	"strings"
)

// ALPNMode 出站 ALPN 策略。字面值与 config.json 的 tls_alpn 一致。
type ALPNMode string

const (
	// ALPNHTTP1 只广告 http/1.1（默认）。与 transport「禁 h2」的认知严格同调。
	ALPNHTTP1 ALPNMode = "http/1.1"
	// ALPNH2 广告 h2 + http/1.1，并真正启用标准库的 h2 实现。
	//
	// 逃生门：若中间盒/VPN/网关无视 ALPN 径自按 h2 回帧（此时客户端说什么都没用），
	// 唯有真的讲 h2 才能通。代价是回到 h2 流复用，半死连接由 ResponseHeaderTimeout
	// 与失败清池兜底（见 transport.go）。
	ALPNH2 ALPNMode = "h2"
)

// ParseALPNMode 解析配置值。空 / 未知 / 显式 "http/1.1" → ALPNHTTP1（默认且最安全）；
// "h2"（及常见别名 http2 / http/2）→ ALPNH2。
func ParseALPNMode(s string) ALPNMode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case string(ALPNH2), "http2", "http/2", "force-h2":
		return ALPNH2
	default:
		return ALPNHTTP1
	}
}

// nextProtos mode 对应的 ALPN 广告列表（绝不返回 nil：显式优于隐式）。
func (m ALPNMode) nextProtos() []string {
	if m == ALPNH2 {
		return []string{"h2", "http/1.1"}
	}
	return []string{"http/1.1"}
}

// normalizeTLSForALPN 返回 tc 的副本并把 NextProtos 钉成与 mode 同调的值。
//
// tc 为 nil 时按 mode 新建；**绝不改动入参**——调用方可能把同一个 *tls.Config
// 共享给多个 client（main.go 就把同一份 tlsCfg 同时给了 upstream 与
// http.DefaultTransport），原地改会互相污染。
func normalizeTLSForALPN(tc *tls.Config, m ALPNMode) *tls.Config {
	var out *tls.Config
	if tc == nil {
		out = &tls.Config{}
	} else {
		out = tc.Clone()
	}
	out.NextProtos = m.nextProtos()
	return out
}

// setHTTP1 把 tr 置成**无条件安全**的 http/1.1 自洽态。
//
// 为什么无条件安全：ALPN 只广告 http/1.1 ⇒ 对端不可能选出 h2 ⇒ HTTP 侧
// TLSNextProto 里有什么都永远匹配不上。所以即使这个 Transport 的
// onceSetNextProtoDefaults 早已跑过（典型：http.DefaultTransport），也不会分叉。
//
// 注意这里**不**调用 CloseIdleConnections：它会 Do 一次
// onceSetNextProtoDefaults（见 net/http transport.go:784），而该初始化一个
// Transport 只跑一次——在 HTTP/1.1 档把它烧掉，就等于永久关闭了这个 Transport
// 之后切 h2 的可能。需要清池的调用方请自己显式调。
func setHTTP1(tr *http.Transport) {
	tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	tr.TLSClientConfig = normalizeTLSForALPN(tr.TLSClientConfig, ALPNHTTP1)
}

// ApplyOutboundALPN 把 tr 调整到与 mode **自洽**的「广告 ⇄ 认知」组合，
// 返回是否成功应用（false = 目标档位未能生效，tr 已被置回 http/1.1 自洽态）。
//
// 调用时机：http/1.1 档随时可调；h2 档必须在 tr 首次发起请求**之前**——标准库的
// onceSetNextProtoDefaults 一个 Transport 只跑一次，跑过之后就再也不会自动填 h2。
//
// 本函数**不依赖**上面这条约定：h2 分支走完会回读 TLSNextProto 里到底有没有 "h2"，
// 没有就退回 http/1.1 并返回 false。因此不存在「广告了 h2 却不会讲 h2」的中间态
// ——而那个中间态正是本轮国际版查询失败的机制（见文件头注释）。
func ApplyOutboundALPN(tr *http.Transport, m ALPNMode) bool {
	if tr == nil {
		return false
	}
	if m != ALPNH2 {
		setHTTP1(tr)
		return true
	}
	// 幂等：已经处于 h2 档（HTTP 侧注册了 h2 且 TLS 侧也广告 h2）就直接成功返回。
	// 没有这一步，重复调用会踩到「CloseIdleConnections 已把一次性初始化烧过」
	// 而被误判成不可切换（HTTP 与 ChatHTTP 共用同一个 transport 时必然重复两次）。
	if _, ok := tr.TLSNextProto["h2"]; ok && hasNextProto(tr.TLSClientConfig, "h2") {
		return true
	}
	tr.TLSNextProto = nil
	tr.ForceAttemptHTTP2 = true
	tr.TLSClientConfig = normalizeTLSForALPN(tr.TLSClientConfig, m)

	// CloseIdleConnections 内部会 Do 一次 onceSetNextProtoDefaults，借此把 h2 注册
	// 落实下来，随后即可回读验证（顺带清掉可能带着旧 ALPN 结论的闲置连接）。
	tr.CloseIdleConnections()
	if _, ok := tr.TLSNextProto["h2"]; !ok {
		// 该 Transport 早已初始化过（Once 只跑一次），再置 nil 也不会重新注册 h2。
		// 此时若留着 h2 的 ALPN 就会亲手造出本文档开头那个错配——退回 http/1.1
		// 自洽态：宁可不走 h2，也绝不错配。
		setHTTP1(tr)
		return false
	}
	return true
}

// hasNextProto 报告 tc 的 ALPN 公告里是否含 p（tc 为 nil 时按不含处理）。
func hasNextProto(tc *tls.Config, p string) bool {
	if tc == nil {
		return false
	}
	for _, s := range tc.NextProtos {
		if s == p {
			return true
		}
	}
	return false
}

// alpnMode 当前生效的出站 ALPN 策略（空值按 ALPNHTTP1 处理）。
func (c *Client) alpnMode() ALPNMode {
	if c == nil || c.alpn != ALPNH2 {
		return ALPNHTTP1
	}
	return c.alpn
}

// SetALPNMode 切换出站 ALPN 策略，并同步应用到 HTTP / ChatHTTP 两个 client
// 共用的 Transport。
//
// 必须在服务开始接收请求**之前**调用（ALPNH2 依赖一次性初始化，见
// ApplyOutboundALPN）。返回是否成功——false 表示目标模式未能生效（当前仍是
// 之前那一档），调用方应据此记日志而不是默默继续。
func (c *Client) SetALPNMode(m ALPNMode) bool {
	if c == nil {
		return false
	}
	if m != ALPNH2 {
		m = ALPNHTTP1
	}
	c.alpn = m
	seen := map[*http.Transport]bool{}
	ok := true
	for _, cl := range []*http.Client{c.HTTP, c.ChatHTTP} {
		if cl == nil {
			continue
		}
		tr, isTr := cl.Transport.(*http.Transport)
		if !isTr || seen[tr] {
			continue // HTTP 与 ChatHTTP 通常共用同一个 transport，只处理一次
		}
		seen[tr] = true
		if !ApplyOutboundALPN(tr, m) {
			ok = false
		}
	}
	return ok
}
