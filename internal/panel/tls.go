// tls.go 面板侧出站 TLS 的四个接缝：
//   - hotTransport：可热替换的出站 transport（运行期「自动修」换信任池用）；
//   - SetLoginClientTLS：给设备授权 client（loginHTTP）注入 TLS 信任配置；
//   - SetLoginALPN：给它注入出站 ALPN 档位（与网关出站同口径）；
//   - tlsErrorHint：给「证书不受信任」「出站协议错配」类错误补一句可操作提示。
//
// 为什么单独成文件：login.go 只管设备授权流程本身，TLS 信任是横切关注点，
// 且 main 需要在启动时调用 SetLoginClientTLS / SetLoginALPN（见 cmd/server/main.go）。
package panel

import (
	"crypto/tls"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

// hotTransport 是内部 transport 可被原子替换的 RoundTripper。
//
// 为什么需要它：loginHTTP 是包级单例，而出站 TLS 信任池会在**运行期**被自动修
// 替换（启动后台修 / 请求撞上证书错误时修）。直接改 loginHTTP.Transport 字段会与
// 正在 Do 的 goroutine 数据竞争；固定住这一个 RoundTripper、只换它内部持有的
// *http.Transport，读写就都是原子的。
type hotTransport struct {
	cur atomic.Pointer[http.Transport]
}

func (h *hotTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if tr := h.cur.Load(); tr != nil {
		return tr.RoundTrip(req)
	}
	// 未注入自定义信任池时回落标准库默认传输：继承 ProxyFromEnvironment、
	// 以及 main 可能已替换掉的 DNS DialContext —— 行为与改动前逐字一致。
	return http.DefaultTransport.RoundTrip(req)
}

func (h *hotTransport) set(tr *http.Transport) { h.cur.Store(tr) }

// loginTransport 设备授权 client 全程复用的那一个 RoundTripper（见 loginHTTP）。
var loginTransport = &hotTransport{}

// loginCfg 设备授权 client 的出站配置。loginHTTP 是包级单例，而信任池会在运行期
// 被「自动修」替换、ALPN 档位在启动期被设置，故配置本身也用锁保护。
var loginCfg struct {
	mu   sync.Mutex
	tc   *tls.Config
	alpn upstream.ALPNMode // 零值 = ALPNHTTP1
}

// rebuildLoginTransportLocked 按当前配置重建热替换 transport（调用方须持 loginCfg.mu）。
//
// 基于 http.DefaultTransport 克隆而非裸建：继承其连接池参数、ProxyFromEnvironment，
// 以及 main 已替换掉的 DNS DialContext，只覆盖 TLS 相关内容。
//
// ALPN 一律交给 upstream.ApplyOutboundALPN 统一钉死 —— 这里必须叫它而不是只赋
// TLSClientConfig：Clone() 会把 DefaultTransport 已注册的 h2 一并带过来，若只看
// TLSClientConfig 而不同时约束「广告什么」，就会埋下「TLS 层广告 h2 / HTTP 层只认
// http/1.1」的错配（成因与实证见 upstream/alpn.go）。
func rebuildLoginTransportLocked() {
	base, ok := http.DefaultTransport.(*http.Transport)
	var nt *http.Transport
	if ok {
		nt = base.Clone()
	} else {
		nt = &http.Transport{}
	}
	if loginCfg.tc != nil {
		nt.TLSClientConfig = loginCfg.tc
	}
	upstream.ApplyOutboundALPN(nt, loginCfg.alpn)
	loginTransport.set(nt)
}

// SetLoginClientTLS 给设备授权专用 client 应用出站 TLS 配置（中间人代理 CA）。
//
// 可重复调用 —— 运行期自动修会再次调用来热生效。
func SetLoginClientTLS(tc *tls.Config) {
	if tc == nil {
		return
	}
	loginCfg.mu.Lock()
	defer loginCfg.mu.Unlock()
	loginCfg.tc = tc
	rebuildLoginTransportLocked()
}

// SetLoginALPN 设置设备授权专用 client 的出站 ALPN 档位（config tls_alpn），
// 与网关出站保持同一口径。必须在服务开始接收请求前调用。
func SetLoginALPN(m upstream.ALPNMode) {
	loginCfg.mu.Lock()
	defer loginCfg.mu.Unlock()
	loginCfg.alpn = m
	if loginCfg.tc != nil {
		rebuildLoginTransportLocked()
	}
}

// resetLoginTransport 清空热替换的 transport，回到「回落 DefaultTransport」态。
// 仅测试用：避免某个用例注入的信任池污染同包其它用例。
func resetLoginTransport() {
	loginCfg.mu.Lock()
	loginCfg.tc = nil
	loginCfg.alpn = ""
	loginCfg.mu.Unlock()
	loginTransport.set(nil)
}

// tlsErrorHint 对两类「表面上像网络不通、实则各有明确处置」的出站错误追加提示，
// 其它错误返回空串。
//
//  1. 证书类：几乎总是中间人代理（手机 VPN / 抓包工具 / 企业网关）的自签 CA 不在
//     Go 的系统根池里；但报错文本只说 certificate signed by unknown authority，
//     用户极易误判成「网络不通」而反复检查 DNS/防火墙。
//  2. 协议错配：报文里出现二进制 HTTP/2 帧，标准库报成
//     net/http: HTTP/1.x transport connection broken: malformed HTTP response
//     "\x00\x00\x12\x04..."（\x00\x00\x12\x04 是 h2 的 SETTINGS 帧头）。这既不是
//     证书问题也不是「上游挂了」，而是出站 ALPN 与 HTTP 层认知不一致／中间盒强行按
//     h2 回帧 —— 处置方式是切 tls_alpn=h2（见 internal/upstream/alpn.go）。
func tlsErrorHint(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if strings.Contains(msg, "malformed HTTP response") {
		return "；出站协议错配：对端按 HTTP/2 回帧、本客户端按 HTTP/1.x 解析" +
			"（常见于中间盒/VPN 无视 ALPN 强制 h2）。可在 config.json 设" +
			" tls_alpn=\"h2\"（或环境变量 WB2A_TLS_ALPN=h2）后重启网关"
	}
	if !strings.Contains(msg, "certificate") &&
		!strings.Contains(msg, "x509") &&
		!strings.Contains(msg, "tls:") {
		return ""
	}
	return "；疑似 TLS 中间人代理（VPN/抓包/企业网关）——打开面板 TLS 诊断页 " +
		"/panel/tls 可一键探测并信任其 CA；或让该域名走直连（详见 README 的 TLS 排障）"
}
