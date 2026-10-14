// tlsdiag.go 面板「TLS 诊断」页：把
//
//	Post "https://copilot.tencent.com/...": tls: failed to verify certificate:
//	x509: certificate signed by unknown authority
//
// 从一句黑盒报错变成两步操作（探测 → 一键信任）。
//
// 为什么单独成页而非塞进 app.js 的配置页：
//   - 这个场景只在「刚装好、还没法用」时出现，用户此时对面板不熟，
//     一个短页面比在配置页里翻找更直接；
//   - 不触碰 index.html / app.js（上游高频改动区），同步上游零冲突。
//
// 安全（两条都必要）：
//   - /panel/api/tls/* 与其它数据接口同口径走 Bearer 鉴权（withAuth）；
//   - trust 只接受主机名，证书内容由**服务端自己重新探测**取回——不接受客户端
//     上传的 PEM，否则这条接口就变成「向磁盘写任意内容」的通道了。
package panel

import (
	_ "embed"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

//go:embed tlsdiag.html
var tlsdiagHTML []byte

//go:embed tlsdiag.js
var tlsdiagJS []byte

// defaultTLSDiagHost 诊断页默认探测的上游主机：正是报错信息里出现的那个。
const defaultTLSDiagHost = "copilot.tencent.com"

// caPEMPath 自备 CA 落盘位置：与 config.json **同目录**的 ca.pem。
//
// 选这个位置是因为 service.sh 启动时已会自动加载同目录 ca.pem：
// 面板点「信任」写这个文件、模块脚本事后照常生效，两条路径天然对齐；
// 用户想手工丢一个 CA 进去时，和配置放一起也最符合直觉。
func (p *Panel) caPEMPath() string {
	dir := "."
	if p.cfg.ConfigPath != "" {
		dir = filepath.Dir(p.cfg.ConfigPath)
	}
	return filepath.Join(dir, "ca.pem")
}

// tlsPage 输出诊断页（静态无秘密，可匿名加载；数据接口才鉴权）。
func (p *Panel) tlsPage(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(tlsdiagHTML)
}

// tlsScript 输出诊断页脚本（同源，满足 CSP script-src 'self'，无内联脚本）。
func (p *Panel) tlsScript(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(tlsdiagJS)
}

// tlsProbe GET /panel/api/tls/probe?host=host[:port]
// 探测上游证书链，只读、不改状态。
func (p *Panel) tlsProbe(w http.ResponseWriter, r *http.Request) {
	if p.cfg.Upstream == nil {
		writeErr(w, http.StatusNotImplemented, "upstream_not_configured")
		return
	}
	host, ok := probeHostOr(w, r.URL.Query().Get("host"))
	if !ok {
		return
	}
	res, err := p.cfg.Upstream.ProbeChain(r.Context(), host)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"probe":   res,
		"ca_path": p.caPEMPath(),
	})
}

// tlsTrustReq 信任请求体：只有主机名（见文件头安全说明，不接受 PEM）。
type tlsTrustReq struct {
	Host string `json:"host"`
}

// tlsTrust POST /panel/api/tls/trust
// 重新探测一次上游 → 把整条链写成 ca.pem → 热加载进信任池 → 复验是否已通。
func (p *Panel) tlsTrust(w http.ResponseWriter, r *http.Request) {
	if p.cfg.Upstream == nil {
		writeErr(w, http.StatusNotImplemented, "upstream_not_configured")
		return
	}
	var req tlsTrustReq
	// 上限 4KB：请求体只有一个主机名，大 body 一律视为异常。
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_json")
		return
	}
	host, ok := probeHostOr(w, req.Host)
	if !ok {
		return
	}

	// 服务端自取自证：绝不用客户端送来的证书内容。
	probe, err := p.cfg.Upstream.ProbeChain(r.Context(), host)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if strings.TrimSpace(probe.SuggestedPEM) == "" {
		writeErr(w, http.StatusBadGateway, "探测未取到任何证书，未写入")
		return
	}

	// 共用自动修那一套「合并去重 + 原子替换」写盘：手工信任与自动修写的是同一个
	// ca.pem，代理对不同域名用不同 CA 时必须累积，不能后一次覆盖前一次。
	path := p.caPEMPath()
	if _, err := upstream.MergePEMToFile(path, probe.SuggestedPEM); err != nil {
		writeErr(w, http.StatusInternalServerError, "写入 "+path+" 失败: "+err.Error())
		return
	}

	// 热生效：重建信任池 → 换到出站 Transport（连面板登录 client 一起）→ 清空闲连接。
	hot, note := true, ""
	if tc, err := p.cfg.Upstream.ApplyTLSCA(path); err != nil {
		hot = false
		note = "证书已保存，但热加载失败（重启网关后生效）: " + err.Error()
	} else if tc != nil {
		SetLoginClientTLS(tc)
	}

	// 复验：用刚生效的池再握一次手，直接回答「现在通了吗」。
	// 失败时把「配置之后的真实原因」带出来——否则用户只看到一句含糊的
	// 「仍未通过」，而真正原因（证书缺 SAN / 域名不匹配 / CA 配错）才是下一步线索。
	verified := false
	if re, err := p.cfg.Upstream.ProbeChain(r.Context(), host); err == nil {
		verified = re.TrustedByConfigured
		if !verified && hot {
			reason := strings.TrimSpace(re.ConfiguredVerifyErr)
			if reason == "" {
				reason = "未取到具体原因"
			}
			note = "证书已保存并热加载，但复验仍未通过：" + reason +
				" —— 若原因是域名不匹配或缺 SAN，说明该代理证书另有问题；" +
				"否则可能是它对不同域名用了不同 CA，请对其余报错域名各探测一次。"
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"ca_path":     path,
		"host":        probe.Host,
		"cert_count":  len(probe.Chain),
		"hot_applied": hot,
		"verified":    verified,
		"note":        note,
	})
}

// probeHostOr 归一化并校验探测目标，非法时已写好错误响应并返回 ok=false。
// 字符集白名单（主机名/IPv4/IPv6 字面量所需的全部字符）——这是一个会发起
// 外连的诊断接口，收紧输入避免被当成任意目标的连接跳板。
func probeHostOr(w http.ResponseWriter, raw string) (string, bool) {
	host := strings.TrimSpace(raw)
	if host == "" {
		host = defaultTLSDiagHost
	}
	if len(host) > 255 || strings.ContainsAny(host, " /\\?#@\t\r\n") {
		writeErr(w, http.StatusBadRequest, "invalid_host")
		return "", false
	}
	return host, true
}
