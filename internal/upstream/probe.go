// probe.go 上游证书链探测：把「TLS 握手失败」从黑盒变成可操作的一步。
//
// 场景：中间人代理（手机 VPN / 抓包工具 / 企业网关）把 copilot.tencent.com
// 的证书换成自签 CA 签发的，而 Go 出站只用「系统根池」校验，于是报
//
//	Post "...": tls: failed to verify certificate: x509: certificate signed by unknown authority
//
// 用户既看不到是谁签的，也不知道该信任哪一张。本文件主动连一次、把对端实际
// 出示的整条链取回来，交给调用方（面板 /panel/tls 诊断页）展示与一键信任。
//
// 只读能力：不改任何状态、不写文件、不使用账号凭证（纯 TLS 握手）。
//
// 复用出站 DialContext（而非裸 net.Dial）是关键：Android 上没有
// /etc/resolv.conf，默认解析器会退回 [::1]:53 直接失败；走 Transport 上已接线的
// DNS dialer（见 dns.go）才能解析出地址，探测本身才可能成功。
package upstream

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// probeTimeout 单次探测（TCP + 两/三次 TLS 握手）的总上限。
// 比 dialTimeout(10s) 宽：探测要串行跑多次握手，且用户正在排障，宁可慢也别误报。
const probeTimeout = 20 * time.Second

// CertInfo 一张对端证书的展示信息 + 原始 PEM。
// PEM 原样保留（不做 DER/Base64 重编码），调用方据此拼出可直接喂给
// tls_ca_file 的文件内容。
type CertInfo struct {
	Index      int      `json:"index"`
	Subject    string   `json:"subject"`
	Issuer     string   `json:"issuer"`
	NotBefore  string   `json:"not_before"`
	NotAfter   string   `json:"not_after"`
	IsCA       bool     `json:"is_ca"`
	SelfSigned bool     `json:"self_signed"`
	DNSNames   []string `json:"dns_names,omitempty"`
	SHA256     string   `json:"sha256"`
	PEM        string   `json:"pem"`
}

// ProbeResult 一次探测的完整结果。
type ProbeResult struct {
	Host string `json:"host"` // 规范化后的裸主机名（无端口）
	Addr string `json:"addr"` // 实际连接的 host:port
	// Chain 对端出示的链，[0] 为叶证书（保持上游给出的顺序）。
	Chain []CertInfo `json:"chain"`
	// TrustedBySystem 用「系统根池」严格校验是否通过。
	// false + VerifyErr 非空 = 当前环境的真实症状（unknown authority 等）。
	TrustedBySystem bool   `json:"trusted_by_system"`
	VerifyErr       string `json:"verify_err,omitempty"`
	// ConfiguredVerifyErr 用「当前生效的信任池」校验失败时的原因。
	// 与 VerifyErr 的区别很关键：VerifyErr 回答「系统池为什么不认」（通常是
	// unknown authority），本字段回答「你已经配了 CA 之后为什么还是不通」
	// （证书没有 SAN、域名不匹配、CA 配错了……）——后者才是下一步的线索。
	ConfiguredVerifyErr string `json:"configured_verify_err,omitempty"`
	// TrustedByConfigured 用「当前生效的信任池」（含已配置的 tls_ca_file / ca.pem）
	// 校验是否通过。回答「上次配的 CA 到底生效了没有」。
	TrustedByConfigured bool `json:"trusted_by_configured"`
	// SuggestedPEM 建议写入 ca.pem 的内容：整条链的 PEM 拼接。
	// 一并带上叶证书无害——AppendCertsFromPEM 按 DER 去重，多余条目会被忽略。
	SuggestedPEM string `json:"suggested_pem"`
}

// ProbeChain 连接 host（缺端口按 443）并抓取对端证书链，同时给出系统池 /
// 当前生效池两种校验结论。err 非 nil 表示连 TCP 或握手都没成（真的不通）。
func (c *Client) ProbeChain(ctx context.Context, host string) (*ProbeResult, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil, errors.New("probe: 主机名为空")
	}
	hostOnly, port := splitHostPortDefault(host, "443")
	if hostOnly == "" {
		return nil, fmt.Errorf("probe: 无法解析主机名 %q", host)
	}
	addr := net.JoinHostPort(hostOnly, port)

	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	raw, err := c.dialForProbe(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("probe: 连接 %s 失败: %w", addr, err)
	}
	defer raw.Close()

	// 第一次握手：跳过校验，无论对方出示什么都能把链完整拿回来。
	insecure := tls.Client(raw, &tls.Config{ServerName: hostOnly, InsecureSkipVerify: true})
	_ = insecure.SetDeadline(time.Now().Add(probeTimeout))
	if err := insecure.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("probe: TLS 握手失败: %w", err)
	}
	chain := insecure.ConnectionState().PeerCertificates
	if len(chain) == 0 {
		return nil, errors.New("probe: 对端未出示任何证书")
	}

	res := &ProbeResult{Host: hostOnly, Addr: addr, Chain: make([]CertInfo, 0, len(chain))}
	var buf strings.Builder
	for i, cert := range chain {
		ci := certInfoOf(i, cert)
		res.Chain = append(res.Chain, ci)
		buf.WriteString(ci.PEM)
	}
	res.SuggestedPEM = buf.String()

	// 第二次握手：系统根池严格校验（另起连接，不复用上面跳过校验的会话）。
	res.TrustedBySystem, res.VerifyErr = c.verifyChain(ctx, addr, hostOnly, nil)
	// 第三次：当前生效池（可能已并入用户配的 CA）。
	if roots := c.configuredRoots(); roots != nil {
		res.TrustedByConfigured, res.ConfiguredVerifyErr = c.verifyChain(ctx, addr, hostOnly, roots)
	} else {
		res.TrustedByConfigured = res.TrustedBySystem
		res.ConfiguredVerifyErr = res.VerifyErr
	}
	return res, nil
}

// verifyChain 用给定根池（nil = 系统池）对 addr 做一次严格校验握手，
// 返回 (是否通过, 失败原因)。失败原因来自标准库，正是用户看到的那句。
func (c *Client) verifyChain(ctx context.Context, addr, serverName string, roots *x509.CertPool) (bool, string) {
	raw, err := c.dialForProbe(ctx, addr)
	if err != nil {
		return false, err.Error()
	}
	defer raw.Close()
	conn := tls.Client(raw, &tls.Config{ServerName: serverName, RootCAs: roots})
	_ = conn.SetDeadline(time.Now().Add(probeTimeout))
	if err := conn.HandshakeContext(ctx); err != nil {
		return false, err.Error()
	}
	return true, ""
}

// dialForProbe 复用出站 Transport 的 DialContext：继承已配置的 DNS 解析器
// （Android 必需）、建连超时与 keepalive 参数。测试注入的非 *http.Transport
// 或未接线时回落默认拨号器。
func (c *Client) dialForProbe(ctx context.Context, addr string) (net.Conn, error) {
	if c != nil && c.HTTP != nil {
		if tr, ok := c.HTTP.Transport.(*http.Transport); ok && tr.DialContext != nil {
			return tr.DialContext(ctx, "tcp", addr)
		}
	}
	return newDialer().DialContext(ctx, "tcp", addr)
}

// configuredRoots 当前出站 Transport 上已生效的自定义根池（含用户配的
// tls_ca_file 与自动加载的 ca.pem）。未配置过时返回 nil，语义等同「用系统根池」。
func (c *Client) configuredRoots() *x509.CertPool {
	if c == nil || c.HTTP == nil {
		return nil
	}
	if tr, ok := c.HTTP.Transport.(*http.Transport); ok && tr.TLSClientConfig != nil {
		return tr.TLSClientConfig.RootCAs
	}
	return nil
}

// certInfoOf 把一张证书投影成展示信息（含 SHA256 指纹与 PEM）。
func certInfoOf(i int, cert *x509.Certificate) CertInfo {
	sum := sha256.Sum256(cert.Raw)
	return CertInfo{
		Index:      i,
		Subject:    cert.Subject.String(),
		Issuer:     cert.Issuer.String(),
		NotBefore:  cert.NotBefore.Format(time.RFC3339),
		NotAfter:   cert.NotAfter.Format(time.RFC3339),
		IsCA:       cert.IsCA,
		SelfSigned: cert.CheckSignatureFrom(cert) == nil,
		DNSNames:   cert.DNSNames,
		SHA256:     hex.EncodeToString(sum[:]),
		PEM:        string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
	}
}

// splitHostPortDefault 接受 "host" / "host:port" / "[v6]" / "[v6]:port"。
// 裸 IPv6（含冒号但不是 host:port）会 SplitHostPort 失败，按无端口处理。
func splitHostPortDefault(s, defPort string) (host, port string) {
	if h, p, err := net.SplitHostPort(s); err == nil {
		return h, p
	}
	return strings.Trim(s, "[]"), defPort
}
