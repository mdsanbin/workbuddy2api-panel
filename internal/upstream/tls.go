// tls.go 出站 TLS 信任配置：应对中间人代理导致的
//
//	Post "https://copilot.tencent.com/...": tls: failed to verify certificate:
//	x509: certificate signed by unknown authority
//
// 成因：Go 出站校验只用「系统根证书池」（Android 为 /system/etc/security/cacerts，
// Linux 为 /etc/ssl/certs，Windows 为系统证书库）。企业代理 / 抓包工具 / 手机端
// VPN 自签 CA 常被装进「用户级」证书库——那不在 Go 的根池里，于是所有上游 TLS
// 握手一律失败，且表现为「网络不通」，排查成本很高。
//
// 两条出口（config.json 顶层）：
//   - tls_ca_file：把代理 CA 的 PEM 追加进信任池（推荐，不降低安全强度）；
//   - tls_insecure_skip_verify：完全跳过校验（最后手段，等于放弃中间人防护）。
//
// 两者都不配时行为与改动前逐字一致（无 TLSClientConfig，走标准库默认）。
package upstream

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// BuildTLSConfig 按 caFile / insecure 构造出站 TLS 配置。
//   - 两者皆空/false → (nil, nil)：调用方据此保持默认客户端，零行为变化；
//   - caFile 非空 → 系统根池 ∪ 该文件（多张 PEM 亦可），代理只拦部分域名时
//     直连域名仍靠系统根通过；
//   - insecure=true → 跳过校验（此时若同时给了 caFile，也一并并入，便于随时回退）。
func BuildTLSConfig(caFile string, insecure bool) (*tls.Config, error) {
	caFile = strings.TrimSpace(caFile)
	if caFile == "" && !insecure {
		return nil, nil
	}
	tc := &tls.Config{InsecureSkipVerify: insecure}
	if caFile == "" {
		return tc, nil
	}
	// 读文件放在最前：路径写错要 fail fast，不能等首个请求才暴露。
	pemBytes, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("tls_ca_file: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		// Android / 精简容器里可能取不到系统池（无 /etc/ssl/certs 且无 cacerts）。
		// 退化语义：只信任自备 CA —— 中间人代理对所有域名都用自己的 CA 签，
		// 因此这不影响目标场景；直连域名会不通，届时改用 insecure 或直连分流。
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("tls_ca_file %s: 未解析出任何 PEM 证书"+
			"（需 PEM 文本，DER/.crt 二进制请先转换；Android 用户证书 /data/misc/user/0/cacerts-added/*.0 就是 PEM）", caFile)
	}
	tc.RootCAs = pool
	return tc, nil
}

// SetTLSConfig 把 TLS 配置应用到出站 Transport。
// Client.HTTP 与 Client.ChatHTTP 共用同一个 *http.Transport（见 New），
// 此处对两个字段都做赋值是幂等的，同时兼容测试注入自定义 RoundTripper 的场景。
// 必须在服务开始接收请求前调用。
//
// 赋值前经 normalizeTLSForALPN 钉住 NextProtos：TLS 层「广告什么」必须与
// transport 层「认识什么」同调，否则会得到 malformed HTTP response
// （HTTP/2 帧被 HTTP/1.x 解析器读）——成因与实证见 alpn.go。
func (c *Client) SetTLSConfig(tc *tls.Config) {
	if c == nil || tc == nil {
		return
	}
	tc = normalizeTLSForALPN(tc, c.alpnMode())
	if tr, ok := c.HTTP.Transport.(*http.Transport); ok {
		tr.TLSClientConfig = tc
	}
	if tr, ok := c.ChatHTTP.Transport.(*http.Transport); ok {
		tr.TLSClientConfig = tc
	}
}

// ApplyTLSCA 从 caFile 重建信任配置并**热应用**到出站 Transport，返回生效的
// *tls.Config（供调用方同步给面板登录 client）。
//
// 与 SetTLSConfig 的差别在最后一步：这里清空两个 client 的空闲连接池。
// 已建立的 keep-alive 连接是带着旧信任结论握完手的，不清掉就会继续复用、
// 让「刚导入的 CA」看起来没生效——排障场景里这个假象最耗时间。
//
// caFile 路径必须真实存在且含 ≥1 张 PEM，否则返回 error 且**不做任何改动**
// （调用方据此提示用户，而不是默默保持半生效状态）。
func (c *Client) ApplyTLSCA(caFile string) (*tls.Config, error) {
	tc, err := BuildTLSConfig(caFile, false)
	if err != nil {
		return nil, err
	}
	if tc == nil {
		return nil, nil
	}
	c.SetTLSConfig(tc)
	if c.HTTP != nil {
		roundTripCloseIdle(c.HTTP.Transport)
	}
	if c.ChatHTTP != nil {
		roundTripCloseIdle(c.ChatHTTP.Transport)
	}
	return tc, nil
}
