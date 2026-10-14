// tlsauto.go 面板侧「出站 TLS 自动修」：请求撞上证书错误时，现场探测上游 →
// 信任其出示的链 → 原样重试一次。
//
// 与 tlsdiag.go 的关系：诊断页是「手动、可见、可解释」的路径；本文件是
// 「用户不操作也能通过」的兜底路径 —— 两者共用 upstream.EnsureTrusted 同一套逻辑。
//
// 状态放包级的理由：loginHTTP 是包级单例，自动修必须能拿到它的 CA 落盘位置与
// 出站 client，故由 main 在启动时通过 SetTLSAutoHeal 注入。
package panel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

// tlsHealCooldown 同一主机的自动修最小间隔。
// 上游持续不可用时，每个失败请求都触发一轮探测（每轮 3 次 TLS 握手）会造成
// 请求放大，故做冷却；冷却内的失败请求直接原样返回错误。
const tlsHealCooldown = 30 * time.Second

// tlsHeal 自动修的包级上下文（loginHTTP 是包级单例，故状态也必须在包级）。
var tlsHeal struct {
	mu     sync.Mutex
	caFile string
	up     *upstream.Client
	last   map[string]time.Time
}

// SetTLSAutoHeal 注册自动修上下文（caFile = ca.pem 落盘路径；up = 出站 client）。
// 未注册时（up == nil）自动修静默跳过 —— 行为与改动前完全一致。
func SetTLSAutoHeal(caFile string, up *upstream.Client) {
	tlsHeal.mu.Lock()
	defer tlsHeal.mu.Unlock()
	tlsHeal.caFile = caFile
	tlsHeal.up = up
	if tlsHeal.last == nil {
		tlsHeal.last = make(map[string]time.Time)
	}
}

// doWithTLSHeal 发送设备授权请求；若因「证书不受信任」失败，现场自动修一次信任后
// 原样重试一次。
//
// 为什么只重试一次：自动修要么成功（信任池已含对端 CA，重试必成），要么失败
// （环境确实有问题），再试只是浪费。body 能重放是因为 http.NewRequest 会对
// *bytes.Reader/*bytes.Buffer/*strings.Reader 自动填充 GetBody；无 body 的 GET
// 天然可重放。
func doWithTLSHeal(req *http.Request) (*http.Response, error) {
	resp, err := loginHTTP.Do(req)
	if err == nil || !isCertErr(err) {
		return resp, err
	}
	if !healTLSForHost(req.URL.Host) {
		return resp, err
	}
	retry := req.Clone(req.Context())
	if req.GetBody != nil {
		b, gerr := req.GetBody()
		if gerr != nil {
			return resp, err
		}
		retry.Body = b
	}
	return loginHTTP.Do(retry)
}

// healTLSForHost 为该主机尝试一次自动修；返回 true 表示信任池已被改动
// （调用方应重试原请求）。失败只记日志，不返回错误。
func healTLSForHost(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}

	tlsHeal.mu.Lock()
	up, caFile := tlsHeal.up, tlsHeal.caFile
	if up == nil || caFile == "" {
		tlsHeal.mu.Unlock()
		return false
	}
	if tlsHeal.last == nil {
		tlsHeal.last = make(map[string]time.Time)
	}
	if last, ok := tlsHeal.last[host]; ok && time.Since(last) < tlsHealCooldown {
		tlsHeal.mu.Unlock()
		return false
	}
	tlsHeal.last[host] = time.Now()
	tlsHeal.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	out, tc, err := upstream.EnsureTrusted(ctx, up, host, caFile)
	if err != nil {
		log.Printf("TLS 自动修：%s 失败：%v", host, err)
		return false
	}
	switch out.Status {
	case upstream.TrustStatusTrusted:
		log.Printf("TLS 自动修：已信任 %s 出示的证书链（新增 %d 张，复验通过）→ %s", host, out.CertsAdded, caFile)
	case upstream.TrustStatusUnverified:
		log.Printf("TLS 自动修：%s 已写入 CA 但复验未通过（%s）", host, out.Detail)
	case upstream.TrustStatusUnreachable:
		log.Printf("TLS 自动修：%s 暂不可达（%s）", host, out.Detail)
	case upstream.TrustStatusSkipped:
		log.Printf("TLS 自动修：%s 未处理（%s）", host, out.Detail)
	}
	if tc == nil {
		return false
	}
	SetLoginClientTLS(tc)
	return true
}

// isCertErr 判定错误是否属于「证书不受信任」类。
// 先按 x509 的具体错误类型精确判断，再以文本兜底覆盖被包装层吞掉类型的场景
// （与 tlsErrorHint 的口径保持一致）。
func isCertErr(err error) bool {
	if err == nil {
		return false
	}
	var ua x509.UnknownAuthorityError
	var hn x509.HostnameError
	var ci x509.CertificateInvalidError
	var cv *tls.CertificateVerificationError
	if errors.As(err, &ua) || errors.As(err, &hn) || errors.As(err, &ci) || errors.As(err, &cv) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "certificate") || strings.Contains(msg, "x509")
}
