// probe_test.go 证书链探测 + 一键信任的端到端验证：
// 起一个自签 HTTPS 服务扮演「被中间人替换证书的上游」，验证
//
//	探测拿到链 → 诊断出系统池不信任 → 落盘 CA → 热加载 → 复验通过
//
// 这条闭环正是面板 /panel/tls 上点两下所做的事。
package upstream

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestProbeChainSelfSignedAndTrust 主链路：自签上游 → 探到链 → 信任后复验通过。
func TestProbeChainSelfSignedAndTrust(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	c := New()
	addr := strings.TrimPrefix(srv.URL, "https://") // 127.0.0.1:<port>

	res, err := c.ProbeChain(context.Background(), addr)
	if err != nil {
		t.Fatalf("ProbeChain: %v", err)
	}
	if len(res.Chain) == 0 {
		t.Fatal("应至少拿到 1 张证书")
	}
	if !strings.Contains(res.SuggestedPEM, "BEGIN CERTIFICATE") {
		t.Errorf("SuggestedPEM 应为 PEM 文本，got %q", res.SuggestedPEM)
	}
	if res.TrustedBySystem {
		t.Fatal("自签服务不该被系统根池信任 —— 这正是用户看到 unknown authority 的成因")
	}
	if !strings.Contains(res.VerifyErr, "certificate") {
		t.Fatalf("校验失败原因应含 certificate，got %q", res.VerifyErr)
	}
	if res.TrustedByConfigured {
		t.Fatal("未配置 CA 时「当前生效池」也不应通过")
	}
	if !res.Chain[0].SelfSigned {
		t.Errorf("httptest 的叶证书应被识别为自签，got %+v", res.Chain[0])
	}
	if res.Chain[0].SHA256 == "" || res.Chain[0].Subject == "" {
		t.Errorf("证书展示字段不应为空，got %+v", res.Chain[0])
	}
	if res.Addr == "" || res.Host == "" {
		t.Errorf("Host/Addr 不应为空，got host=%q addr=%q", res.Host, res.Addr)
	}

	// 一键信任：SuggestedPEM 落盘 → 热加载 → 复验。
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, []byte(res.SuggestedPEM), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ApplyTLSCA(caPath); err != nil {
		t.Fatalf("ApplyTLSCA: %v", err)
	}

	res2, err := c.ProbeChain(context.Background(), addr)
	if err != nil {
		t.Fatalf("ProbeChain(复验): %v", err)
	}
	if !res2.TrustedByConfigured {
		t.Fatalf("信任后「当前生效池」应通过，verifyErr=%q", res2.VerifyErr)
	}
	if res2.TrustedBySystem {
		t.Error("系统池仍不该通过（我们只加了自备 CA，没动系统库）")
	}
}

// TestProbeChainDefaultsPort 不写端口时按 443 处理，且不误伤裸 IPv6。
func TestProbeChainDefaultsPort(t *testing.T) {
	c := New()
	res, err := c.ProbeChain(context.Background(), "127.0.0.1:1")
	// 端口 1 必然连不上：这里只验证错误信息里带上了我们拼出的地址，而非 panic。
	if err == nil {
		t.Logf("意外连上了 127.0.0.1:1（环境特殊），res=%+v", res)
	} else if !strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Errorf("连接失败信息应指明目标地址，got: %v", err)
	}
	if _, err := c.ProbeChain(context.Background(), "  "); err == nil {
		t.Error("空主机名应报错")
	}
}

// TestSplitHostPortDefault 覆盖主机名/带端口/IPv6 的归一化。
func TestSplitHostPortDefault(t *testing.T) {
	cases := []struct{ in, host, port string }{
		{"copilot.tencent.com", "copilot.tencent.com", "443"},
		{"copilot.tencent.com:8443", "copilot.tencent.com", "8443"},
		{"127.0.0.1:1", "127.0.0.1", "1"},
		{"[::1]:443", "::1", "443"},
		{"::1", "::1", "443"}, // 裸 IPv6：SplitHostPort 会失败，应按无端口处理
	}
	for _, c := range cases {
		h, p := splitHostPortDefault(c.in, "443")
		if h != c.host || p != c.port {
			t.Errorf("splitHostPortDefault(%q) = (%q, %q)，want (%q, %q)", c.in, h, p, c.host, c.port)
		}
	}
}

// TestApplyTLSCABadFile 路径无效时必须返回 error 且不改动现有配置
// （排障接口不能把服务留在「半生效」状态）。
func TestApplyTLSCABadFile(t *testing.T) {
	c := New()
	if _, err := c.ApplyTLSCA(filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Fatal("不存在的 CA 文件应报错")
	}
	if c.configuredRoots() != nil {
		t.Error("失败时不应留下自定义根池")
	}
}

// TestConfiguredVerifyErrSurfacesReason 配了 CA 但仍不通时，必须能说清
// 「配完之后为什么还是不行」——否则用户面对的只是一句含糊的「仍未通过」。
//
// 手法：写入一张与上游无关的自签 CA（等价于真实场景里「导错了证书」）。
// 注意不能用第二个 httptest server 的证书：Go 的 httptest 全局共用同一张内置
// 证书，两个 server 的证书其实完全相同，构不成「不匹配」。
func TestConfiguredVerifyErrSurfacesReason(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	c := New()
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, decoyCAPEM(t), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ApplyTLSCA(caPath); err != nil {
		t.Fatalf("ApplyTLSCA: %v", err)
	}

	res, err := c.ProbeChain(context.Background(), strings.TrimPrefix(srv.URL, "https://"))
	if err != nil {
		t.Fatalf("ProbeChain: %v", err)
	}
	if res.TrustedByConfigured {
		t.Fatal("配了无关的 CA 不该通过")
	}
	if !strings.Contains(res.ConfiguredVerifyErr, "certificate") {
		t.Errorf("应带出配置后的真实失败原因，got %q", res.ConfiguredVerifyErr)
	}
}

// decoyCAPEM 现场生成一张与 httptest 无关的自签 CA。
func decoyCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "decoy-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// TestProbeChainWithIntermediateCA 最贴近真实中间人的场景：由自建 CA 签发叶证书、
// 服务端发送**完整链**（叶 + CA）。验证两件事：
//   - 探测能把整条链都取回来（否则用户拿不到 CA，配了也白配）；
//   - SuggestedPEM 落盘后复验通过 —— 这正是面板上「信任并保存」的效果。
func TestProbeChainWithIntermediateCA(t *testing.T) {
	_, cert := makeCAAndLeaf(t)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	defer srv.Close()

	c := New()
	addr := strings.TrimPrefix(srv.URL, "https://")
	res, err := c.ProbeChain(context.Background(), addr)
	if err != nil {
		t.Fatalf("ProbeChain: %v", err)
	}
	if len(res.Chain) != 2 {
		t.Fatalf("应取回叶 + CA 两张证书，got %d：%+v", len(res.Chain), res.Chain)
	}
	if res.Chain[0].IsCA {
		t.Error("第 1 张应是叶证书（非 CA）")
	}
	if !res.Chain[1].IsCA {
		t.Error("第 2 张应是 CA")
	}
	if res.TrustedBySystem {
		t.Fatal("自建 CA 不该被系统池信任")
	}

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, []byte(res.SuggestedPEM), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ApplyTLSCA(caPath); err != nil {
		t.Fatalf("ApplyTLSCA: %v", err)
	}
	res2, err := c.ProbeChain(context.Background(), addr)
	if err != nil {
		t.Fatalf("ProbeChain(复验): %v", err)
	}
	if !res2.TrustedByConfigured {
		t.Fatalf("信任整条链后应通过，verifyErr=%q", res2.ConfiguredVerifyErr)
	}
}

// makeCAAndLeaf 生成一张自签 CA + 一张由它签发、带 SAN 的叶证书，并组装成
// tls.Certificate（Certificate 里含 CA，模拟代理发送完整链的行为）。
func makeCAAndLeaf(t *testing.T) (caPEM []byte, leaf tls.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(11),
		Subject:               pkix.Name{CommonName: "Fake MITM CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// 必须有 SAN：Go 1.15 起已不接受 CN 回退，无 SAN 的证书会被判域名不匹配，
	// 与「信任链」无关——这点很坑，测试里带 SAN 才是有效样本。
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(12),
		Subject:      pkix.Name{CommonName: "test-upstream"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caTmpl, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	return caPEM, tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}
}
