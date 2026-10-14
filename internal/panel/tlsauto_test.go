// tlsauto_test.go 面板侧「自动修」的端到端验证：
// 请求撞上中间人证书错误 → 现场信任其链 → 原样重试成功。
//
// 这条链路是「用户不点诊断页也能通过」的依据——正是那句
//
//	auth state (upstream 0): Post "...": tls: failed to verify certificate: ...
//
// 应该被自愈掉的地方。
package panel

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

// tlsHealFixture 起自签上游并注册自动修上下文，返回上游 host:port 与 ca.pem 路径。
func tlsHealFixture(t *testing.T) (addr, caPath string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"code":0,"msg":"ok","data":{"state":"s","authUrl":"u"}}`))
	}))
	t.Cleanup(srv.Close)

	caPath = filepath.Join(t.TempDir(), "ca.pem")
	t.Cleanup(func() {
		tlsHeal.mu.Lock()
		tlsHeal.up, tlsHeal.caFile, tlsHeal.last = nil, "", nil
		tlsHeal.mu.Unlock()
		resetLoginTransport()
	})
	SetTLSAutoHeal(caPath, upstream.New())
	return strings.TrimPrefix(srv.URL, "https://"), caPath
}

// TestHealTLSForHost 首次修返回 true（信任池已变更）且 ca.pem 落盘；再修返回 false。
func TestHealTLSForHost(t *testing.T) {
	addr, caPath := tlsHealFixture(t)

	if !healTLSForHost(addr) {
		t.Fatal("首次自动修应返回 true（信任池已变更）")
	}
	raw, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("ca.pem 未写入: %v", err)
	}
	if !strings.Contains(string(raw), "BEGIN CERTIFICATE") {
		t.Errorf("ca.pem 内容应为 PEM，got %q", string(raw))
	}
	// 已信任后无改动；冷却同样指向 false —— 两条都要求不返回 true。
	if healTLSForHost(addr) {
		t.Error("已修好时不该再返回 true（会造成无意义重试）")
	}
}

// TestHealTLSForHostNoContext 未注册上下文时静默跳过：不 panic、不返回 true。
func TestHealTLSForHostNoContext(t *testing.T) {
	resetLoginTransport()
	tlsHeal.mu.Lock()
	tlsHeal.up, tlsHeal.caFile, tlsHeal.last = nil, "", nil
	tlsHeal.mu.Unlock()

	if healTLSForHost("copilot.tencent.com") {
		t.Error("未注册自动修上下文时不该声称修好了")
	}
}

// TestDoWithTLSHealRetry 端到端：自签上游 → 首次必然证书失败 → 自动修 → 重试 200。
func TestDoWithTLSHealRetry(t *testing.T) {
	addr, caPath := tlsHealFixture(t)

	// 先确认基线：不加信任池时确实失败（复现用户看到的现象）。
	if _, err := loginHTTP.Get("https://" + addr + "/v2/plugin/auth/state"); err == nil {
		t.Fatal("基线：未信任自签 CA 时不该成功（否则本用例失去意义）")
	}

	req, err := http.NewRequest(http.MethodGet, "https://"+addr+"/v2/plugin/auth/state", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := doWithTLSHeal(req)
	if err != nil {
		t.Fatalf("自动修后重试仍失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status=%d，want 200", resp.StatusCode)
	}
	if _, err := os.Stat(caPath); err != nil {
		t.Errorf("自动修应写出 ca.pem: %v", err)
	}
}

// TestIsCertErr 判定口径：证书类错误为真，网络类错误为假。
func TestIsCertErr(t *testing.T) {
	if isCertErr(nil) {
		t.Error("nil 不该判为证书错误")
	}
	if !isCertErr(tlsTestErr("tls: failed to verify certificate: x509: certificate signed by unknown authority")) {
		t.Error("unknown authority 应判为证书错误")
	}
	if isCertErr(tlsTestErr("dial tcp 127.0.0.1:1: connect: connection refused")) {
		t.Error("连接失败不该判为证书错误（否则会触发无谓的自动修）")
	}
}

type tlsTestErr string

func (e tlsTestErr) Error() string { return string(e) }
