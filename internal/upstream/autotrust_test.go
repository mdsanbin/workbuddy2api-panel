// autotrust_test.go 「自动修」的单元与端到端验证：
//
//	探测到系统池不信任 → 合并写 ca.pem → 热应用 → 复验通过
//
// 并覆盖幂等（已修好不再写盘）与「连不上 ≠ 错误」这两个易错点。
package upstream

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMergePEMToFileAppendDedupe 合并写盘：新增才计、重复不计、内容不重复。
func TestMergePEMToFileAppendDedupe(t *testing.T) {
	_, cert := makeCAAndLeaf(t)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[1]})

	caPath := filepath.Join(t.TempDir(), "ca.pem")

	added, err := MergePEMToFile(caPath, string(caPEM))
	if err != nil {
		t.Fatalf("MergePEMToFile: %v", err)
	}
	if added != 1 {
		t.Fatalf("首次写入应新增 1 张，got %d", added)
	}

	// 幂等：同一张再写不该计入，也不该重复出现在文件里。
	added, err = MergePEMToFile(caPath, string(caPEM))
	if err != nil {
		t.Fatal(err)
	}
	if added != 0 {
		t.Fatalf("重复证书不该新增，got %d", added)
	}
	raw, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(raw), "BEGIN CERTIFICATE"); n != 1 {
		t.Fatalf("文件应只含 1 张证书，got %d", n)
	}
}

// TestMergePEMToFileNoValidCerts 无有效证书时不写盘、空路径报错。
func TestMergePEMToFileNoValidCerts(t *testing.T) {
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	added, err := MergePEMToFile(caPath, "", "not a pem at all")
	if err != nil {
		t.Fatalf("不该返回 error: %v", err)
	}
	if added != 0 {
		t.Fatalf("无有效证书不该新增，got %d", added)
	}
	if _, err := os.Stat(caPath); err == nil {
		t.Error("无有效证书时不该创建文件")
	}
	if _, err := MergePEMToFile("", "x"); err == nil {
		t.Error("空路径应报错")
	}
}

// TestEnsureTrustedSelfSigned 主链路：自签上游（= 被中间人替换证书）→ 自动信任并复验通过。
func TestEnsureTrustedSelfSigned(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	c := New()
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	addr := strings.TrimPrefix(srv.URL, "https://")

	out, tc, err := EnsureTrusted(context.Background(), c, addr, caPath)
	if err != nil {
		t.Fatalf("EnsureTrusted: %v", err)
	}
	if out.Status != TrustStatusTrusted {
		t.Fatalf("status=%s detail=%s", out.Status, out.Detail)
	}
	if !out.Verified {
		t.Error("Verified 应为 true")
	}
	if out.CertsAdded != 1 {
		t.Errorf("应新增 1 张证书，got %d", out.CertsAdded)
	}
	if tc == nil {
		t.Error("修好后应返回新生效的 TLS 配置（调用方据此同步 login client）")
	}
	if _, err := os.Stat(caPath); err != nil {
		t.Fatalf("ca.pem 未写入: %v", err)
	}

	// 幂等：第二次应判定「已由现有 ca.pem 信任」，且不再返回新配置。
	out2, tc2, err := EnsureTrusted(context.Background(), c, addr, caPath)
	if err != nil {
		t.Fatal(err)
	}
	if out2.Status != TrustStatusConfigured {
		t.Errorf("第二次 status 应为 %s，got %s", TrustStatusConfigured, out2.Status)
	}
	if tc2 != nil {
		t.Error("无需改动时不该返回 TLS 配置")
	}
}

// TestEnsureTrustedUnreachable 连不上属于「可重试」而非错误 —— 设备上代理晚就绪很常见，
// 调用方要能区分「环境没就绪」与「操作失败」。
func TestEnsureTrustedUnreachable(t *testing.T) {
	c := New()
	out, tc, err := EnsureTrusted(context.Background(), c, "127.0.0.1:1", filepath.Join(t.TempDir(), "ca.pem"))
	if err != nil {
		t.Fatalf("连不上不该返回 error，got %v", err)
	}
	if out.Status != TrustStatusUnreachable {
		t.Fatalf("status=%s", out.Status)
	}
	if tc != nil {
		t.Error("连接失败不该返回 TLS 配置")
	}
	if out.Detail == "" {
		t.Error("应带出失败原因")
	}
}

// TestEnsureTrustedNilClient 未初始化 client 不该 panic。
func TestEnsureTrustedNilClient(t *testing.T) {
	out, tc, err := EnsureTrusted(context.Background(), nil, "h", "f")
	if err != nil {
		t.Fatalf("不该返回 error: %v", err)
	}
	if out.Status != TrustStatusSkipped || tc != nil {
		t.Errorf("got %+v tc=%v", out, tc)
	}
}
