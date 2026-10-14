// tlsdiag_test.go 面板 TLS 诊断页的服务端行为：
//
//	GET  /panel/api/tls/probe → 探到链、判明系统池不信任
//	POST /panel/api/tls/trust → 落盘 ca.pem、热加载、复验通过
//
// 与 /panel/tls 页面上的两次点击一一对应。
package panel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

// tlsDiagFixture 起自签上游 + 一个指向临时目录的 Panel。
func tlsDiagFixture(t *testing.T) (*Panel, string, string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)

	addr := strings.TrimPrefix(srv.URL, "https://")
	dir := t.TempDir()

	// loginTransport 是包级单例，trust 会把自签 CA 热加载进它 —— 用例结束
	// 必须还原，否则会污染同包其它用例（尤其是「基线应当失败」的那些断言）。
	t.Cleanup(resetLoginTransport)

	p := New(Config{
		Upstream:   upstream.New(),
		ConfigPath: filepath.Join(dir, "config.json"), // 文件无需存在：只用来推导 ca.pem 目录
	})
	return p, addr, dir
}

func doJSONReq(t *testing.T, p *Panel, method, target string, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var rdr *strings.Reader
	if body == "" {
		rdr = strings.NewReader("")
	} else {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, rdr)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("响应不是 JSON（status=%d）: %s", rec.Code, rec.Body.String())
	}
	return rec, out
}

// TestTLSDiagProbeEndpoint 探测接口要把「系统池不信任」这个事实带出来。
func TestTLSDiagProbeEndpoint(t *testing.T) {
	p, addr, dir := tlsDiagFixture(t)

	rec, out := doJSONReq(t, p, http.MethodGet, "/panel/api/tls/probe?host="+url.QueryEscape(addr), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if out["ok"] != true {
		t.Fatalf("ok 应为 true，got %v", out)
	}
	if got := out["ca_path"]; got != filepath.Join(dir, "ca.pem") {
		t.Errorf("ca_path = %v，want %v", got, filepath.Join(dir, "ca.pem"))
	}

	probe, _ := out["probe"].(map[string]any)
	if probe == nil {
		t.Fatalf("缺少 probe 字段: %v", out)
	}
	if probe["trusted_by_system"] != false {
		t.Errorf("自签上游 trusted_by_system 应为 false，got %v", probe["trusted_by_system"])
	}
	if ve, _ := probe["verify_err"].(string); !strings.Contains(ve, "certificate") {
		t.Errorf("verify_err 应含 certificate，got %q", ve)
	}
	chain, _ := probe["chain"].([]any)
	if len(chain) == 0 {
		t.Errorf("chain 不应为空: %v", probe)
	}
	if sp, _ := probe["suggested_pem"].(string); !strings.Contains(sp, "BEGIN CERTIFICATE") {
		t.Errorf("suggested_pem 应为 PEM 文本，got %q", sp)
	}
}

// TestTLSDiagTrustEndpoint 一键信任：写文件 + 热加载 + 复验通过。
func TestTLSDiagTrustEndpoint(t *testing.T) {
	p, addr, dir := tlsDiagFixture(t)

	rec, out := doJSONReq(t, p, http.MethodPost, "/panel/api/tls/trust",
		`{"host":`+jsonStr(addr)+`}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if out["verified"] != true {
		t.Fatalf("信任后复验应为 true，got %v（note=%v）", out["verified"], out["note"])
	}
	if out["hot_applied"] != true {
		t.Errorf("应热加载生效，got %v", out["hot_applied"])
	}

	raw, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		t.Fatalf("ca.pem 未写入: %v", err)
	}
	if !strings.Contains(string(raw), "BEGIN CERTIFICATE") {
		t.Errorf("ca.pem 内容应为 PEM，got %q", string(raw))
	}
}

// TestTLSDiagTrustRejectsBadHost 非法主机名必须在写盘前被拒（这是一个会外连的接口）。
func TestTLSDiagTrustRejectsBadHost(t *testing.T) {
	p, _, dir := tlsDiagFixture(t)

	rec, _ := doJSONReq(t, p, http.MethodPost, "/panel/api/tls/trust",
		`{"host":"http://evil.example/x"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("非法主机应 400，got %d body=%s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "ca.pem")); err == nil {
		t.Error("被拒绝的请求不应写出 ca.pem")
	}
}

// TestTLSDiagPagesServed 两个静态资源可匿名加载（页面本身无秘密，数据接口才鉴权）。
func TestTLSDiagPagesServed(t *testing.T) {
	p, _, _ := tlsDiagFixture(t)
	cases := []struct{ path, ctype, want string }{
		{"/panel/tls", "text/html", "TLS 证书诊断"},
		{"/panel/tls.js", "text/javascript", "tls/trust"},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, c.path, strings.NewReader(""))
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status=%d", c.path, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, c.ctype) {
			t.Errorf("%s Content-Type=%q，want 含 %q", c.path, ct, c.ctype)
		}
		if !strings.Contains(rec.Body.String(), c.want) {
			t.Errorf("%s 内容未包含 %q", c.path, c.want)
		}
	}
}

// jsonStr 把字符串安全地嵌进测试用 JSON 字面量。
func jsonStr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
