// tls_test.go 验证「面板设备授权」这条具体链路能被 tls_ca_file 修好。
// 报错原文即出自本包：
//
//	auth state (upstream 0): Post "https://copilot.tencent.com/...":
//	tls: failed to verify certificate: x509: certificate signed by unknown authority
package panel

import (
	"bytes"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

// TestLoginClientTLSWiring 端到端：
//  1. 未注入 → doJSON 对自签 HTTPS 上游失败，且错误含 certificate（复现用户报错）；
//  2. 走 upstream.BuildTLSConfig + SetLoginClientTLS（与 main.go 同一路径）→ 成功。
//
// 注意：loginHTTP 是包级单例，本测试会替换其 Transport，结束时还原，避免污染同包其它测试。
func TestLoginClientTLSWiring(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"code":0,"msg":"ok","data":{"state":"s","authUrl":"u"}}`))
	}))
	defer srv.Close()

	origin := "https://www.codebuddy.cn"
	// loginHTTP 是包级单例，其出站配置（信任池 + ALPN 档）挂在 loginCfg 上，
	// 用 resetLoginTransport 还原，避免污染同包其它用例。
	t.Cleanup(resetLoginTransport)

	// 1) 注入前：默认 client 不信任自签证书 —— 正是用户遇到的报错。
	_, _, err := doJSON(http.MethodPost, srv.URL, "", bytes.NewReader([]byte("{}")), origin)
	if err == nil {
		t.Fatal("注入前对自签上游应握手失败")
	}
	if !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("期望证书类错误，got: %v", err)
	}

	// 2) 把服务端证书当 CA 注入（等价于用户填 tls_ca_file）→ 必须成功。
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	tc, err := upstream.BuildTLSConfig(caPath, false)
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	SetLoginClientTLS(tc)

	data, status, err := doJSON(http.MethodPost, srv.URL, "", bytes.NewReader([]byte("{}")), origin)
	if err != nil {
		t.Fatalf("注入自备 CA 后应成功，got: %v", err)
	}
	if status != http.StatusOK || !strings.Contains(string(data), "authUrl") {
		t.Fatalf("响应异常: status=%d data=%s", status, data)
	}
}

// TestTLSErrorHint 提示只在证书类错误上追加，其它错误保持原样。
func TestTLSErrorHint(t *testing.T) {
	cases := []struct {
		msg  string
		want bool
	}{
		{`Post "https://x": tls: failed to verify certificate: x509: certificate signed by unknown authority`, true},
		{`Post "https://www.workbuddy.ai/billing/meter/get-user-resource": net/http: HTTP/1.x transport connection broken: malformed HTTP response "\x00\x00\x12\x04"`, true},
		{"http_error: upstream 502", false},
		{"dial tcp: lookup copilot.tencent.com on [::1]:53: connection refused", false},
	}
	for _, c := range cases {
		got := tlsErrorHint(errString(c.msg))
		if (got != "") != c.want {
			t.Errorf("msg=%q got=%q want hint=%v", c.msg, got, c.want)
		}
	}
	if tlsErrorHint(nil) != "" {
		t.Error("nil 错误不应有提示")
	}
}

type errString string

func (e errString) Error() string { return string(e) }
