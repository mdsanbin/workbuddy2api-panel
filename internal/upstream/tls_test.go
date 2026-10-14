// tls_test.go 出站 TLS 信任配置的端到端验证：用真实自签 HTTPS 服务复现
// 「certificate signed by unknown authority」，再验证配置 CA 后恢复正常。
package upstream

import (
	"crypto/tls"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBuildTLSConfigDisabled 两者都不配 → (nil, nil)：调用方据此保持默认客户端，
// 保证改动对现有部署零影响。
func TestBuildTLSConfigDisabled(t *testing.T) {
	tc, err := BuildTLSConfig("", false)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if tc != nil {
		t.Fatalf("未配置时应返回 nil（保持默认客户端），got %+v", tc)
	}
}

// TestBuildTLSConfigReadError 路径不存在必须 fail fast，而不是等到首个请求才暴露。
func TestBuildTLSConfigReadError(t *testing.T) {
	if _, err := BuildTLSConfig(filepath.Join(t.TempDir(), "nope.pem"), false); err == nil {
		t.Fatal("不存在的 ca 文件应报错")
	}
}

// TestBuildTLSConfigGarbage 文件存在但不是 PEM → 报错，防止静默得到空信任池
// （那种情况下所有请求都会失败，但错误信息会指向别处）。
func TestBuildTLSConfigGarbage(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(p, []byte("not a pem at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildTLSConfig(p, false); err == nil {
		t.Fatal("非 PEM 内容应报错")
	}
}

// TestBuildTLSConfigSelfSignedChain 端到端复现与修复：
//  1. 起自签证书的 HTTPS 服务；
//  2. 不配 CA 时请求必须失败且错误含 certificate（= 用户看到的报错）；
//  3. 把该证书当 tls_ca_file 后请求必须成功。
func TestBuildTLSConfigSelfSignedChain(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"code":0,"msg":"ok","data":{"state":"s","authUrl":"u"}}`))
	}))
	defer srv.Close()

	// 导出服务端证书为 PEM——等价于用户从代理/抓包工具里导出的自签 CA。
	leaf := srv.Certificate()
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	// 显式关掉 Proxy，避免本机 HTTP_PROXY 环境变量把请求绕出去。
	get := func(tc *tls.Config) error {
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: tc}}
		resp, err := c.Get(srv.URL)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		return nil
	}

	// 1) 基线 = 改动前的行为：无 TLSClientConfig → 自签证书不受信任。
	err := get(nil)
	if err == nil {
		t.Fatal("未配 CA 时对自签服务应握手失败（这正是用户报的错）")
	}
	if !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("期望证书类错误，got: %v", err)
	}

	// 2) 配上 ca_file → 必须成功。
	tc, err := BuildTLSConfig(caPath, false)
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	if err := get(tc); err != nil {
		t.Fatalf("配了 tls_ca_file 后应成功，got: %v", err)
	}

	// 3) insecure 也必须成功（最后手段同样可用）。
	tcInsecure, err := BuildTLSConfig("", true)
	if err != nil {
		t.Fatalf("BuildTLSConfig(insecure): %v", err)
	}
	if err := get(tcInsecure); err != nil {
		t.Fatalf("insecure 模式下应成功，got: %v", err)
	}
}
