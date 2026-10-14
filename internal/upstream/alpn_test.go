package upstream

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// newALPNTestServer 起一个**同时支持 h2 与 http/1.1**（按 ALPN 协商）的自签 TLS 服务。
// 这样「客户端广告什么协议」会直接决定服务端用哪套线格式回答 —— 正是复现
// malformed HTTP response 所需的最小环境。
func newALPNTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Server-Proto", r.Proto)
		_, _ = w.Write([]byte("ok"))
	}))
	srv.TLS = &tls.Config{NextProtos: []string{"h2", "http/1.1"}}
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// transportFor 按 mode 造一个信任测试服务的出站 transport（复用生产 newTransport 默认）。
func transportFor(t *testing.T, srv *httptest.Server, mode ALPNMode) *http.Transport {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	tr := newTransport()
	tr.TLSClientConfig = &tls.Config{RootCAs: pool}
	if !ApplyOutboundALPN(tr, mode) {
		t.Fatalf("ApplyOutboundALPN(%q) 应成功", mode)
	}
	return tr
}

func protoOf(t *testing.T, srv *httptest.Server, tr http.RoundTripper) string {
	t.Helper()
	cl := &http.Client{Transport: tr}
	resp, err := cl.Get(srv.URL)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()
	return resp.Header.Get("X-Server-Proto")
}

// TestNewTransportALPNConsistent 生产默认 transport 必须「广告」与「认知」同调：
// TLS 侧只广告 http/1.1，HTTP 侧置空 map（不认识任何 next-proto），且不得自动启用 h2。
func TestNewTransportALPNConsistent(t *testing.T) {
	tr := newTransport()
	if tr.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig 不得为 nil：ALPN 必须显式声明，不能依赖隐式行为")
	}
	if got := tr.TLSClientConfig.NextProtos; !reflect.DeepEqual(got, []string{"http/1.1"}) {
		t.Errorf("默认 ALPN 应只含 http/1.1，got %v", got)
	}
	if tr.TLSNextProto == nil || len(tr.TLSNextProto) != 0 {
		t.Errorf("默认应置空（非 nil）TLSNextProto 以禁 h2，got %v", tr.TLSNextProto)
	}
	if tr.ForceAttemptHTTP2 {
		t.Error("默认不得开启 ForceAttemptHTTP2")
	}
}

// TestDefaultModeTalksHTTP1 默认档在双协议服务上必须走 HTTP/1.1（不广告 h2）。
func TestDefaultModeTalksHTTP1(t *testing.T) {
	srv := newALPNTestServer(t)
	if got := protoOf(t, srv, transportFor(t, srv, ALPNHTTP1)); got != "HTTP/1.1" {
		t.Fatalf("ALPNHTTP1 档应协商到 HTTP/1.1，got %q", got)
	}
}

// TestH2ModeTalksHTTP2 逃生门档必须真的讲 h2（而不是只敢在 ALPN 里写 h2）。
func TestH2ModeTalksHTTP2(t *testing.T) {
	srv := newALPNTestServer(t)
	if got := protoOf(t, srv, transportFor(t, srv, ALPNH2)); got != "HTTP/2.0" {
		t.Fatalf("ALPNH2 档应协商到 HTTP/2.0，got %q", got)
	}
}

// TestALPNMismatchIsFatal 反例固化（本测试就是「国际版查询失败」的机制说明）：
// 只要 TLS 层广告 h2、HTTP 层却不认识 h2，对 h2 服务就必然拿到
// `malformed HTTP response "\x00\x00\x12\x04..."`。
//
// 本测试把这对开关拆开设置一遍，断言它确实炸 —— 从而锁死「两者必须由
// ApplyOutboundALPN 成对设置」这条不变量，防止将来有人只改一边。
func TestALPNMismatchIsFatal(t *testing.T) {
	srv := newALPNTestServer(t)

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	footgun := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			NextProtos: []string{"h2", "http/1.1"}, // 广告 h2
		},
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}, // 却不认识 h2
	}

	cl := &http.Client{Transport: footgun}
	resp, err := cl.Get(srv.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("协议错配的组合竟然成功了 —— 说明不变量已被破坏，反例不再成立")
	}
	if !strings.Contains(err.Error(), "malformed HTTP response") {
		t.Fatalf("期望 malformed HTTP response（HTTP/2 帧被 HTTP/1.x 读），got: %v", err)
	}
}

// TestApplyOutboundALPNStaysConsistent 切换档位后两处开关必须始终成对。
func TestApplyOutboundALPNStaysConsistent(t *testing.T) {
	tr := newTransport()

	if !ApplyOutboundALPN(tr, ALPNH2) {
		t.Fatal("未使用的 transport 应能切到 h2")
	}
	if _, ok := tr.TLSNextProto["h2"]; !ok {
		t.Errorf("h2 档应让标准库把 h2 真正注册进 TLSNextProto，got %v", tr.TLSNextProto)
	}
	if !tr.ForceAttemptHTTP2 {
		t.Error("h2 档必须开启 ForceAttemptHTTP2")
	}
	if !reflect.DeepEqual(tr.TLSClientConfig.NextProtos, []string{"h2", "http/1.1"}) {
		t.Errorf("h2 档 ALPN 应为 [h2 http/1.1]，got %v", tr.TLSClientConfig.NextProtos)
	}

	if !ApplyOutboundALPN(tr, ALPNHTTP1) {
		t.Fatal("应能切回 http/1.1")
	}
	if tr.TLSNextProto == nil || len(tr.TLSNextProto) != 0 {
		t.Error("切回后应恢复空（非 nil）TLSNextProto")
	}
	if !reflect.DeepEqual(tr.TLSClientConfig.NextProtos, []string{"http/1.1"}) {
		t.Errorf("切回后 ALPN 应只含 http/1.1，got %v", tr.TLSClientConfig.NextProtos)
	}
}

// TestApplyOutboundALPNRefusesLateH2Switch 已错过切换窗口的 transport 不能再切 h2。
//
// 场景：这个 Transport 已经按 http/1.1 档用过（onceSetNextProtoDefaults 已在
// TLSNextProto=空 map 的状态下跑完，标准库不会再注册 h2）。此时若照旧把 ALPN 改成
// 含 h2，就会亲手造出「广告 h2 却不讲 h2」——必须拒绝，并回到 http/1.1 自洽态。
//
// 注：CloseIdleConnections 内部会 Do 一次那次一次性初始化（net/http transport.go:784），
// 这里正是用它来把 transport 推进到「已初始化」状态。
func TestApplyOutboundALPNRefusesLateH2Switch(t *testing.T) {
	tr := newTransport()
	tr.CloseIdleConnections() // 烧掉一次性初始化（此时 TLSNextProto 非 nil → 不注册 h2）

	if ApplyOutboundALPN(tr, ALPNH2) {
		t.Fatal("已初始化过的 transport 应拒绝切 h2，而不是只改一半")
	}
	if !reflect.DeepEqual(tr.TLSClientConfig.NextProtos, []string{"http/1.1"}) {
		t.Fatalf("拒绝后必须回到 http/1.1 自洽态，got %v", tr.TLSClientConfig.NextProtos)
	}
	if tr.TLSNextProto == nil || len(tr.TLSNextProto) != 0 {
		t.Errorf("拒绝后 HTTP 侧也应回到空（非 nil）映射，got %v", tr.TLSNextProto)
	}
}

// TestSetALPNMode 走 Client 入口，HTTP 与 ChatHTTP 共用的 transport 都要被覆盖。
func TestSetALPNMode(t *testing.T) {
	c := New()
	if !c.SetALPNMode(ALPNH2) {
		t.Fatal("新 client 应能切到 h2")
	}
	tr, ok := c.HTTP.Transport.(*http.Transport)
	if !ok {
		t.Fatal("HTTP.Transport 应为 *http.Transport")
	}
	if !reflect.DeepEqual(tr.TLSClientConfig.NextProtos, []string{"h2", "http/1.1"}) {
		t.Fatalf("ALPN 未切换: %v", tr.TLSClientConfig.NextProtos)
	}
	if c.ChatHTTP.Transport != c.HTTP.Transport {
		t.Error("HTTP 与 ChatHTTP 应共用同一个 transport")
	}
	// 非法值一律回落默认档（安全侧）。
	c2 := New()
	if !c2.SetALPNMode(ALPNMode("garbage")) {
		t.Fatal("回落默认档应成功")
	}
	if got := c2.alpn; got != ALPNHTTP1 {
		t.Errorf("非法档位应回落 ALPNHTTP1，got %q", got)
	}
}

// TestSetTLSConfigPinsALPNWithoutMutatingCaller SetTLSConfig 必须把外部提供的
// *tls.Config 规范化成「同调 ALPN」，但**不得**原地改动调用方那份（main 会把它
// 同时交给 DefaultTransport，原地改会互相污染）。
func TestSetTLSConfigPinsALPNWithoutMutatingCaller(t *testing.T) {
	c := New()
	shared := &tls.Config{InsecureSkipVerify: true}
	c.SetTLSConfig(shared)

	tr := c.HTTP.Transport.(*http.Transport)
	if !reflect.DeepEqual(tr.TLSClientConfig.NextProtos, []string{"http/1.1"}) {
		t.Errorf("装到 transport 上的配置应钉住 ALPN=http/1.1，got %v", tr.TLSClientConfig.NextProtos)
	}
	if len(shared.NextProtos) != 0 {
		t.Errorf("不得原地修改调用方的 tls.Config，got NextProtos=%v", shared.NextProtos)
	}
	if tr.TLSClientConfig == shared {
		t.Error("应装副本而不是同一指针")
	}
}

// TestParseALPNMode 配置字面解析：只有明确的 h2 别名才走 h2，其余一律默认档。
func TestParseALPNMode(t *testing.T) {
	cases := map[string]ALPNMode{
		"":         ALPNHTTP1,
		"   ":      ALPNHTTP1,
		"http/1.1": ALPNHTTP1,
		"HTTP/1.1": ALPNHTTP1,
		"h2":       ALPNH2,
		"H2":       ALPNH2,
		" h2 ":     ALPNH2,
		"http2":    ALPNH2,
		"http/2":   ALPNH2,
		"h3":       ALPNHTTP1,
		"nonsense": ALPNHTTP1,
	}
	for in, want := range cases {
		if got := ParseALPNMode(in); got != want {
			t.Errorf("ParseALPNMode(%q) = %q, want %q", in, got, want)
		}
	}
}
