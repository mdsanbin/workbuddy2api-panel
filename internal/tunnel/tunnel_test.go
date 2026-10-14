package tunnel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestMain 让**测试二进制兼任 mock cloudflared**：环境变量 MOCK_CF=1 时扮演
// quick 模式——往 stderr 打几行日志（含一行 trycloudflare 地址）后长驻，等父
// 进程来杀。
//
// 为什么不另编一个 mock 可执行文件：本机沙箱会拦截 agent 侧新建的独立 exe，
// 而 `go test -c` 产出的测试二进制可以正常执行，兼任是既可靠又不污染仓库的做法。
func TestMain(m *testing.M) {
	if os.Getenv("MOCK_CF") == "1" {
		os.Stderr.WriteString("2026-10-12T18:00:00Z INF Requesting new quick Tunnel on trycloudflare.com...\n")
		os.Stderr.WriteString("2026-10-12T18:00:01Z INF |  https://mock-probe-abc.trycloudflare.com  |\n")
		os.Stderr.WriteString("2026-10-12T18:00:01Z INF Registered tunnel connection connIndex=0\n")
		time.Sleep(2 * time.Minute)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func selfBin(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("取自身可执行路径失败: %v", err)
	}
	abs, err := filepath.Abs(exe)
	if err != nil {
		t.Fatalf("转绝对路径失败: %v", err)
	}
	return abs
}

func waitURL(t *testing.T, m *Manager, d time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if u := m.Status().URL; u != "" {
			return u
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("超时未抓到公网地址；最后状态=%+v", m.Status())
	return ""
}

// TestQuickModeCapturesURL 是这块功能的核心断言：能从子进程输出里把
// trycloudflare 地址抓出来——面板就靠它显示「公网地址」。
func TestQuickModeCapturesURL(t *testing.T) {
	t.Setenv("MOCK_CF", "1")

	m := New()
	if err := m.Apply(Config{
		Enabled: true, Mode: "quick",
		Binary: selfBin(t), Target: "http://127.0.0.1:9",
	}); err != nil {
		t.Fatalf("Apply 失败: %v", err)
	}
	defer m.Stop()

	if got := waitURL(t, m, 5*time.Second); got != "https://mock-probe-abc.trycloudflare.com" {
		t.Fatalf("抓到的地址不对: %q", got)
	}
	st := m.Status()
	if !st.Running {
		t.Error("状态应为运行中")
	}
	if st.Binary == "" {
		t.Error("应记录解析到的二进制路径")
	}
	if st.Err != "" {
		t.Errorf("不该有错误: %s", st.Err)
	}
}

// TestStopClearsState 确认 Stop 之后运行态与地址都被清掉——否则面板会一直
// 显示一个已经失效的公网地址，用户点进去打不开还不知道为什么。
func TestStopClearsState(t *testing.T) {
	t.Setenv("MOCK_CF", "1")

	m := New()
	if err := m.Apply(Config{
		Enabled: true, Mode: "quick",
		Binary: selfBin(t), Target: "http://127.0.0.1:9",
	}); err != nil {
		t.Fatalf("Apply 失败: %v", err)
	}
	waitURL(t, m, 5*time.Second)

	m.Stop()
	time.Sleep(150 * time.Millisecond)
	if st := m.Status(); st.Running || st.URL != "" {
		t.Fatalf("Stop 后应清空运行态，实际: %+v", st)
	}
}

// TestApplyIsIdempotent 同样的配置重复 Apply 不该重启进程（quick 模式地址会变，
// 面板每次保存配置都重启隧道是没法用的）。
func TestApplyIsIdempotent(t *testing.T) {
	t.Setenv("MOCK_CF", "1")

	cfg := Config{Enabled: true, Mode: "quick", Binary: selfBin(t), Target: "http://127.0.0.1:9"}
	m := New()
	if err := m.Apply(cfg); err != nil {
		t.Fatalf("首次 Apply 失败: %v", err)
	}
	defer m.Stop()
	first := waitURL(t, m, 5*time.Second)

	if err := m.Apply(cfg); err != nil {
		t.Fatalf("二次 Apply 失败: %v", err)
	}
	// 若被重启，URL 会先被清空再重新抓到；这里立刻查应该原样保留。
	if got := m.Status().URL; got != first {
		t.Fatalf("配置未变却被重启：地址从 %q 变成 %q", first, got)
	}
}

// TestDisabledDoesNotStart 默认关着（按需开启）的核心语义：Enabled=false 时
// 不该拉起任何进程。
func TestDisabledDoesNotStart(t *testing.T) {
	t.Setenv("MOCK_CF", "1")

	m := New()
	if err := m.Apply(Config{Enabled: false, Mode: "quick", Binary: selfBin(t), Target: "http://127.0.0.1:9"}); err != nil {
		t.Fatalf("Apply 失败: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	st := m.Status()
	if st.Running || st.URL != "" {
		t.Fatalf("Enabled=false 时不该启动: %+v", st)
	}
}

func TestBuildArgs(t *testing.T) {
	args, err := buildArgs(Config{Mode: "quick", Target: "http://127.0.0.1:7863"})
	if err != nil {
		t.Fatalf("quick: %v", err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--url http://127.0.0.1:7863") {
		t.Errorf("quick 模式参数不对: %v", args)
	}

	args, err = buildArgs(Config{Mode: "token", Token: "tok-xyz"})
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	joined = strings.Join(args, " ")
	if !strings.Contains(joined, "run --token tok-xyz") {
		t.Errorf("token 模式参数不对: %v", args)
	}

	// token 模式缺 token 必须在启动前就拦住，别让 cloudflared 起一个必然失败的进程。
	if _, err := buildArgs(Config{Mode: "token"}); err == nil {
		t.Error("token 模式缺 token 时应报错")
	}
	// 未知模式同样拦下。
	if _, err := buildArgs(Config{Mode: "nonsense"}); err == nil {
		t.Error("未知 mode 应报错")
	}
}

// TestMissingBinaryErrorIsActionable 没装 cloudflared 是本机最可能的首次使用
// 状态，报错必须指向怎么解决，而不是一句「exec: not found」。
func TestMissingBinaryErrorIsActionable(t *testing.T) {
	if _, err := resolveBinary(""); err == nil {
		t.Skip("本机 PATH 里已有 cloudflared，跳过这条")
	} else if !strings.Contains(err.Error(), "cloudflared") {
		t.Errorf("错误信息应提到 cloudflared: %v", err)
	}

	// 显式配了路径但文件不存在时，要点名是 tunnel.binary 配错了。
	if _, err := resolveBinary("definitely-not-a-real-binary-xyz"); err == nil {
		t.Error("显式路径不存在时应报错")
	} else if !strings.Contains(err.Error(), "tunnel.binary") {
		t.Errorf("错误信息应指向 tunnel.binary: %v", err)
	}
}

// TestTargetRequired 没有回源地址就没法建隧道，必须明确报错而不是静默不动。
func TestTargetRequired(t *testing.T) {
	m := New()
	if err := m.Apply(Config{Enabled: true, Mode: "quick", Target: ""}); err == nil {
		t.Fatal("Target 为空时应报错")
	}
}
