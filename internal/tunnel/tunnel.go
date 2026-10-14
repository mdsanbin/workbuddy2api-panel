// Package tunnel 按需拉起 Cloudflare Tunnel，把本机网关暴露到公网。
//
// 为什么做成「按需开启」：隧道**不改本机任何网络配置**——纯出站，cloudflared 主动
// 连 Cloudflare 边缘，不监听入站端口、不动路由表 / DNS / 防火墙。但面板一旦上了
// 公网，api_key 就是唯一防线，所以默认必须关着，由用户主动打开。
//
// 两种模式：
//
//	quick —— `cloudflared tunnel --url <target>`，Cloudflare 分配一个随机的
//	          xxx.trycloudflare.com 地址，**无需账号**。地址每次启动都变，适合
//	          临时用一次（我们从进程输出里把地址抓出来显示在面板上）。
//	token —— `cloudflared tunnel run --token <token>`，用在 Zero Trust 里建好的
//	          具名隧道，地址固定，适合长期使用。
package tunnel

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strings"
	"sync"
)

// quickURLRe 从 cloudflared 输出里抓 quick 模式分配的公网地址。
// 形如 https://random-words-here.trycloudflare.com
var quickURLRe = regexp.MustCompile(`https://[a-zA-Z0-9][a-zA-Z0-9-]*\.trycloudflare\.com`)

// logRingMax 面板上保留展示的输出行数（再多也没人看，白占内存）。
const logRingMax = 40

// Config 隧道运行参数（与 cmd/server 的 tunnel 配置段一一对应）。
type Config struct {
	Enabled bool   `json:"enabled"`
	Mode    string `json:"mode"`   // quick | token
	Token   string `json:"token"`  // token 模式必填
	Binary  string `json:"binary"` // 空 = 走 PATH 查找
	Target  string `json:"target"` // 隧道指向的本地地址，如 http://127.0.0.1:7863
}

// Status 面板读取的运行时快照。
type Status struct {
	Enabled   bool     `json:"enabled"`
	Running   bool     `json:"running"`
	Mode      string   `json:"mode"`
	Target    string   `json:"target"`
	URL       string   `json:"url"`
	Binary    string   `json:"binary"`
	Installed bool     `json:"installed"`
	Err       string   `json:"err"`
	Log       []string `json:"log"`
}

// Manager 隧道的生命周期管理。
//
// 并发约定：所有导出方法内部加锁；Start 里拉起的读日志 goroutine 通过
// appendLog 回写也用同一把锁。锁内不做阻塞操作（Kill 是非阻塞的），
// 避免面板轮询状态时被拖住。
type Manager struct {
	mu      sync.Mutex
	cfg     Config
	cmd     *exec.Cmd
	running bool
	url     string
	errMsg  string
	binary  string   // 解析到的 cloudflared 绝对路径（空 = 没找到）
	logs    []string // 环形缓冲，最近 logRingMax 行
}

// New 建一个未启动的 Manager。是否启动由 Apply 决定。
func New() *Manager {
	return &Manager{}
}

// Apply 应用一份新配置：必要时停掉旧进程再按新配置拉起来。
//
// 面板保存配置后调这里，所以「开关隧道」不需要重启网关。配置没变且运行状态
// 已经符合期望时直接返回，避免每次保存配置都把隧道重启一遍（quick 模式地址会变）。
func (m *Manager) Apply(cfg Config) error {
	m.mu.Lock()
	same := m.cfg == cfg
	already := m.running
	m.cfg = cfg
	m.mu.Unlock()

	if same && already == cfg.Enabled {
		return nil
	}
	m.Stop()
	if !cfg.Enabled {
		return nil
	}
	return m.Start()
}

// Start 拉起 cloudflared。重复调用是安全的（已在跑则先停）。
func (m *Manager) Start() error {
	m.mu.Lock()
	cfg := m.cfg
	if m.running {
		m.mu.Unlock()
		return nil // 已在运行
	}
	m.errMsg = ""
	m.url = ""
	m.mu.Unlock()

	if strings.TrimSpace(cfg.Target) == "" {
		return m.fail(errors.New("未确定隧道回源地址（tunnel.target 为空且无法从 listen 推导）"))
	}

	bin, err := resolveBinary(cfg.Binary)
	if err != nil {
		return m.fail(err)
	}

	args, err := buildArgs(cfg)
	if err != nil {
		return m.fail(err)
	}

	cmd := exec.Command(bin, args...)
	// 两路都收：quick 模式的地址历史上有过走 stdout 的版本，token 模式日志走 stderr。
	// 合到一个 pipe 里省一半 goroutine，也天然保序。
	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw

	m.mu.Lock()
	m.binary = bin
	m.mu.Unlock()

	if err := cmd.Start(); err != nil {
		_ = pw.Close()
		_ = pr.Close()
		return m.fail(fmt.Errorf("启动 cloudflared 失败：%w", err))
	}

	m.mu.Lock()
	m.cmd = cmd
	m.running = true
	m.mu.Unlock()

	go m.readLogs(pr)
	go func() {
		// Wait 必须有人调，否则进程退出后留下僵尸。pw 关掉后 readLogs 会自然收尾。
		err := cmd.Wait()
		_ = pw.Close()

		m.mu.Lock()
		// 只有仍是当前进程时才改状态——旧进程的退出回调不该覆盖新进程的状态。
		if m.cmd == cmd {
			m.running = false
			m.cmd = nil
			if err != nil && m.errMsg == "" {
				// 非主动 Stop（Stop 会先把 running 置 false）时，退出原因要留在面板上。
				m.errMsg = "cloudflared 已退出：" + err.Error()
			}
		}
		m.mu.Unlock()
	}()

	m.appendLog("已启动：" + bin + " " + strings.Join(args, " "))
	return nil
}

// Stop 终止隧道进程。未运行时是 no-op。
func (m *Manager) Stop() {
	m.mu.Lock()
	cmd := m.cmd
	m.running = false
	m.cmd = nil
	m.url = ""
	m.mu.Unlock()

	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
		m.appendLog("已停止隧道进程")
	}
}

// Status 返回当前快照，供面板轮询。
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	logs := make([]string, len(m.logs))
	copy(logs, m.logs)
	return Status{
		Enabled:   m.cfg.Enabled,
		Running:   m.running,
		Mode:      m.cfg.Mode,
		Target:    m.cfg.Target,
		URL:       m.url,
		Binary:    m.binary,
		Installed: m.binary != "" || findBinary(m.cfg.Binary) != "",
		Err:       m.errMsg,
		Log:       logs,
	}
}

// readLogs 逐行读 cloudflared 输出，抓 quick 模式的公网地址并留一份环形日志。
func (m *Manager) readLogs(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if u := quickURLRe.FindString(line); u != "" {
			m.mu.Lock()
			if m.url == "" {
				m.url = u
			}
			m.mu.Unlock()
		}
		m.appendLog(line)
	}
}

func (m *Manager) appendLog(line string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logs = append(m.logs, line)
	if len(m.logs) > logRingMax {
		m.logs = m.logs[len(m.logs)-logRingMax:]
	}
}

func (m *Manager) fail(err error) error {
	m.mu.Lock()
	m.errMsg = err.Error()
	m.running = false
	m.cmd = nil
	m.mu.Unlock()
	return err
}

// buildArgs 按模式拼 cloudflared 参数。
func buildArgs(cfg Config) ([]string, error) {
	switch cfg.Mode {
	case "token":
		if strings.TrimSpace(cfg.Token) == "" {
			return nil, errors.New("token 模式下必须填写 tunnel.token（Zero Trust 里建好的隧道凭据）")
		}
		// --no-autoupdate：模块 / 容器场景下不想让它自己拉新版本覆盖二进制。
		return []string{"tunnel", "--no-autoupdate", "run", "--token", cfg.Token}, nil
	case "quick", "":
		return []string{"tunnel", "--no-autoupdate", "--url", cfg.Target}, nil
	default:
		return nil, fmt.Errorf("未知的 tunnel.mode %q", cfg.Mode)
	}
}

// resolveBinary 解析 cloudflared 路径：显式配置优先，其次 PATH。
func resolveBinary(explicit string) (string, error) {
	if p := findBinary(explicit); p != "" {
		return p, nil
	}
	if strings.TrimSpace(explicit) != "" {
		return "", fmt.Errorf("找不到可执行文件 %q（请检查 tunnel.binary）", explicit)
	}
	return "", errors.New("未找到 cloudflared。请先安装它再打开这个开关" +
		"（Windows：winget install --id Cloudflare.cloudflared，或从 GitHub Release 下载 " +
		"cloudflared-windows-amd64.exe 改名为 cloudflared.exe 放进 PATH）")
}

func findBinary(explicit string) string {
	if strings.TrimSpace(explicit) != "" {
		if p, err := exec.LookPath(explicit); err == nil {
			return p
		}
		return ""
	}
	if p, err := exec.LookPath("cloudflared"); err == nil {
		return p
	}
	return ""
}
