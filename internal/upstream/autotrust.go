// autotrust.go 出站 TLS 的「自动修」：把中间人代理从「需要人工导出 CA」
// 变成「启动即自愈」。
//
// 与同包另两个文件的分工：
//   - probe.go 只读探测（对端到底出示了什么链）；
//   - tls.go   按配置建信任池（用户手工指定 tls_ca_file / ca.pem）；
//   - 本文件   把探测结果真正落到信任池：合并 PEM → 写盘 → 热应用 → 复验。
//
// 安全性：这是 Trust-On-First-Use —— 它会信任「第一次握手见到的证书」。
// 若此刻恰好存在攻击者，等于把凭证交给对方。因此调用方必须显式开启
// （config.tls_auto_trust），且默认清单只含本服务本来就要访问的腾讯域名。
package upstream

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// TrustStatus 单主机「确保信任」的结论。
type TrustStatus string

const (
	// TrustStatusSystem 系统根池已验证通过 —— 无中间人，无需任何动作。
	TrustStatusSystem TrustStatus = "system"
	// TrustStatusConfigured 当前生效的信任池已通过 —— 之前已修好，无需动作。
	TrustStatusConfigured TrustStatus = "configured"
	// TrustStatusTrusted 本轮写入了 CA 且复验通过。
	TrustStatusTrusted TrustStatus = "trusted"
	// TrustStatusUnverified 已写入 CA，但复验仍未通过（证书缺 SAN / 域名不匹配 / CA 配错）。
	// 重试无意义，属于「证书本身的问题」，与「环境未就绪」区分开。
	TrustStatusUnverified TrustStatus = "unverified"
	// TrustStatusUnreachable 连 TCP 或握手都没成（网络未就绪 / DNS 失败）——值得稍后重试。
	TrustStatusUnreachable TrustStatus = "unreachable"
	// TrustStatusSkipped 探测到了但没取到证书、或写盘/热加载失败 —— 未做改动。
	TrustStatusSkipped TrustStatus = "skipped"
)

// TrustOutcome 一次「确保信任」的结果，供调用方记日志/回报。
type TrustOutcome struct {
	Host       string      `json:"host"`
	Status     TrustStatus `json:"status"`
	CertsAdded int         `json:"certs_added"` // 本次真正新写入的证书张数
	Verified   bool        `json:"verified"`    // 末次复验是否通过
	Detail     string      `json:"detail,omitempty"`
}

// EnsureTrusted 确保出站信任池能验证 host：探测对端实际出示的链，必要时把整条链
// 合并进 caFile 并热应用到出站 Transport，最后复验一次。
//
// 返回值：
//   - TrustOutcome 结论（永不依赖 error 判空即可安全记日志）；
//   - *tls.Config  本次新生效的 TLS 配置；nil 表示**未做任何改动**（调用方据此
//     跳过同步 login client / DefaultTransport）；
//   - error        仅表示「写盘或热加载失败」这类需要用户知道的操作性错误；
//     「连不上」「系统池已信任」都走 Status 表达，不算 error。
//
// 幂等：已修好（TrustStatusConfigured）时不会重复写盘。
func EnsureTrusted(ctx context.Context, c *Client, host, caFile string) (TrustOutcome, *tls.Config, error) {
	out := TrustOutcome{Host: host}
	if c == nil {
		out.Status = TrustStatusSkipped
		out.Detail = "upstream client 未初始化"
		return out, nil, nil
	}
	probe, err := c.ProbeChain(ctx, host)
	if err != nil {
		// 连不上不是致命错误：设备上的代理/网络可能还没就绪，交给调用方决定是否重试。
		out.Status = TrustStatusUnreachable
		out.Detail = err.Error()
		return out, nil, nil
	}
	if probe.TrustedBySystem {
		out.Status = TrustStatusSystem
		out.Verified = true
		return out, nil, nil
	}
	if probe.TrustedByConfigured {
		out.Status = TrustStatusConfigured
		out.Verified = true
		return out, nil, nil
	}
	if strings.TrimSpace(probe.SuggestedPEM) == "" {
		out.Status = TrustStatusSkipped
		out.Detail = "探测未取到任何证书"
		return out, nil, nil
	}

	added, err := MergePEMToFile(caFile, probe.SuggestedPEM)
	if err != nil {
		out.Status = TrustStatusSkipped
		out.Detail = "写入 " + caFile + " 失败: " + err.Error()
		return out, nil, err
	}
	out.CertsAdded = added

	tc, err := c.ApplyTLSCA(caFile)
	if err != nil {
		out.Status = TrustStatusSkipped
		out.Detail = "热加载 " + caFile + " 失败: " + err.Error()
		return out, nil, err
	}

	// 复验：用刚生效的池再握一次手，直接回答「现在通了吗」。
	// 失败时把「配置之后的真实原因」带出来（证书缺 SAN、域名不匹配……）——
	// 否则调用方只能看到一句含糊的「仍未通过」。
	out.Status = TrustStatusUnverified
	if re, rerr := c.ProbeChain(ctx, host); rerr != nil {
		out.Detail = rerr.Error()
	} else if re.TrustedByConfigured {
		out.Status = TrustStatusTrusted
		out.Verified = true
	} else {
		out.Detail = strings.TrimSpace(re.ConfiguredVerifyErr)
	}
	return out, tc, nil
}

// MergePEMToFile 把 pems 中的证书合并进 caFile（按 DER 去重 + 原子替换写），
// 返回本次新增的证书张数。caFile 不存在则创建（0644）。
//
// 为什么必须「合并」而非覆盖：真实环境里代理常对不同域名用不同 CA，逐主机
// 自动修时后一次不能把前一次的结果冲掉。相反，若新增证书已全部存在，
// 则**不写盘**（保持文件 mtime、避免无意义 IO 与断电窗口）。
func MergePEMToFile(caFile string, pems ...string) (int, error) {
	caFile = strings.TrimSpace(caFile)
	if caFile == "" {
		return 0, errors.New("tls 自动修: CA 文件路径为空")
	}
	existing, err := os.ReadFile(caFile)
	if err != nil && !os.IsNotExist(err) {
		return 0, fmt.Errorf("读取 %s: %w", caFile, err)
	}

	seen := make(map[[32]byte]bool)
	var ders [][]byte
	collect := func(raw []byte) {
		for {
			var blk *pem.Block
			blk, raw = pem.Decode(raw)
			if blk == nil {
				return
			}
			if blk.Type != "CERTIFICATE" || len(blk.Bytes) == 0 {
				continue // 非证书块（极罕见）忽略，不作为 CA
			}
			k := sha256.Sum256(blk.Bytes)
			if seen[k] {
				continue
			}
			seen[k] = true
			ders = append(ders, blk.Bytes)
		}
	}
	collect(existing)
	before := len(ders)
	for _, p := range pems {
		collect([]byte(p))
	}
	if added := len(ders) - before; added == 0 {
		return 0, nil
	}

	// 统一重新编码（规范化 64 列），文件永远是干净的纯 PEM。
	var buf bytes.Buffer
	for _, der := range ders {
		buf.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	if err := writeFileAtomic(caFile, buf.Bytes(), 0o644); err != nil {
		return 0, err
	}
	return len(ders) - before, nil
}

// writeFileAtomic 同目录临时文件 + rename 覆盖写。
//
// 为什么不用 os.WriteFile：写到一半掉电/被杀会留下半截 PEM，而 ca.pem 会在下次
// 启动时被 BuildTLSConfig 解析，半截文件直接导致启动 fail fast —— 一个本来只是
// 「证书没修好」的小问题被放大成「服务起不来」。
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("创建目录 %s: %w", dir, err)
		}
	}
	f, err := os.CreateTemp(dir, ".ca-*.tmp")
	if err != nil {
		return fmt.Errorf("创建临时文件: %w", err)
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }() // rename 成功后此处必然失败，无害
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("写入 %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("关闭 %s: %w", tmp, err)
	}
	_ = os.Chmod(tmp, perm) // Windows 上 chmod 语义有限，失败可忽略
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("替换 %s: %w", path, err)
	}
	return nil
}
