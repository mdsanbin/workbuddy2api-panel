// tlsauto.go main 侧「出站 TLS 自动修」的启动编排。
//
// 与 internal/panel/tlsauto.go 的分工：那里是「请求撞上证书错误时现场修」，
// 这里是「服务启动后主动修」——覆盖用户还没发任何请求、或压根不会点面板的场景。
// 两者都调用 upstream.EnsureTrusted，同一套判定与落盘逻辑，不会漂移。
package main

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/panel"
	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

// tlsAutoTrustMaxRounds 后台自动修的最大轮数（含首轮）。
const tlsAutoTrustMaxRounds = 6

// caPEMFileFor 自动修写入的 CA 文件：与 config.json 同目录的 ca.pem。
// 与面板诊断页（internal/panel/tlsdiag.go 的 caPEMPath）以及模块 service.sh 的
// 自动加载路径三处对齐——同一个文件，手工修的与自动修的不会各存一份。
func caPEMFileFor(cfgFile string) string {
	dir := "."
	if strings.TrimSpace(cfgFile) != "" {
		dir = filepath.Dir(cfgFile)
	}
	return filepath.Join(dir, "ca.pem")
}

// startTLSAutoTrust 启动后台自动修（不阻塞监听）。
//
// 为什么放后台：每台主机要串行跑 3 次 TLS 握手（单次上限 20s），放启动路径会让
// 「服务开始监听」晚几十秒——手机上尤其不可接受。
//
// 为什么循环若干轮：设备上「代理尚未就绪」（VPN 刚连上、企业网关策略刚下发）很
// 常见，首轮探测失败不代表永久失败；每轮若已无需修（系统池通过 / 已有 ca.pem）
// 即退出，不长期占资源。重试间隔 <=0 时只试一次。
//
// 同时注册面板侧的「请求失败现场修」（SetTLSAutoHeal），两条路径共用同一 ca.pem。
func startTLSAutoTrust(cfg *Config, up *upstream.Client, cfgFile string) {
	hosts := cfg.autoTrustHosts()
	if len(hosts) == 0 {
		return
	}
	caFile := caPEMFileFor(cfgFile)
	// 同步 DefaultTransport 的 TLS 配置时必须一并保持 ALPN 同调（见 upstream/alpn.go）。
	alpnMode := upstream.ParseALPNMode(cfg.TLSALPN)
	panel.SetTLSAutoHeal(caFile, up)

	go func() {
		interval := time.Duration(cfg.TLSAutoTrustRetryMinutes) * time.Minute
		for round := 1; round <= tlsAutoTrustMaxRounds; round++ {
			if tlsAutoTrustRound(hosts, up, caFile, alpnMode) {
				return
			}
			if interval <= 0 {
				return
			}
			if round == tlsAutoTrustMaxRounds {
				log.Printf("TLS 自动修：经 %d 轮仍有主机未就绪，停止重试（可重启网关，或打开面板 /panel/tls 手动处理）", round)
				return
			}
			log.Printf("TLS 自动修：仍有主机未就绪，%s 后重试（第 %d/%d 轮）", interval, round+1, tlsAutoTrustMaxRounds)
			time.Sleep(interval)
		}
	}()
}

// tlsAutoTrustRound 跑一轮：对每台主机「确保信任」。返回 true 表示所有主机都已处于
// 终态（系统池通过 / 已有 ca.pem / 本轮已修好 / 证书本身有问题），无需再重试。
func tlsAutoTrustRound(hosts []string, up *upstream.Client, caFile string, alpnMode upstream.ALPNMode) bool {
	allDone := true
	for _, h := range hosts {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		out, tc, err := upstream.EnsureTrusted(ctx, up, h, caFile)
		cancel()

		if err != nil {
			log.Printf("TLS 自动修：%s 失败：%v", h, err)
			allDone = false
			continue
		}
		if tc != nil {
			// 信任池已变更：同步到设备授权 client 与 http.DefaultTransport
			//（推送 webhook / Upstash 镜像等走后者）。
			panel.SetLoginClientTLS(tc)
			syncDefaultTransportTLS(tc, alpnMode)
		}
		switch out.Status {
		case upstream.TrustStatusSystem:
			log.Printf("TLS 自动修：%s 由系统根池验证通过，无需处理", h)
		case upstream.TrustStatusConfigured:
			log.Printf("TLS 自动修：%s 已由现有 %s 信任", h, filepath.Base(caFile))
		case upstream.TrustStatusTrusted:
			log.Printf("TLS 自动修：已信任 %s 出示的证书链（新增 %d 张，复验通过）→ %s", h, out.CertsAdded, caFile)
		case upstream.TrustStatusUnverified:
			// 证书本身的问题（缺 SAN / 域名不匹配），重试不会有不同结果。
			log.Printf("TLS 自动修：%s 的证书已写入 %s 但复验未通过（%s）——请检查该证书本身",
				h, filepath.Base(caFile), out.Detail)
		case upstream.TrustStatusUnreachable:
			log.Printf("TLS 自动修：%s 暂不可达（%s）", h, out.Detail)
			allDone = false
		case upstream.TrustStatusSkipped:
			log.Printf("TLS 自动修：%s 未处理（%s）", h, out.Detail)
			allDone = false
		}
	}
	return allDone
}

// syncDefaultTransportTLS 把生效的 TLS 配置同步给 http.DefaultTransport
// （推送 webhook / Upstash 镜像等走它），与启动时的接线保持一致。
//
// 一并按 alpnMode 钉住 ALPN：DefaultTransport 自己会在首次使用时注册 h2，
// 若只换 TLSClientConfig 而不动 ALPN，就会出现「TLS 广告 h2 / HTTP 层却另有一套
// 认知」的分叉风险（成因与实证见 internal/upstream/alpn.go）。
func syncDefaultTransportTLS(tc *tls.Config, alpnMode upstream.ALPNMode) {
	if t, ok := http.DefaultTransport.(*http.Transport); ok {
		if tc != nil {
			t.TLSClientConfig = tc
		}
		upstream.ApplyOutboundALPN(t, alpnMode)
		// ApplyOutboundALPN 在 http/1.1 档刻意不清池（清池会烧掉标准库的一次性
		// 初始化，见 upstream/alpn.go），这里显式清一次：信任池刚换，带旧信任
		// 结论的 keep-alive 连接必须弃用。
		t.CloseIdleConnections()
	}
}
