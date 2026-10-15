package panel

import (
	"net"
	"net/http"
)

// lanIPv4s 枚举本机非环回网卡的 IPv4 地址。
//
// primary 是默认路由的出口 IP——UDP dial 技巧：连接 8.8.8.8:80 但 UDP 不实际
// 发包，仅让内核查一次路由表，LocalAddr 即「当前网络下外网流量走的那块网卡」。
// 用户在局域网其他设备（手机等）访问时用的就是它。
func lanIPv4s() (primary string, ips []map[string]any) {
	if conn, err := net.Dial("udp", "8.8.8.8:80"); err == nil {
		if la, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			primary = la.IP.String()
		}
		conn.Close()
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return primary, nil
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil {
				continue // 面板访问场景只关心 IPv4
			}
			ips = append(ips, map[string]any{
				"addr":    ip4.String(),
				"iface":   ifc.Name,
				"primary": ip4.String() == primary,
			})
		}
	}
	return primary, ips
}

// lan 当前局域网访问地址（GET /panel/api/lan）。
//
// 换网络后本机 IP 会变——前端在配置页轮询本接口实时刷新。每次请求都重新
// 枚举（不走缓存），网卡切换的感知延迟 = 前端轮询间隔。
func (p *Panel) lan(w http.ResponseWriter, r *http.Request) {
	primary, ips := lanIPv4s()
	writeJSON(w, http.StatusOK, map[string]any{
		"port":    p.cfg.ListenPort,
		"primary": primary,
		"ips":     ips,
	})
}
