package panel

import "net/http"

// tunnelStatus 返回隧道的运行时状态，供面板「配置 → 远程访问」轮询显示。
//
// 只读：启停本身走的是配置保存（POST /panel/api/config）——「是否启用隧道」本来就是
// 配置项，再开一条独立的写入路径会出现「配置说关着、进程却在跑」的不一致窗口。
// 启动失败的详情（没装 cloudflared、token 缺失等）通过 Status.Err 透出。
func (p *Panel) tunnelStatus(w http.ResponseWriter, r *http.Request) {
	if p.cfg.Tunnel == nil {
		writeErr(w, http.StatusNotImplemented, "tunnel_unavailable")
		return
	}
	writeJSON(w, http.StatusOK, p.cfg.Tunnel.Status())
}
