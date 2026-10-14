// shutdown.go 面板「停止服务」：优雅停机 + 模块场景下的停驻标记。
package panel

import (
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// shutdown POST /panel/api/shutdown：停止网关服务。
//
// 两件事的顺序不能反：
//
//  1. 先写「停止请求」标记文件（若配置了路径）。这是给 watcher.sh 的信号：
//     KernelSU 模块里网关是 watcher 的子进程，watcher 见子进程退出会自动把它拉起来
//     ——只让进程退出等于「重启」，用户点「停止服务」会眼看着服务又回来。标记文件
//     让 watcher 知道这次不要拉，它自己也会退出，服务才真的停住。
//
//  2. 再触发优雅停机，且**异步 + 延时**：先让本次 HTTP 响应完整发出去，200ms 后再
//     取消 ctx。http.Server.Shutdown 本身会等待在途请求收尾，这点余量是给面板并发
//     请求的收尾留的，避免用户看到「请求失败」而不是「已停止」。
func (p *Panel) shutdown(w http.ResponseWriter, r *http.Request) {
	if p.cfg.Shutdown == nil {
		writeErr(w, http.StatusNotImplemented, "该部署不支持从面板停止服务")
		return
	}

	resp := map[string]any{"ok": true}
	if path := strings.TrimSpace(p.cfg.ShutdownMark); path != "" {
		if err := os.WriteFile(path, []byte(time.Now().Format(time.RFC3339)+"\n"), 0o600); err != nil {
			// 写标记失败不阻断停机：进程照样退，只是模块场景下会被 watcher 拉起
			// （表现为「停了自己又回来」）。把原因带回给用户，别让他靠猜。
			resp["mark_error"] = err.Error()
			log.Printf("panel: 写停止标记 %s 失败: %v（服务仍会停止，但模块守护可能把它拉起）", path, err)
		} else {
			log.Printf("panel: 已写停止标记 %s，即将停机", path)
		}
	} else {
		log.Printf("panel: 收到停止服务请求，即将停机")
	}

	shutdown := p.cfg.Shutdown
	go func() {
		time.Sleep(200 * time.Millisecond)
		shutdown()
	}()

	writeJSON(w, http.StatusOK, resp)
}
