// ide_import.go 从本机 Trae IDE 的登录态导入账号（POST /admin/api/import-ide）。
//
// 为什么单独一条路由而不是并进 /accounts/import：那条接口吃的是「凭证内容」
// （回调链接或 JSON），用户得自己把 token 搬过来；而这条吃的是「去本机哪儿读」。
// IDE 的登录态是客户端用自家 "tc" 格式加密存的（见 auth.LoadIDECredential），
// 只有网关侧解密才拿得到，所以这里直接解密后转成标准的 trae-*.json 落盘，
// 之后与手工导入的账号走完全相同的池逻辑。
//
// 导入是一次性动作：落盘后 token 的刷新与写回由常规流程负责，不再回读
// storage.json——避免与客户端抢写同一个文件。
package server

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/linguo2625469/workbuddy2api-panel/internal/trae/auth"
)

// ideImportRequest 请求体（可空：不带 body 即纯自动探测）。
type ideImportRequest struct {
	// StoragePath 显式指定 storage.json 路径；空 = 按平台约定自动探测。
	StoragePath string `json:"storage_path"`
}

// adminImportIDE 读本机 Trae IDE 登录态并导入账号池。
func (h *Handler) adminImportIDE(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request", "read body: "+err.Error())
		return
	}
	var req ideImportRequest
	if strings.TrimSpace(string(body)) != "" {
		if err := json.Unmarshal(body, &req); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid_request", "parse json: "+err.Error())
			return
		}
	}
	if h.cfg.AuthDir == "" {
		writeOpenAIError(w, http.StatusInternalServerError, "no_auth_dir", "server AuthDir not configured")
		return
	}

	cred, err := auth.LoadIDECredential(req.StoragePath)
	if err != nil {
		// 原样透出原因：最常见的是「没装 / 没登录 / 换过安装目录」，
		// 用户据此能自己判断，不必让他靠猜。
		writeOpenAIError(w, http.StatusBadRequest, "ide_import_failed", err.Error())
		return
	}
	a := cred.ToAuth("")
	a.FilePath = auth.FilePathFor(h.cfg.AuthDir, a.UID)

	if err := os.MkdirAll(h.cfg.AuthDir, 0o755); err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, "mkdir_failed", err.Error())
		return
	}
	_, statErr := os.Stat(a.FilePath)
	if err := a.SaveAtomic(); err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, "save_failed", err.Error())
		return
	}
	action := "created"
	if statErr == nil {
		action = "updated"
	}
	h.cfg.Pool.Add(a)

	writeJSON(w, http.StatusOK, map[string]any{
		"uid":         a.UID,
		"nickname":    a.Nickname,
		"action":      action,
		"kind":        auth.KindIDE,
		"expires_at":  a.ExpiresAt,
		"needs_check": true,
	})
}
