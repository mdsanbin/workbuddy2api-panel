// headers.go SOLO 三类请求头：对话（SOLOHeaders）/ ug（UgHeaders）/ oauth（OAuthHeaders）。
package upstream

import (
	"crypto/rand"
	"fmt"
	"net/http"

	"github.com/linguo2625469/workbuddy2api-panel/internal/trae/auth"
)

const clientUA = "Trae/" + IdeVersion

// SOLOHeaders 设置 llm_utils_chat / get_detail_param 所需的 SOLO 专属头。
// 规则来自 SPEC §1 SOLO headers（实测必须）。
func SOLOHeaders(req *http.Request, a *auth.Auth, stream bool) {
	req.Header.Set("Content-Type", "application/json")
	if stream {
		req.Header.Set("Accept", "text/event-stream")
	} else {
		req.Header.Set("Accept", "application/json")
	}
	req.Header.Set("User-Agent", clientUA)
	at := a.JWT() // 读锁快照，防与 RefreshToken 写并发竞态
	req.Header.Set("Authorization", "Cloud-IDE-JWT "+at)
	req.Header.Set("X-Cloudide-Token", at)
	req.Header.Set("X-Ide-Token", at)
	if a.UID != "" {
		req.Header.Set("X-Uid", a.UID)
	}
	req.Header.Set("X-App-Id", AppID)
	req.Header.Set("X-App-Version", "default")
	// 版本号按产品线取：两边版本体系不同，用错可能被上游按「过旧客户端」拒绝。
	ideVer, ideVerCode := IdeVersion, IdeVersionCode
	if a.IsIDE() {
		ideVer, ideVerCode = IdeVersionIDE, IdeVersionCodeIDE
	}
	req.Header.Set("X-Ide-Version", ideVer)
	req.Header.Set("X-Ide-Version-Code", ideVerCode)
	req.Header.Set("X-App-Version-Code", ideVerCode)
	req.Header.Set("X-Ide-Version-Type", "stable")
	req.Header.Set("X-Device-Type", "windows")
	req.Header.Set("X-OS-Version", OSVersion)
	req.Header.Set("X-Device-Brand", DeviceBrand)
	req.Header.Set("Request-Traffic-Type", "prod")
	if a.MachineID != "" {
		req.Header.Set("X-Machine-Id", a.MachineID)
	}
	if a.DeviceID != "" {
		req.Header.Set("X-Device-Id", a.DeviceID)
	}
	// x-request-id 是 IDE 侧链路要求的每请求唯一标识（Work 侧不需要，故按来源加）。
	if a.IsIDE() {
		if rid := newRequestID(); rid != "" {
			req.Header.Set("X-Request-Id", rid)
		}
	}
}

// newRequestID 生成 v4 UUID（用标准库，不引第三方依赖）。
// 失败返回空串——调用方据此跳过该头，不因此让整个请求失败。
func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// UgHeaders 设置签到/积分（api.trae.cn）所需头。
func UgHeaders(req *http.Request, a *auth.Auth) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", clientUA)
	req.Header.Set("Authorization", "Cloud-IDE-JWT "+a.JWT()) // 读锁快照
	req.Header.Set("X-User-Region", "CN")
	if a.DeviceID != "" {
		req.Header.Set("X-Device-Id", a.DeviceID)
	}
}

// OAuthHeaders 设置 ExchangeToken / GetUserInfo 所需头（无签名，仅 UA）。
func OAuthHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", clientUA)
}
