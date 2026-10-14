// 管理面板（/admin）：只读查询，无鉴权（本地面板）；CLI 操作留待开发。
package server

import (
	_ "embed"
	"net/http"
	"sync"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/trae/pool"
)

//go:embed admin.html
var adminPageHTML []byte

// adminPage 返回内嵌 HTML 面板（深色简洁风，无外部依赖）。
func (h *Handler) adminPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// 只允许同源 iframe 内嵌：面板的「Trae 账号」页就是这么用它的。用 frame-ancestors
	// 而不是 X-Frame-Options: DENY —— 后者是「谁都不许嵌」，会把我们自己的面板页也挡掉。
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'self'")
	_, _ = w.Write(adminPageHTML)
}

// adminCredits 查询全部账号的实时额度 + 签到状态（并发拉取上游）。
func (h *Handler) adminCredits(w http.ResponseWriter, r *http.Request) {
	type acct struct {
		UID            string `json:"uid"`
		Nickname       string `json:"nickname"`
		Remain         int64  `json:"remain"`
		Limit          int64  `json:"limit"`
		Used           int64  `json:"used"`
		Packs          int    `json:"packs"`
		CheckedIn      bool   `json:"checked_in"`
		CheckinCredits int64  `json:"checkin_credits"`
		CheckinEnable  bool   `json:"checkin_enable"`
		Cooling        bool   `json:"cooling"`
		Disabled       bool   `json:"disabled"`
		Error          string `json:"error,omitempty"`
	}

	st := h.cfg.Pool.List()
	out := make([]acct, len(st))
	var wg sync.WaitGroup
	for i, s := range st {
		wg.Add(1)
		go func(i int, s pool.Status) {
			defer wg.Done()
			a := h.cfg.Pool.AuthByUID(s.UID)
			if a == nil {
				out[i] = acct{UID: s.UID, Nickname: s.Nickname, Error: "no auth found"}
				return
			}
			var ac acct
			ac.UID = s.UID
			ac.Nickname = s.Nickname
			ac.Cooling = s.Cooling
			ac.Disabled = s.Disabled
			remain, limit, used, packs, err := h.cfg.Upstream.EntUsage(a)
			if err != nil {
				ac.Error = "ent_usage: " + err.Error()
			} else {
				ac.Remain, ac.Limit, ac.Used, ac.Packs = remain, limit, used, packs
				// 回写池内存：账号列表（/admin/api/accounts）读的就是 entry.credits，
				// 不在这里回写的话那边永远显示 0。这正是「积分区域显示不出来」的根因——
				// 真实额度只活在本次响应里，没进池，列表自然拿不到。
				h.cfg.Pool.SetCredits(s.UID, remain)
			}
			checkedIn, credits, enable, cerr := h.cfg.Upstream.CheckinStatus(a)
			if cerr != nil {
				if ac.Error != "" {
					ac.Error += "; "
				}
				ac.Error += "checkin: " + cerr.Error()
			} else {
				ac.CheckedIn, ac.CheckinCredits, ac.CheckinEnable = checkedIn, credits, enable
			}
			out[i] = ac
		}(i, s)
	}
	wg.Wait()

	writeJSON(w, http.StatusOK, map[string]any{
		"fetched_at": time.Now().Format("2006-01-02 15:04:05"),
		"accounts":   out,
	})
}
