package server

import (
	"log"
	"net/http"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/trae/auth"
)

// 签到与批量运维（ops.go）。
//
// Trae 的签到有一个绕不开的约束：**一个设备号一天只能签一个账号**，且设备号
// 没过校验时上游只会返回 9074（文案「当前参与用户太多」是假的，与并发无关）。
// 所以批量签到一律**串行 + 固定间隔**，绝不并发 —— 并发只会让多个账号同时
// 撞 9074，还会加重风控。账号通常个位数，串行的代价可以忽略。

// checkinInterval 批量操作里相邻两个账号之间的间隔。
const checkinInterval = 300 * time.Millisecond

// checkinOutcome 单个账号的签到结果。
// Action 取值：checked_in（本次签上）/ already（今日已签）/ disabled（签到关闭）/
// error（上游失败）。Err 非 nil 时 Action 恒为 "error"。
type checkinOutcome struct {
	Action  string
	Credits int64
	Err     error
}

// checkinOne 对一个账号执行签到，并顺带刷新额度、写回池、尝试解冻。
//
// 与调度器 RunCheckinNow 同一套判据：先查状态，未签到且签到开启才 claim。
// 「今日已签」不是错误，单独用 Action 区分，避免前端把正常情况标红。
// 额度回写与 adminCredits 同一口径 —— 不写的话账号列表那边又变回 0。
func (h *Handler) checkinOne(a *auth.Auth) checkinOutcome {
	var out checkinOutcome

	checkedIn, _, enable, err := h.cfg.Upstream.CheckinStatus(a)
	switch {
	case err != nil:
		out.Action, out.Err = "error", err
		return out
	case checkedIn:
		out.Action = "already"
	case !enable:
		out.Action = "disabled"
	default:
		if err := h.cfg.Upstream.CheckinClaim(a); err != nil {
			out.Action, out.Err = "error", err
			return out
		}
		out.Action = "checked_in"
	}

	// 签到前后额度可能变化（签到本身就 +100），取最新值回写。
	if remain, _, _, _, uerr := h.cfg.Upstream.EntUsage(a); uerr == nil {
		out.Credits = remain
		h.cfg.Pool.SetCredits(a.UID, remain)
		h.cfg.Pool.ReenableIfCredits(a.UID, remain)
	}
	return out
}

// adminBalance 单账号刷新余额（EntUsage 查询 + 回写池内存）。
//
// 与 adminCredits 的区别：那个查全池、给「额度监控」用；这个只查一个号，
// 给账号卡片的「余额」按钮用（对齐主面板账号池的按钮命名）。
func (h *Handler) adminBalance(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	a := h.cfg.Pool.AuthByUID(uid)
	if a == nil {
		writeOpenAIError(w, http.StatusNotFound, "not_found", "no auth for uid")
		return
	}
	remain, limit, used, packs, err := h.cfg.Upstream.EntUsage(a)
	if err != nil {
		log.Printf("[trae] balance %s: %v", uid, err)
		// 业务失败同样返回 200 + ok:false（请求本身成功了），前端据 error 展示。
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "uid": uid, "error": err.Error()})
		return
	}
	h.cfg.Pool.SetCredits(uid, remain)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "uid": uid, "nickname": a.Nickname,
		"remain": remain, "limit": limit, "used": used, "packs": packs,
	})
}

// adminCheckin 单账号签到（写操作，需面板密钥）。
//
// 上游业务失败也返回 200：请求本身是成功的，失败原因走 body 的 error 字段，
// 前端据 ok/error 展示 —— 网络错误和业务失败混在一个状态码里反而分不清。
func (h *Handler) adminCheckin(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	a := h.cfg.Pool.AuthByUID(uid)
	if a == nil {
		writeOpenAIError(w, http.StatusNotFound, "not_found", "no auth for uid")
		return
	}
	res := h.checkinOne(a)
	log.Printf("[trae] checkin %s: %s", uid, res.Action)

	body := map[string]any{
		"uid":      uid,
		"nickname": a.Nickname,
		"action":   res.Action,
		"credits":  res.Credits,
		"ok":       res.Err == nil,
	}
	if res.Err != nil {
		body["error"] = res.Err.Error()
	}
	writeJSON(w, http.StatusOK, body)
}

// adminCheckinAll 批量签到（串行，间隔见 checkinInterval）。
//
// 冷却中的账号也参与 —— 签到本来就是解冻它们的手段；仅跳过硬禁用与凭证缺失。
// 汇总字段里 checked_in / already / failed 互斥计数，前端据此给一句话总结。
func (h *Handler) adminCheckinAll(w http.ResponseWriter, r *http.Request) {
	sts := h.cfg.Pool.List()
	results := make([]map[string]any, 0, len(sts))
	var okN, alreadyN, failN int

	for i, st := range sts {
		item := map[string]any{"uid": st.UID, "nickname": st.Nickname}
		a := h.cfg.Pool.AuthByUID(st.UID)
		switch {
		case st.Disabled:
			item["action"], item["error"] = "skipped", "账号已禁用，跳过"
		case a == nil:
			item["action"], item["error"] = "skipped", "凭证缺失，跳过"
		default:
			if i > 0 {
				time.Sleep(checkinInterval)
			}
			res := h.checkinOne(a)
			item["action"] = res.Action
			item["credits"] = res.Credits
			switch {
			case res.Err != nil:
				item["error"] = res.Err.Error()
				failN++
			case res.Action == "checked_in":
				okN++
			default:
				alreadyN++
			}
			log.Printf("[trae] checkin_all %s: %s", st.UID, res.Action)
		}
		results = append(results, item)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"total":      len(sts),
		"checked_in": okN,
		"already":    alreadyN,
		"failed":     failN,
		"results":    results,
		"fetched_at": time.Now().Format("2006-01-02 15:04:05"),
	})
}

// adminRefreshAll 批量刷新 token（串行）。与单号刷新同一套失败处置：
// session 失效 → 硬禁用（聊天路径遇到也走这条路，口径必须一致）。
func (h *Handler) adminRefreshAll(w http.ResponseWriter, r *http.Request) {
	sts := h.cfg.Pool.List()
	results := make([]map[string]any, 0, len(sts))
	var okN, failN, skipN int

	for i, st := range sts {
		item := map[string]any{"uid": st.UID, "nickname": st.Nickname}
		a := h.cfg.Pool.AuthByUID(st.UID)
		switch {
		case st.Disabled:
			item["action"], item["error"] = "skipped", "账号已禁用，跳过"
			skipN++
		case a == nil:
			item["action"], item["error"] = "skipped", "凭证缺失，跳过"
			skipN++
		default:
			if i > 0 {
				time.Sleep(checkinInterval)
			}
			if err := h.cfg.Upstream.RefreshToken(a); err != nil {
				if isSessionDeadErr(err) {
					h.cfg.Pool.Disable(st.UID, "refresh_all: session dead")
				}
				item["action"], item["error"] = "error", err.Error()
				failN++
				log.Printf("[trae] refresh_all %s: %v", st.UID, err)
				break
			}
			if a.FilePath == "" {
				a.FilePath = auth.FilePathFor(h.cfg.AuthDir, st.UID)
			}
			if err := a.SaveAtomic(); err != nil {
				item["action"], item["error"] = "error", "落盘失败: "+err.Error()
				failN++
				break
			}
			item["action"] = "refreshed"
			item["expires_at"] = a.ExpiresAt
			okN++
		}
		results = append(results, item)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"total":      len(sts),
		"refreshed":  okN,
		"failed":     failN,
		"skipped":    skipN,
		"results":    results,
		"fetched_at": time.Now().Format("2006-01-02 15:04:05"),
	})
}
