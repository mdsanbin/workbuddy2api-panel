// payload.go OpenAI → SOLO llm_utils_chat 请求体改写。
package upstream

import (
	"encoding/json"
	"strings"

	"github.com/linguo2625469/workbuddy2api-panel/internal/trae/auth"
)

// PrepareBody 单 pass 改写；无法解析时原样返回。
//
//	OpenAI: {model, messages, stream, tools, tool_choice, ...}
//	SOLO:   {messages, function:"solo_work_lite", stream:true,
//	         config_name:<model>, model:<model>}
//
// 改写规则（SPEC §4.4）：
//  1. messages: content 字符串 → [{"type":"text","text":...}]；已是数组 → 透传
//  2. stream: 强制 true（非流式由服务端聚合）
//  3. model → config_name + model
//  4. function: 固定 "solo_work_lite"
//  5. tools/tool_choice: 归一化（"none" 删 tools；auto/required 保留；function 提取 name）
// kind 决定 function 取值与字段集：Work 用 solo_work_lite + config_name，
// IDE 用 inline_chat + 每请求唯一的 request_id/session_id（IDE 侧不接受
// config_name，发了会被上游按未知字段处理）。
// applyReasoningEffort 归一化 OpenAI 风格的 reasoning_effort 到 Trae 口径。
//
// Trae 的档位值域（2026-10 从 IDE 客户端 i18n 与请求体构造双向确认）是
// xhigh / high / low —— **没有 medium，也没有关闭档**：客户端UI的「Thinking
// Effort」只有低/高/超高。请求体只认 reasoning_effort（部分旧链路用
// reasoning_effort_level），没有任何 thinking 开关字段。
//
// 已知未决（2026-10-14 实测，待后续修）：IDE 账号的对话端点其实是
// /api/ide/v1/chat_completion，而当前 ChatStream 对 IDE 也发 Work 侧的
// /api/agent/v3/llm_utils_chat，服务端因此默认 reasoning_effort=high 且
// thinking=disabled，直接 400 InvalidParameter。端点分流修好之前，
// 这里只做值域归一化（含 OpenAI 的 none/minimal → 删除该字段），不再附加
// 任何未被识别的 thinking 字段。
func applyReasoningEffort(obj map[string]any) {
	if v, ok := obj["reasoning_effort"].(string); ok {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "none", "minimal", "off", "disable", "disabled":
			// Trae 无「最小/关闭」档位：删除字段，让服务端按模型默认处理。
			delete(obj, "reasoning_effort")
		case "low", "high", "xhigh":
			obj["reasoning_effort"] = strings.ToLower(strings.TrimSpace(v))
		default:
			delete(obj, "reasoning_effort") // medium 等无效值不下发
		}
	}
	delete(obj, "enable_thinking")
	if t, ok := obj["thinking"].(map[string]any); ok {
		_ = t
	}
	// 兼容 OpenWeight/部分客户端：thinking.type=disabled → 视作关闭，删 effort。
	if t, ok := obj["thinking"].(map[string]any); ok {
		if ty, _ := t["type"].(string); ty == "disabled" || ty == "off" {
			delete(obj, "reasoning_effort")
		}
	}
	delete(obj, "thinking") // Trae 请求体不认 thinking 对象，删掉避免干扰
}

func PrepareBody(src []byte, kind string) []byte {
	if len(src) == 0 {
		return src
	}
	var obj map[string]any
	if err := json.Unmarshal(src, &obj); err != nil {
		return src
	}
	obj["stream"] = true
	if kind == auth.KindIDE {
		obj["function"] = FunctionIDE
		// 每次请求独立的会话标识：IDE 侧用它做上下文隔离，复用会导致串话。
		if sid := newRequestID(); sid != "" {
			obj["request_id"] = sid
			obj["session_id"] = sid
		}
	} else {
		obj["function"] = Function
	}

	if msgs, ok := obj["messages"].([]any); ok {
		for _, mi := range msgs {
			m, ok := mi.(map[string]any)
			if !ok {
				continue
			}
			content, present := m["content"]
			role, _ := m["role"].(string)

			// assistant 消息回传 tool_calls: OpenAI function → 上游 function_call
			if role == "assistant" {
				if tcs, ok := m["tool_calls"].([]any); ok {
					kept := make([]any, 0, len(tcs))
					for _, tci := range tcs {
						tc, ok := tci.(map[string]any)
						if !ok {
							continue
						}
						// OpenAI: function{name, arguments} → 上游 SOLO: function_call{name, arguments}
						if fn, ok := tc["function"].(map[string]any); ok {
							tc["function_call"] = fn
							delete(tc, "function")
						}
						// 上游要求 FunctionCall.Name 必填: 无 name 的 tool_call 剔除
						if fc, ok := tc["function_call"].(map[string]any); ok {
							name, _ := fc["name"].(string)
							if strings.TrimSpace(name) == "" {
								continue
							}
						}
						kept = append(kept, tc)
					}
					if len(kept) == 0 {
						delete(m, "tool_calls")
					} else {
						m["tool_calls"] = kept
					}
				}
			}

			if !present || content == nil {
				continue // 无 content 的消息(如纯 tool_calls assistant 已转换完)保留字段但跳过 content 改写
			}
			switch c := content.(type) {
			case string:
				m["content"] = []any{
					map[string]any{"type": "text", "text": c},
				}
			default:
				// 已是数组 → 透传（兼容多模态，未实测，保守透传）
			}
		}
	}

	model, _ := obj["model"].(string)
	model = strings.TrimSpace(model)
	if model == "" {
		model = DefaultConfigName
	}
	if kind == auth.KindIDE {
		obj["model"] = model
	} else {
		obj["config_name"] = model
		obj["model"] = model
	}

	normalizeToolChoice(obj)
	normalizeTools(obj)
	applyReasoningEffort(obj)
	out, err := json.Marshal(obj)
	if err != nil {
		return src
	}
	return out
}

// DefaultConfigName 默认模型（glm-5.2，实测可用）。
const DefaultConfigName = "glm-5.2"

// normalizeToolChoice 按上游 Go struct（string 类型）改写 OpenAI tool_choice。
//   - "none" / {"type":"none"} → 删 tool_choice + 删 tools/functions
//   - {"type":"auto"/"required"} → 字符串 "auto"/"required"
//   - {"type":"function","function":{"name":"x"}} → 字符串 "x"
//   - 其他对象/非标量 → 删 tool_choice
func normalizeToolChoice(obj map[string]any) {
	suppress := func() {
		delete(obj, "tools")
		delete(obj, "functions")
	}
	tc, present := obj["tool_choice"]
	if !present {
		return
	}
	switch v := tc.(type) {
	case string:
		if strings.EqualFold(strings.TrimSpace(v), "none") {
			delete(obj, "tool_choice")
			suppress()
		}
	case map[string]any:
		typ, _ := v["type"].(string)
		typ = strings.ToLower(strings.TrimSpace(typ))
		switch typ {
		case "none":
			delete(obj, "tool_choice")
			suppress()
		case "auto", "required":
			obj["tool_choice"] = typ
		case "function":
			name := ""
			if fn, ok := v["function"].(map[string]any); ok {
				name, _ = fn["name"].(string)
			}
			if name == "" {
				name, _ = v["name"].(string)
			}
			if name = strings.TrimSpace(name); name != "" {
				obj["tool_choice"] = name
			} else {
				obj["tool_choice"] = "auto"
			}
		default:
			delete(obj, "tool_choice")
		}
	default:
		delete(obj, "tool_choice")
	}
}

// normalizeTools 把 OpenAI tools 转为 SOLO 上游格式。
// 实测上游 Go struct: FunctionDefinition.tools[].function.parameters 是 string 类型
// （OpenAI 标准是 object）→ 需把 parameters 对象序列化为 JSON 字符串。
// 同时 tools 条目若不是 map 或缺 function，整体剔除（避免上游反序列化失败）。
func normalizeTools(obj map[string]any) {
	raw, present := obj["tools"]
	if !present {
		return
	}
	list, ok := raw.([]any)
	if !ok || len(list) == 0 {
		return
	}
	out := make([]any, 0, len(list))
	for _, item := range list {
		t, ok := item.(map[string]any)
		if !ok {
			continue
		}
		fn, ok := t["function"].(map[string]any)
		if !ok {
			continue
		}
		if params, ok := fn["parameters"]; ok {
			if paramsMap, isMap := params.(map[string]any); isMap {
				if s, err := json.Marshal(paramsMap); err == nil {
					fn["parameters"] = string(s)
				}
			}
		}
		out = append(out, t)
	}
	if len(out) == 0 {
		delete(obj, "tools")
		return
	}
	obj["tools"] = out
}
