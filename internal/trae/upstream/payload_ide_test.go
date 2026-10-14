package upstream

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/trae/auth"
)

// IDE 侧与 Work 侧的载荷差异：function 取值、每请求唯一会话标识、不发 config_name。
func TestPrepareBodyIDEKind(t *testing.T) {
	out := PrepareBody([]byte(`{"model":"glm-5.2","messages":[{"role":"user","content":"hi"}]}`), auth.KindIDE)
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("结果不是 JSON: %v", err)
	}
	if m["function"] != FunctionIDE {
		t.Errorf("function = %v，want %v", m["function"], FunctionIDE)
	}
	if v, ok := m["config_name"]; ok {
		t.Errorf("IDE 侧不应发 config_name，实际为 %v", v)
	}
	if m["model"] != "glm-5.2" {
		t.Errorf("model = %v", m["model"])
	}
	if m["stream"] != true {
		t.Errorf("stream = %v，应强制 true", m["stream"])
	}
	sid, _ := m["session_id"].(string)
	rid, _ := m["request_id"].(string)
	if sid == "" || rid == "" {
		t.Fatalf("缺少会话标识: session_id=%q request_id=%q", sid, rid)
	}
	if sid != rid {
		t.Errorf("同一次请求的 session_id 与 request_id 应一致: %q vs %q", sid, rid)
	}
}

// 两次调用必须生成不同的会话标识 —— 复用会让上游把两轮对话当成同一会话从而串话。
func TestPrepareBodyIDESessionUnique(t *testing.T) {
	src := []byte(`{"model":"glm-5.2","messages":[{"role":"user","content":"hi"}]}`)
	first := sessionIDOf(t, src)
	second := sessionIDOf(t, src)
	if first == second {
		t.Errorf("两次请求的 session_id 相同: %q", first)
	}
}

func sessionIDOf(t *testing.T, src []byte) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(PrepareBody(src, auth.KindIDE), &m); err != nil {
		t.Fatalf("结果不是 JSON: %v", err)
	}
	s, _ := m["session_id"].(string)
	return s
}

// Work 侧行为不受本次改动影响（回归护栏）。
func TestPrepareBodyWorkKindUnchanged(t *testing.T) {
	for _, kind := range []string{"", auth.KindSOLO} {
		out := PrepareBody([]byte(`{"model":"glm-5.2","messages":[{"role":"user","content":"hi"}]}`), kind)
		var m map[string]any
		if err := json.Unmarshal(out, &m); err != nil {
			t.Fatalf("kind=%q 结果不是 JSON: %v", kind, err)
		}
		if m["function"] != Function {
			t.Errorf("kind=%q function = %v，want %v", kind, m["function"], Function)
		}
		if m["config_name"] != "glm-5.2" {
			t.Errorf("kind=%q config_name = %v", kind, m["config_name"])
		}
		if _, ok := m["session_id"]; ok {
			t.Errorf("kind=%q 不应发 session_id", kind)
		}
	}
}

func TestNewRequestID(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 32; i++ {
		id := newRequestID()
		if len(id) != 36 {
			t.Fatalf("UUID 长度应为 36，得到 %d (%q)", len(id), id)
		}
		if strings.Count(id, "-") != 4 {
			t.Fatalf("UUID 应有 4 个连字符: %q", id)
		}
		if id[14] != '4' {
			t.Errorf("version 位应为 4: %q", id)
		}
		if seen[id] {
			t.Fatalf("出现重复 UUID: %q", id)
		}
		seen[id] = true
	}
}
