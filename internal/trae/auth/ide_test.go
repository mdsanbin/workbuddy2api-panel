package auth

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestDeriveDeviceID(t *testing.T) {
	got := deriveDeviceID("machine-abc")
	if len(got) != 32 {
		t.Errorf("长度应为 32，得到 %d (%q)", len(got), got)
	}
	// 同一 machineId 必须稳定产出同一 deviceId —— 每次请求漂移会被上游当成换设备。
	if again := deriveDeviceID("machine-abc"); again != got {
		t.Errorf("同一输入结果不稳定: %q vs %q", got, again)
	}
	if other := deriveDeviceID("machine-abd"); other == got {
		t.Errorf("不同输入不应碰撞: %q", got)
	}
	if empty := deriveDeviceID("  "); empty != "" {
		t.Errorf("空白 machineId 应返回空串，得到 %q", empty)
	}
}

func TestParseIDETime(t *testing.T) {
	bad := []string{"", "   ", "not-a-time", "2026-13-45T99:99:99Z"}
	for _, in := range bad {
		if got := parseIDETime(in); got != 0 {
			t.Errorf("parseIDETime(%q) = %d，应视为无效并返回 0", in, got)
		}
	}
	for _, in := range []string{"2026-10-26T12:56:00.000Z", "2026-10-26T12:56:00Z"} {
		if got := parseIDETime(in); got <= 0 {
			t.Errorf("parseIDETime(%q) = %d，应解析成功", in, got)
		}
	}
}

func TestDecryptTCRejectsMalformed(t *testing.T) {
	short := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, 20))
	for _, in := range []string{"", "not base64!!", short} {
		if _, err := DecryptTC(in); err == nil {
			t.Errorf("DecryptTC(%q) 应报错", in)
		}
	}
}

func TestDecryptTCUnknownHeader(t *testing.T) {
	// 头特征不匹配任何已知类型 → 必须明确报错，而不是拿错 salt 解出乱码。
	raw := bytes.Repeat([]byte{0x11}, 6+32+16)
	if _, err := DecryptTC(base64.StdEncoding.EncodeToString(raw)); err == nil {
		t.Error("未知 header 应报错")
	}
}

func TestPKCS7Unpad(t *testing.T) {
	valid := append([]byte("abc"), bytes.Repeat([]byte{13}, 13)...)
	got, err := pkcs7Unpad(valid)
	if err != nil {
		t.Fatalf("合法填充不应报错: %v", err)
	}
	if string(got) != "abc" {
		t.Errorf("去掉填充后应得 \"abc\"，得到 %q", got)
	}
	// 填充长度超过分组大小
	if _, err := pkcs7Unpad([]byte{1, 2, 17}); err == nil {
		t.Error("填充长度非法应报错")
	}
	// 填充字节与长度不一致
	if _, err := pkcs7Unpad([]byte{1, 2, 3, 2}); err == nil {
		t.Error("填充字节不一致应报错")
	}
	if _, err := pkcs7Unpad(nil); err == nil {
		t.Error("空输入应报错")
	}
}

func TestKindHelpers(t *testing.T) {
	a := &Auth{}
	if a.IsIDE() {
		t.Error("空 Kind 不应判为 IDE")
	}
	if k := a.KindOrDefault(); k != KindSOLO {
		t.Errorf("空 Kind 应回落 %q，得到 %q", KindSOLO, k)
	}
	b := &Auth{Kind: KindIDE}
	if !b.IsIDE() {
		t.Error("KindIDE 应判为 IDE")
	}
	if k := b.KindOrDefault(); k != KindIDE {
		t.Errorf("KindOrDefault 应返回 %q，得到 %q", KindIDE, k)
	}
}

func TestIDECredentialToAuthUsesPrefix(t *testing.T) {
	c := &IDECredential{
		Token:        "tok",
		RefreshToken: "ref",
		UserID:       "1234567890",
		Host:         "https://api.trae.cn",
		MachineID:    "m1",
	}
	a := c.ToAuth("/tmp/x.json")
	if a.UID != "ide-1234567890" {
		t.Errorf("UID 应带 ide- 前缀以避免与 Work 账号撞主键，得到 %q", a.UID)
	}
	if a.Kind != KindIDE || !a.IsIDE() {
		t.Errorf("Kind 应为 %q，得到 %q", KindIDE, a.Kind)
	}
	if a.ApiHost != "https://api.trae.cn" {
		t.Errorf("ApiHost 应取自登录态里的 host，得到 %q", a.ApiHost)
	}
	if a.DeviceID == "" || len(a.DeviceID) != 32 {
		t.Errorf("DeviceID 应由 machineId 派生，得到 %q", a.DeviceID)
	}
	if a.FilePath != "/tmp/x.json" {
		t.Errorf("FilePath = %q", a.FilePath)
	}
}
