// ide.go 从本机 Trae IDE 的登录态中导出账号凭证。
//
// 背景：Trae 有两条独立产品线——TRAE IDE（VSCode 系客户端）与 TRAE Work
// （原 TRAE SOLO，AI 原生工作台）。两者的登录态互不相通，签发 token 的 OAuth
// ClientID 也不同（IDE 是 ono9krqynydwx5，Work 是 en1oxy7wnw8j9n）。本包已支持
// Work 侧的 trae-*.json 凭证文件；IDE 侧没有这类文件，登录态只存在于客户端自己
// 的加密存储里，故需要本文件把它读出来并归一化成同构的 Auth。
//
// 存储位置（VSCode 系约定）：
//
//	%APPDATA%\<产品名>\User\globalStorage\storage.json
//
// 其中 "iCubeAuthInfo://icube.cloudide" 是自家定义的 "tc" 密文；国际版（SG）
// 该字段是明文 JSON，此处自动识别。
//
// tc 解密（数据布局与密钥派生来自客户端前端 JS 的实测结果）：
//
//	密文 = [6B 头][32B 随机数][N 密文]       整体 Base64 后存进 storage.json
//	明文 = [64B SHA-512 校验][N 明文 JSON]
//	Key/IV = SHA-512( SHA-512(随机数) ‖ (SALT_X ^ SALT_Y) )
//	         取前 16B 作 AES-128 Key、次 16B 作 IV，CBC 模式
//
// 两个 6 字节头特征分别对应两组 salt：A^B（普通 tc）与 C^D（AES_PRIVATE）。
package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Kind 取值：凭证来源产品线。空值等价 solo（老文件零回归）。
const (
	// KindSOLO TRAE Work（原 TRAE SOLO）独立客户端的凭证文件。
	KindSOLO = "solo"
	// KindIDE Trae IDE（VSCode 系客户端）导出的本机登录态。
	KindIDE = "ide"
)

// ideUIDPrefix IDE 账号在池内的 uid 前缀。
//
// 为什么必须加：池以 UID 为主键，而同一个 Trae 账号可以同时在 IDE 与 Work 两个
// 客户端登录、各持一份互不相同的 token。不加前缀两条记录会在池里互相覆盖。
// 前缀同时也让面板/日志一眼看出这条账号来自哪条产品线，并让落盘文件名自然分开
// （trae-ide-<uid>.json vs trae-<uid>.json）。
//
// 用连字符而非冒号：UID 会进文件名，而 Windows 文件名不允许冒号。
const ideUIDPrefix = "ide-"

// IDEUIDPrefix 导出给上层（如服务端路由判断账号来源）。
func IDEUIDPrefix() string { return ideUIDPrefix }

// tc 加密的两组 64 字节 salt（来自客户端前端 JS，禁止改动）。
var (
	saltTC = [64]byte{
		82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251,
		124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203,
		84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78,
		8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37,
	}
	saltTC2 = [64]byte{
		31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95,
		96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239,
		160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97,
		23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125,
	}
	saltPriv = [64]byte{
		191, 192, 216, 250, 122, 246, 220, 97, 31, 254, 98, 27, 8, 72, 71, 176,
		135, 99, 96, 18, 127, 101, 203, 104, 211, 102, 191, 125, 37, 72, 150, 156,
		51, 229, 121, 35, 17, 153, 141, 177, 110, 131, 150, 128, 172, 255, 254, 6,
		18, 140, 55, 62, 236, 249, 135, 64, 135, 12, 117, 4, 89, 149, 168, 209,
	}
	saltPriv2 = [64]byte{
		246, 204, 26, 232, 232, 70, 129, 109, 223, 146, 169, 242, 23, 241, 105, 145,
		50, 196, 165, 42, 254, 120, 3, 54, 244, 207, 209, 85, 53, 6, 138, 106,
		175, 148, 31, 204, 186, 186, 165, 182, 87, 142, 49, 10, 39, 110, 26, 154,
		86, 56, 173, 125, 18, 64, 198, 225, 99, 99, 83, 82, 191, 134, 76, 170,
	}
)

// tcHeader 密文头特征。
var (
	tcHeaderTC     = [6]byte{0x74, 0x63, 0x05, 0x10, 0x00, 0x00} // "tc"
	tcHeaderPriv   = [6]byte{18, 57, 32, 32, 2, 3}               // AES_PRIVATE
)

func xor64(a, b [64]byte) [64]byte {
	var out [64]byte
	for i := range out {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// DecryptTC 解密 Trae 客户端 "tc" 格式的 Base64 密文，返回明文 JSON 字节。
//
// 校验失败即返回错误（不返回半解出的内容）——SHA-512 校验和是唯一的完整性判据，
// 忽略它会把「密钥派生写错了」伪装成「成功解出乱码」，排查时极难定位。
func DecryptTC(b64 string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, fmt.Errorf("tc 解密: base64 解码失败: %w", err)
	}
	if len(raw) < 38+aes.BlockSize {
		return nil, fmt.Errorf("tc 解密: 密文长度 %d 过短", len(raw))
	}
	var header [6]byte
	copy(header[:], raw[:6])
	randomBytes := raw[6:38]
	encData := raw[38:]

	var salt [64]byte
	switch header {
	case tcHeaderTC:
		salt = xor64(saltTC, saltTC2)
	case tcHeaderPriv:
		salt = xor64(saltPriv, saltPriv2)
	default:
		return nil, fmt.Errorf("tc 解密: 未知加密类型 header=% x", header[:])
	}

	// Key/IV 派生：SHA-512( SHA-512(随机数) ‖ salt ) → Key=前16B, IV=次16B。
	h1 := sha512.Sum512(randomBytes)
	h2 := sha512.Sum512(append(h1[:], salt[:]...))
	key, iv := h2[:16], h2[16:32]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("tc 解密: %w", err)
	}
	if len(encData)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("tc 解密: 密文长度 %d 不是分组大小的整数倍", len(encData))
	}
	padded := make([]byte, len(encData))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(padded, encData)
	// 去 PKCS#7 填充：与 Node crypto 的 Decipher.final() 同语义。少了这一步，
	// 尾部填充字节会被算进正文，SHA-512 校验必然失败（实测踩过）。
	plain, err := pkcs7Unpad(padded)
	if err != nil {
		return nil, fmt.Errorf("tc 解密: %w", err)
	}

	// 明文 = [64B SHA-512 校验][N JSON]；校验和覆盖其后的全部正文。
	if len(plain) < 64 {
		return nil, errors.New("tc 解密: 明文过短，缺少校验段")
	}
	want := plain[:64]
	body := plain[64:]
	got := sha512.Sum512(body)
	for i := range want {
		if want[i] != got[i] {
			return nil, errors.New("tc 解密: SHA-512 校验失败（密钥派生不匹配或密文已变更）")
		}
	}
	return body, nil
}

// pkcs7Unpad 校验并去除 PKCS#7 填充。
func pkcs7Unpad(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, errors.New("空明文")
	}
	n := int(b[len(b)-1])
	if n == 0 || n > aes.BlockSize || n > len(b) {
		return nil, fmt.Errorf("PKCS#7 填充长度非法: %d", n)
	}
	for _, c := range b[len(b)-n:] {
		if int(c) != n {
			return nil, errors.New("PKCS#7 填充字节不一致")
		}
	}
	return b[:len(b)-n], nil
}

// ideStorageFile IDE 登录态在客户端数据目录中的相对路径。
var ideStorageFile = filepath.Join("User", "globalStorage", "storage.json")

// ideAuthKey storage.json 中存放登录态的键。
const ideAuthKey = "iCubeAuthInfo://icube.cloudide"

// ideAppDirNames Windows 上各版本 Trae 客户端的 %APPDATA% 子目录名。
// 顺序即探测优先级（国内版优先）。
var ideAppDirNames = []string{"Trae CN", "Trae", "TRAE SOLO CN", "TRAE SOLO"}

// IDECredential Trae IDE storage.json 里解密出来的登录态。
// 字段名与客户端落盘保持一致，便于对照排查。
type IDECredential struct {
	Token            string `json:"token"`
	RefreshToken     string `json:"refreshToken"`
	ExpiredAt        string `json:"expiredAt"`
	RefreshExpiredAt string `json:"refreshExpiredAt"`
	UserID           string `json:"userId"`
	Host             string `json:"host"`
	Account          struct {
		Username string `json:"username"`
		Email    string `json:"email"`
	} `json:"account"`

	// MachineID 不在密文里：它位于 storage.json 顶层的 telemetry.machineId
	// （客户端安装时生成、之后不变），由 LoadIDECredential 一并取出。
	MachineID string `json:"-"`
}

// FindIDEStorage 按平台约定探测本机 Trae IDE 的 storage.json 路径。
// 找到第一个存在的即返回；都找不到返回空串（调用方据此提示用户）。
func FindIDEStorage() string {
	appData := os.Getenv("APPDATA")
	if appData == "" {
		// 非 Windows（或环境变量缺失）时退回用户主目录下的同名结构。
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		appData = filepath.Join(home, ".config")
	}
	for _, name := range ideAppDirNames {
		p := filepath.Join(appData, name, ideStorageFile)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

// LoadIDECredential 读取并解密指定 storage.json 里的 IDE 登录态。
// path 为空时自动探测。
func LoadIDECredential(path string) (*IDECredential, error) {
	if strings.TrimSpace(path) == "" {
		path = FindIDEStorage()
		if path == "" {
			return nil, errors.New("未找到 Trae IDE 的 storage.json（请确认已安装并登录 Trae IDE，或用 trae.ide.storage_path 显式指定）")
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取 %s: %w", path, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("解析 %s: %w", path, err)
	}
	// machineId 在密文之外的顶层：一并取出（缺失不致命，只是少一个出站头）。
	machineID, _ := doc["telemetry.machineId"].(string)

	v, ok := doc[ideAuthKey]
	if !ok {
		return nil, fmt.Errorf("%s 中没有 %s（该客户端未登录？）", path, ideAuthKey)
	}
	s, ok := v.(string)
	if !ok || strings.TrimSpace(s) == "" {
		return nil, fmt.Errorf("%s 中的 %s 为空或类型异常", path, ideAuthKey)
	}

	var plain []byte
	if strings.HasPrefix(strings.TrimSpace(s), "{") {
		// 国际版（SG）直接存明文 JSON。
		plain = []byte(s)
	} else {
		plain, err = DecryptTC(s)
		if err != nil {
			return nil, err
		}
	}
	var cred IDECredential
	if err := json.Unmarshal(plain, &cred); err != nil {
		return nil, fmt.Errorf("解析解密结果: %w", err)
	}
	if strings.TrimSpace(cred.Token) == "" || strings.TrimSpace(cred.UserID) == "" {
		return nil, errors.New("登录态缺少 token 或 userId（该客户端未登录？）")
	}
	cred.MachineID = strings.TrimSpace(machineID)
	return &cred, nil
}

// ToAuth 把 IDE 登录态归一化成池内使用的 Auth。
//
// machineID 取自 storage.json 顶层的 telemetry.machineId（客户端安装时生成、
// 之后不变），deviceID 由它派生 —— 与客户端自身的做法一致。
func (c *IDECredential) ToAuth(filePath string) *Auth {
	return &Auth{
		AccessToken:  c.Token,
		RefreshToken: c.RefreshToken,
		ExpiresAt:    parseIDETime(c.ExpiredAt),
		UID:          ideUIDPrefix + c.UserID,
		Nickname:     c.Account.Username,
		// ApiHost 是**刷新 token 用的 OAuth host**（客户端自己记在登录态里），
		// 不是对话上游——对话上游走 upstream 包里的固定常量。
		ApiHost:   strings.TrimSpace(c.Host),
		MachineID: c.MachineID,
		DeviceID:  deriveDeviceID(c.MachineID),
		Kind:      KindIDE,
		FilePath:  filePath,
	}
}

// deriveDeviceID 由 machineId 派生 x-device-id：SHA-256 十六进制串取前 32 字符。
// 与客户端行为一致；machineID 为空时返回空串（调用方据此跳过该头）。
func deriveDeviceID(machineID string) string {
	machineID = strings.TrimSpace(machineID)
	if machineID == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(machineID))
	return hex.EncodeToString(sum[:])[:32]
}

// parseIDETime 解析客户端的时间串（ISO8601，带毫秒与 Z），失败返回 0（= 视作需刷新）。
func parseIDETime(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.000Z", "2006-01-02T15:04:05Z"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.Unix()
		}
	}
	return 0
}
