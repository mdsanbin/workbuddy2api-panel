// constants.go SOLO 上游技术常量（SPEC §1，来自实测，禁止改动）。
package upstream

const (
	AgentHost      = "https://trae-api-cn.mchost.guru"
	UgHost         = "https://api.trae.cn"
	OAuthHost      = "https://api.trae.com.cn"
	ConsoleHost    = "https://www.trae.cn"
	ClientID       = "en1oxy7wnw8j9n" // SOLO stable
	AppID          = "6eefa01c-1036-4c7e-9ca5-d891f63bfcd8"
	IdeVersion     = "0.1.52"
	IdeVersionCode = "20260811"
	DeviceBrand    = "83DG"
	OSVersion      = "Windows 11 Pro"
	Function       = "solo_work_lite"

	// --- Trae IDE（VSCode 系客户端）侧常量 ---
	// IDE 与 Work 是两个独立的 OAuth 应用：ClientID 不通用，function 取值也不同。
	// 两边共用同一个对话上游（AgentHost）与同一套 Cloud-IDE-JWT 鉴权。
	ClientIDIDE       = "ono9krqynydwx5" // IDE 的 OAuth ClientID
	FunctionIDE       = "inline_chat"    // IDE 对话的 function 取值
	// IDE 侧版本号：上游会校验 x-ide-version 系列头，取一个实测可用的稳定值。
	// 与 Work 侧（0.1.52）不同体系——IDE 客户端自身版本是 VSCode 式的 1.107.x。
	IdeVersionIDE     = "3.3.67"
	IdeVersionCodeIDE = "20260401"

	// 端点
	EpChat          = "/api/agent/v3/llm_utils_chat"
	EpModels        = "/api/ide/v1/get_detail_param"
	EpExchange      = "/cloudide/api/v3/trae/oauth/ExchangeToken"
	EpUserInfo      = "/cloudide/api/v3/trae/GetUserInfo"
	EpCheckinStatus = "/trae/api/v2/ug/checkin_credits/status"
	EpCheckinClaim  = "/trae/api/v2/ug/checkin_credits/claim"
	EpEntUsage      = "/trae/api/v2/pay/ide_user_ent_usage"
)
