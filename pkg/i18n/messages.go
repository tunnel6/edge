package i18n

// Messages 消息定义
type Messages struct {
	// Public Address
	DetectingPublicIP  string
	DetectedPublicIPs  string
	IPv4Label          string
	IPv6Label          string
	ManualInputOption  string
	SelectPrompt       string
	InvalidOption      string
	Selected           string
	FailedToDetectIP   string
	EnterPublicAddress string
	InvalidAddress     string

	// AssignedDomain DNS
	VerifyingDNS        string
	AssignedDomainLabel string
	ExpectedResolve     string
	DNSCorrect          string
	DNSIncorrect        string
	ErrorLabel          string
	DNSRecordGuide      string
	DNSRecordType       string
	DNSRecordName       string
	DNSRecordValue      string
	DNSRecordTTL        string
	SelectOperation     string
	OptionRetry         string
	OptionSkip          string
	OptionQuit          string
	InputPrompt         string
	SkippingDNS         string
	SkipNote            string
	UserCancelled       string
	InvalidOptionRSQ    string
	DNSStillIncorrect   string
	CannotVerifyDNS     string

	// Certificate bootstrap

	// Edge server logs
	EdgeServerStarting            string
	EdgeServerStarted             string
	EdgeServerStopping            string
	EdgeServerStopped             string
	IPCNodeMarkedOnline           string
	IPCNodeMarkedOffline          string
	IPCReloadConfigRequested      string
	CertManagerInitialized        string
	CheckingCertificateStatus     string
	CertMissingOrExpiredBootstrap string
	CertExpiringSoon              string
	LoadedAssignedDomainFromLocal string
	CertificateReady              string
	StartingCertificateBootstrap  string
	ExtractedNodeIDFromCert       string
	AppliedAssignedDomain         string
	PersistAssignedDomainFailed   string
	BootstrapCompleted            string
	InitializingServices          string
	ServicesInitialized           string
	StartingServices              string
	StartIPCServerFailed          string
	ServerStateChanged            string
}

var zhMessages = Messages{
	// Public Address
	DetectingPublicIP:  "\n🔍 正在自动检测公网地址...",
	DetectedPublicIPs:  "\n检测到以下公网地址:",
	IPv4Label:          "IPv4",
	IPv6Label:          "IPv6",
	ManualInputOption:  "手动输入其他地址",
	SelectPrompt:       "\n请选择 (输入数字): ",
	InvalidOption:      "无效选项，请输入 1-%d\n",
	Selected:           "✅ 已选择: %s\n",
	FailedToDetectIP:   "⚠️  未能自动检测到公网地址",
	EnterPublicAddress: "请输入公网地址 (IP 或域名): ",
	InvalidAddress:     "无效地址: %v，请重试\n",

	// AssignedDomain DNS
	VerifyingDNS:        "\n🔍 正在校验自定义域名 CNAME 解析...",
	AssignedDomainLabel: "   自定义域名: %s",
	ExpectedResolve:     "   期望 CNAME 到: %s",
	DNSCorrect:          "   ✅ DNS 解析正确\n",
	DNSIncorrect:        "\n⚠️  DNS 解析未完成或不正确",
	ErrorLabel:          "   错误: %v",
	DNSRecordGuide:      "\n📋 请手动添加以下 DNS 记录:",
	DNSRecordType:       "   类型: CNAME",
	DNSRecordName:       "   名称: *.%s",
	DNSRecordValue:      "   值:   %s",
	DNSRecordTTL:        "   TTL:  300 (或更短，便于快速生效)",
	SelectOperation:     "\n请选择操作:",
	OptionRetry:         "  [r] 重新检测 DNS",
	OptionSkip:          "  [s] 跳过检测，继续启动",
	OptionQuit:          "  [q] 退出",
	InputPrompt:         "请输入选项 (r/s/q): ",
	SkippingDNS:         "⏭️  跳过 DNS 检测，继续启动...",
	SkipNote:            "   注意: HTTP 通道功能可能无法正常工作，直到 CNAME 解析生效\n",
	UserCancelled:       "用户取消启动",
	InvalidOptionRSQ:    "无效选项，请输入 r、s 或 q\n",
	DNSStillIncorrect:   "⚠️  DNS 仍未正确解析",
	CannotVerifyDNS:     "⚠️  无法校验 CNAME: 未设置 edge baseDomain",

	// Edge server logs
	EdgeServerStarting:            "正在启动 edge server, state: %s",
	EdgeServerStarted:             "edge server 启动成功, state: %s",
	EdgeServerStopping:            "正在停止 edge server...",
	EdgeServerStopped:             "edge server 已停止",
	IPCNodeMarkedOnline:           "通过 IPC 将节点标记为在线",
	IPCNodeMarkedOffline:          "通过 IPC 将节点标记为离线",
	IPCReloadConfigRequested:      "通过 IPC 请求重载配置",
	CertManagerInitialized:        "证书管理器初始化完成, data: %s",
	CheckingCertificateStatus:     "检查证书状态...",
	CertMissingOrExpiredBootstrap: "证书不存在或已过期，需要 Bootstrap",
	CertExpiringSoon:              "证书即将过期，请及时续期, expires_at: %v, expires_in: %v",
	LoadedAssignedDomainFromLocal: "已从本地加载 assigned_domain: %s",
	CertificateReady:              "证书就绪",
	StartingCertificateBootstrap:  "开始执行证书 Bootstrap...",
	ExtractedNodeIDFromCert:       "从证书提取 node_id: %s",
	AppliedAssignedDomain:         "已应用 assigned_domain: %s",
	PersistAssignedDomainFailed:   "持久化 assigned_domain 失败: %v",
	BootstrapCompleted:            "Bootstrap 完成, domain: %s, expires_at: %v",
	InitializingServices:          "正在初始化服务...",
	ServicesInitialized:           "服务初始化完成",
	StartingServices:              "正在启动服务...",
	StartIPCServerFailed:          "启动 IPC 服务失败: %v",
	ServerStateChanged:            "服务状态变更: %s -> %s",
}

var enMessages = Messages{
	// Public Address
	DetectingPublicIP:  "\n🔍 Auto-detecting public IP address...",
	DetectedPublicIPs:  "\nDetected public IP addresses:",
	IPv4Label:          "IPv4",
	IPv6Label:          "IPv6",
	ManualInputOption:  "Enter manually",
	SelectPrompt:       "\nSelect (enter number): ",
	InvalidOption:      "Invalid option, please enter 1-%d\n",
	Selected:           "✅ Selected: %s\n",
	FailedToDetectIP:   "⚠️  Failed to auto-detect public IP",
	EnterPublicAddress: "Enter public address (IP or domain): ",
	InvalidAddress:     "Invalid address: %v, please retry\n",

	// AssignedDomain DNS
	VerifyingDNS:        "\n🔍 Verifying custom-domain CNAME resolution...",
	AssignedDomainLabel: "   Custom Domain: %s",
	ExpectedResolve:     "   Expected CNAME target: %s",
	DNSCorrect:          "   ✅ DNS resolution correct\n",
	DNSIncorrect:        "\n⚠️  DNS resolution incomplete or incorrect",
	ErrorLabel:          "   Error: %v",
	DNSRecordGuide:      "\n📋 Please add the following DNS record manually:",
	DNSRecordType:       "   Type: CNAME",
	DNSRecordName:       "   Name: *.%s",
	DNSRecordValue:      "   Value: %s",
	DNSRecordTTL:        "   TTL:  300 (or shorter for faster propagation)",
	SelectOperation:     "\nSelect operation:",
	OptionRetry:         "  [r] Retry DNS check",
	OptionSkip:          "  [s] Skip and continue",
	OptionQuit:          "  [q] Quit",
	InputPrompt:         "Enter option (r/s/q): ",
	SkippingDNS:         "⏭️  Skipping DNS check, continuing...",
	SkipNote:            "   Note: HTTP channel may not work until CNAME resolves\n",
	UserCancelled:       "User cancelled",
	InvalidOptionRSQ:    "Invalid option, please enter r, s, or q\n",
	DNSStillIncorrect:   "⚠️  DNS still not resolved correctly",
	CannotVerifyDNS:     "⚠️  Cannot verify CNAME: edge baseDomain not set",

	// Edge server logs
	EdgeServerStarting:            "starting edge server, state: %s",
	EdgeServerStarted:             "edge server started successfully, state: %s",
	EdgeServerStopping:            "stopping edge server...",
	EdgeServerStopped:             "edge server stopped",
	IPCNodeMarkedOnline:           "node marked as online via IPC",
	IPCNodeMarkedOffline:          "node marked as offline via IPC",
	IPCReloadConfigRequested:      "reload config requested via IPC",
	CertManagerInitialized:        "certificate manager initialized, data: %s",
	CheckingCertificateStatus:     "checking certificate status...",
	CertMissingOrExpiredBootstrap: "certificate missing or expired, bootstrap required",
	CertExpiringSoon:              "certificate will expire soon, please renew in time, expires_at: %v, expires_in: %v",
	LoadedAssignedDomainFromLocal: "loaded assigned_domain from local: %s",
	CertificateReady:              "certificate ready",
	StartingCertificateBootstrap:  "starting certificate bootstrap...",
	ExtractedNodeIDFromCert:       "extracted node_id from certificate: %s",
	AppliedAssignedDomain:         "applied assigned_domain: %s",
	PersistAssignedDomainFailed:   "failed to persist assigned_domain: %v",
	BootstrapCompleted:            "bootstrap completed, domain: %s,  expires_at: %v",
	InitializingServices:          "initializing services...",
	ServicesInitialized:           "services initialized",
	StartingServices:              "starting services...",
	StartIPCServerFailed:          "start IPC server failed: %v",
	ServerStateChanged:            "server state changed: %s -> %s",
}

// Msg 获取当前语言的消息
func Msg() *Messages {
	if currentLang == LangZH {
		return &zhMessages
	}
	return &enMessages
}
