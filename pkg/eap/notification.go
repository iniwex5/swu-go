package eap

import "fmt"

var akaNotificationCodeTextsIANA = map[uint16]string{
	// RFC 4187 / RFC 9048 / IANA EAP-AKA numbers
	0:     "General failure after authentication (通用认证后失败)",
	1026:  "User has been temporarily denied access (用户被临时拒绝访问)",
	1031:  "User has not subscribed to the requested service (用户未订阅请求的服务)",
	16384: "General failure (通用失败)",
	16385: "Certificate replacement required (需要更换证书)",
	32768: "Success (成功)",
}

var akaNotificationCodeTexts3GPP = map[uint16]string{
	// 3GPP TS 24.302 / TS 23.003 常见扩展通知码
	10500: "APN not subscribed (APN 未签约)",
	10501: "Authorization rejected (授权被拒绝)",
	11000: "Network failure (网络故障)",
	11001: "RAT type not allowed (接入技术类型不允许)",
	11002: "Tracking area not allowed (跟踪区域不允许)",
	11003: "Roaming not allowed (不允许漫游)",
	11004: "Identity cannot be resolved (身份无法解析)",
	11005: "Congestion (网络拥塞)",
	11011: "PLMN not allowed (PLMN 不允许)",
}

// NotificationCodeToString 将 EAP-AKA/AKA' AT_NOTIFICATION 错误码转换为人类可读的描述
// 参考 RFC 4187 §10.1 和 3GPP TS 24.302
func NotificationCodeToString(code uint16) string {
	// 最高位 (S bit): 0 = 认证后阶段, 1 = 认证前阶段
	// 次高位 (P bit): 0 = 需要 EAP Success/Failure, 1 = 纯通知

	if text, ok := akaNotificationCodeTextsIANA[code]; ok {
		return fmt.Sprintf("[IANA] %s", text)
	}
	if text, ok := akaNotificationCodeTexts3GPP[code]; ok {
		return fmt.Sprintf("[3GPP] %s", text)
	}

	// 根据 S/P bit 给出大致分类
	phase := "认证后"
	if code&0x4000 != 0 {
		phase = "认证前"
	}
	action := "需要 Success/Failure 结束"
	if code&0x8000 != 0 {
		action = "纯通知"
	}

	return fmt.Sprintf("未知通知码 %d (阶段: %s, 类型: %s)", code, phase, action)
}

// IsFailureNotificationCode 判断 AT_NOTIFICATION 是否属于失败语义。
// 规则：
// 1) 已知成功码 32768 明确不是失败。
// 2) 已知 IANA/3GPP 码值除 32768 外均按失败处理。
// 3) 未知码按 P bit 推断：P=1(纯通知) 视作非失败；P=0 视作失败。
func IsFailureNotificationCode(code uint16) bool {
	if code == 32768 {
		return false
	}
	if _, ok := akaNotificationCodeTextsIANA[code]; ok {
		return true
	}
	if _, ok := akaNotificationCodeTexts3GPP[code]; ok {
		return true
	}
	return (code & 0x8000) == 0
}
