package eap

import "fmt"

// NotificationCodeToString 将 EAP-AKA/AKA' AT_NOTIFICATION 错误码转换为人类可读的描述
// 参考 RFC 4187 §10.1 和 3GPP TS 24.302
func NotificationCodeToString(code uint16) string {
	// 最高位 (S bit): 0 = 认证后阶段, 1 = 认证前阶段
	// 次高位 (P bit): 0 = 需要 EAP Success/Failure, 1 = 纯通知

	switch code {
	// RFC 4187 定义的通知码
	case 0:
		return "General failure after authentication (通用认证后失败)"
	case 1026:
		return "User has been temporarily denied access (用户被临时拒绝访问)"
	case 1031:
		return "User has not subscribed to the requested service (用户未订阅请求的服务)"
	case 16384:
		return "General failure (通用失败)"
	case 32768:
		return "Success (成功)"

	// 3GPP TS 24.302 / TS 23.003 定义的扩展通知码
	case 10500:
		return "APN not subscribed (APN 未签约)"
	case 10501:
		return "Authorization rejected (授权被拒绝)"
	case 11000:
		return "Network failure (网络故障)"
	case 11001:
		return "RAT type not allowed (接入技术类型不允许)"
	case 11002:
		return "Tracking area not allowed (跟踪区域不允许)"
	case 11003:
		return "Roaming not allowed (不允许漫游)"
	case 11004:
		return "Identity cannot be resolved (身份无法解析)"
	case 11005:
		return "Congestion (网络拥塞)"
	case 11011:
		return "PLMN not allowed (PLMN 不允许)"
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
