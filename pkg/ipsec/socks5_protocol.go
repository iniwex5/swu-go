// Socks5 协议层实现 (RFC 1928 / RFC 1929)
// 包含握手鉴权、UDP Associate 请求/响应、UDP Datagram Header 封装解封装
package ipsec

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

// Socks5 版本及命令常量
const (
	socks5Version = 0x05

	// 鉴权方法
	socks5AuthNone         = 0x00
	socks5AuthUserPassword = 0x02
	socks5AuthNoAcceptable = 0xFF

	// 鉴权子协商版本 (RFC 1929)
	socks5UserPassVersion = 0x01

	// 命令
	socks5CmdConnect      = 0x01
	socks5CmdBind         = 0x02
	socks5CmdUDPAssociate = 0x03

	// 地址类型
	socks5AtypIPv4   = 0x01
	socks5AtypDomain = 0x03
	socks5AtypIPv6   = 0x04

	// 回复状态
	socks5ReplySuccess             = 0x00
	socks5ReplyGeneralFailure      = 0x01
	socks5ReplyNetworkUnreachable  = 0x03
	socks5ReplyHostUnreachable     = 0x04
	socks5ReplyCommandNotSupported = 0x07
	socks5ReplyAddrNotSupported    = 0x08
)

// Socks5Credential 表示 Socks5 鉴权凭据
type Socks5Credential struct {
	Username string
	Password string
}

// socks5Handshake 完成 Socks5 版本协商及鉴权
// 如果 cred 非空则尝试 USERNAME/PASSWORD 鉴权，否则使用 NOAUTH
func socks5Handshake(conn io.ReadWriter, cred *Socks5Credential) error {
	// 构造支持的鉴权方法列表
	var methods []byte
	if cred != nil && cred.Username != "" {
		methods = []byte{socks5AuthUserPassword, socks5AuthNone}
	} else {
		methods = []byte{socks5AuthNone}
	}

	// 发送版本协商请求：VER | NMETHODS | METHODS
	req := make([]byte, 2+len(methods))
	req[0] = socks5Version
	req[1] = byte(len(methods))
	copy(req[2:], methods)
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socks5 握手发送失败: %w", err)
	}

	// 读取响应：VER | METHOD
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("socks5 握手响应读取失败: %w", err)
	}
	if resp[0] != socks5Version {
		return fmt.Errorf("socks5 版本不匹配: 期望 0x05, 实际 0x%02x", resp[0])
	}
	selectedMethod := resp[1]

	switch selectedMethod {
	case socks5AuthNone:
		// 无需鉴权
		return nil
	case socks5AuthUserPassword:
		if cred == nil || cred.Username == "" {
			return errors.New("socks5 服务器要求用户名密码鉴权但未提供凭据")
		}
		return socks5UserPasswordAuth(conn, cred)
	case socks5AuthNoAcceptable:
		return errors.New("socks5 服务器拒绝了所有鉴权方法 (0xFF)")
	default:
		return fmt.Errorf("socks5 服务器选择了不支持的鉴权方法: 0x%02x", selectedMethod)
	}
}

// socks5UserPasswordAuth 执行 RFC 1929 用户名/密码子协商
func socks5UserPasswordAuth(conn io.ReadWriter, cred *Socks5Credential) error {
	uLen := len(cred.Username)
	pLen := len(cred.Password)
	if uLen > 255 || pLen > 255 {
		return errors.New("socks5 用户名或密码过长 (>255 字节)")
	}

	// VER | ULEN | UNAME | PLEN | PASSWD
	req := make([]byte, 1+1+uLen+1+pLen)
	req[0] = socks5UserPassVersion
	req[1] = byte(uLen)
	copy(req[2:2+uLen], cred.Username)
	req[2+uLen] = byte(pLen)
	copy(req[3+uLen:], cred.Password)

	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socks5 鉴权请求发送失败: %w", err)
	}

	// 读取回复：VER | STATUS
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("socks5 鉴权响应读取失败: %w", err)
	}
	if resp[1] != 0x00 {
		return fmt.Errorf("socks5 鉴权失败: 状态码 0x%02x", resp[1])
	}
	return nil
}

// socks5UDPAssociate 发送 UDP ASSOCIATE 请求并返回服务器分配的 Relay 地址
// clientAddr 是客户端期望使用的 UDP 地址（通常为 0.0.0.0:0 表示由服务器分配）
func socks5UDPAssociate(conn io.ReadWriter, clientAddr *net.UDPAddr) (*net.UDPAddr, error) {
	if clientAddr == nil {
		clientAddr = &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	}

	// 构造请求：VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT
	req := buildSocks5Request(socks5CmdUDPAssociate, clientAddr.IP, uint16(clientAddr.Port))
	if _, err := conn.Write(req); err != nil {
		return nil, fmt.Errorf("socks5 UDP ASSOCIATE 请求发送失败: %w", err)
	}

	// 解析响应
	bindAddr, err := readSocks5Reply(conn)
	if err != nil {
		return nil, fmt.Errorf("socks5 UDP ASSOCIATE 响应解析失败: %w", err)
	}
	return bindAddr, nil
}

// buildSocks5Request 构造 Socks5 请求报文
func buildSocks5Request(cmd byte, ip net.IP, port uint16) []byte {
	// VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT
	var buf []byte
	if v4 := ip.To4(); v4 != nil {
		buf = make([]byte, 4+4+2) // header(4) + IPv4(4) + port(2)
		buf[0] = socks5Version
		buf[1] = cmd
		buf[2] = 0x00 // RSV
		buf[3] = socks5AtypIPv4
		copy(buf[4:8], v4)
		binary.BigEndian.PutUint16(buf[8:10], port)
	} else if v6 := ip.To16(); v6 != nil {
		buf = make([]byte, 4+16+2) // header(4) + IPv6(16) + port(2)
		buf[0] = socks5Version
		buf[1] = cmd
		buf[2] = 0x00 // RSV
		buf[3] = socks5AtypIPv6
		copy(buf[4:20], v6)
		binary.BigEndian.PutUint16(buf[20:22], port)
	} else {
		// 回退到 IPv4 zero
		buf = make([]byte, 4+4+2)
		buf[0] = socks5Version
		buf[1] = cmd
		buf[2] = 0x00
		buf[3] = socks5AtypIPv4
		binary.BigEndian.PutUint16(buf[8:10], port)
	}
	return buf
}

// readSocks5Reply 解析 Socks5 服务器的回复，返回绑定地址
func readSocks5Reply(r io.Reader) (*net.UDPAddr, error) {
	// 读取: VER | REP | RSV | ATYP
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("读取响应头失败: %w", err)
	}
	if header[0] != socks5Version {
		return nil, fmt.Errorf("版本不匹配: 0x%02x", header[0])
	}
	if header[1] != socks5ReplySuccess {
		return nil, fmt.Errorf("socks5 请求被拒绝: 状态码 0x%02x (%s)", header[1], socks5ReplyString(header[1]))
	}

	// 读取 BND.ADDR
	var ip net.IP
	switch header[3] {
	case socks5AtypIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(r, addr); err != nil {
			return nil, fmt.Errorf("读取 IPv4 地址失败: %w", err)
		}
		ip = net.IP(addr)
	case socks5AtypIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(r, addr); err != nil {
			return nil, fmt.Errorf("读取 IPv6 地址失败: %w", err)
		}
		ip = net.IP(addr)
	case socks5AtypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			return nil, fmt.Errorf("读取域名长度失败: %w", err)
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(r, domain); err != nil {
			return nil, fmt.Errorf("读取域名失败: %w", err)
		}
		resolved, err := net.ResolveIPAddr("ip", string(domain))
		if err != nil {
			return nil, fmt.Errorf("解析域名 %s 失败: %w", string(domain), err)
		}
		ip = resolved.IP
	default:
		return nil, fmt.Errorf("未知地址类型: 0x%02x", header[3])
	}

	// 读取 BND.PORT
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, portBuf); err != nil {
		return nil, fmt.Errorf("读取端口失败: %w", err)
	}
	port := binary.BigEndian.Uint16(portBuf)

	return &net.UDPAddr{IP: ip, Port: int(port)}, nil
}

// ── UDP Datagram Header 封装/解封装 ──

// socks5UDPHeaderSize 计算给定目标地址的 Socks5 UDP Header 大小
// Header 格式: RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR(variable) + DST.PORT(2)
func socks5UDPHeaderSize(ip net.IP) int {
	if v4 := ip.To4(); v4 != nil {
		return 2 + 1 + 1 + 4 + 2 // 10 字节
	}
	return 2 + 1 + 1 + 16 + 2 // 22 字节
}

// Socks5UDPDatagram 表示一个 Socks5 UDP 数据报
type Socks5UDPDatagram struct {
	Frag    byte       // 分片号（0 = 不分片）
	DstAddr *net.UDPAddr // 目标地址
	Data    []byte     // 负载数据
}

// EncodeSocks5UDPDatagram 将 UDP 数据报编码为 Socks5 UDP Datagram
// 格式: RSV(2) | FRAG(1) | ATYP(1) | DST.ADDR | DST.PORT(2) | DATA
func EncodeSocks5UDPDatagram(dst *net.UDPAddr, data []byte) []byte {
	ip := dst.IP
	port := uint16(dst.Port)

	var headerLen int
	var atyp byte
	var addrBytes []byte

	if v4 := ip.To4(); v4 != nil {
		headerLen = 10
		atyp = socks5AtypIPv4
		addrBytes = v4
	} else if v6 := ip.To16(); v6 != nil {
		headerLen = 22
		atyp = socks5AtypIPv6
		addrBytes = v6
	} else {
		// 回退用 IPv4 zero
		headerLen = 10
		atyp = socks5AtypIPv4
		addrBytes = net.IPv4zero.To4()
	}

	buf := make([]byte, headerLen+len(data))
	// RSV = 0x0000
	buf[0] = 0
	buf[1] = 0
	// FRAG = 0
	buf[2] = 0
	// ATYP
	buf[3] = atyp
	copy(buf[4:4+len(addrBytes)], addrBytes)
	binary.BigEndian.PutUint16(buf[4+len(addrBytes):], port)
	copy(buf[headerLen:], data)
	return buf
}

// DecodeSocks5UDPDatagram 从原始字节解码 Socks5 UDP Datagram
func DecodeSocks5UDPDatagram(raw []byte) (*Socks5UDPDatagram, error) {
	if len(raw) < 4 {
		return nil, errors.New("socks5 UDP datagram 过短 (<4)")
	}

	frag := raw[2]
	atyp := raw[3]

	var ip net.IP
	var addrEnd int

	switch atyp {
	case socks5AtypIPv4:
		if len(raw) < 10 {
			return nil, errors.New("socks5 UDP datagram IPv4 过短")
		}
		ip = net.IP(raw[4:8])
		addrEnd = 8
	case socks5AtypIPv6:
		if len(raw) < 22 {
			return nil, errors.New("socks5 UDP datagram IPv6 过短")
		}
		ip = net.IP(raw[4:20])
		addrEnd = 20
	case socks5AtypDomain:
		if len(raw) < 5 {
			return nil, errors.New("socks5 UDP datagram 域名长度缺失")
		}
		domainLen := int(raw[4])
		if len(raw) < 5+domainLen+2 {
			return nil, errors.New("socks5 UDP datagram 域名数据不足")
		}
		domain := string(raw[5 : 5+domainLen])
		resolved, err := net.ResolveIPAddr("ip", domain)
		if err != nil {
			return nil, fmt.Errorf("解析域名 %s 失败: %w", domain, err)
		}
		ip = resolved.IP
		addrEnd = 5 + domainLen
	default:
		return nil, fmt.Errorf("未知 ATYP: 0x%02x", atyp)
	}

	if len(raw) < addrEnd+2 {
		return nil, errors.New("socks5 UDP datagram 端口数据不足")
	}
	port := binary.BigEndian.Uint16(raw[addrEnd : addrEnd+2])
	dataStart := addrEnd + 2

	return &Socks5UDPDatagram{
		Frag:    frag,
		DstAddr: &net.UDPAddr{IP: ip, Port: int(port)},
		Data:    raw[dataStart:],
	}, nil
}

// socks5ReplyString 将 Socks5 回复状态码转换为可读字符串
func socks5ReplyString(code byte) string {
	switch code {
	case socks5ReplySuccess:
		return "success"
	case socks5ReplyGeneralFailure:
		return "general failure"
	case socks5ReplyNetworkUnreachable:
		return "network unreachable"
	case socks5ReplyHostUnreachable:
		return "host unreachable"
	case socks5ReplyCommandNotSupported:
		return "command not supported"
	case socks5ReplyAddrNotSupported:
		return "address type not supported"
	default:
		return fmt.Sprintf("unknown(0x%02x)", code)
	}
}

// parseSocks5Addr 解析 "host:port" 格式的 Socks5 服务器地址
func parseSocks5Addr(addr string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		// 尝试不带端口的情况，使用默认端口 1080
		if !strings.Contains(addr, ":") {
			return addr, 1080, nil
		}
		return "", 0, fmt.Errorf("无效的 socks5 地址: %s: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("无效的端口号: %s", portStr)
	}
	return host, port, nil
}
