package driver

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// NetTools 封装网络配置操作（使用 vishvananda/netlink）
type NetTools struct{}

// NewNetTools 创建 NetTools 实例
func NewNetTools() *NetTools {
	return &NetTools{}
}

// NetToolError 封装网络操作错误
type NetToolError struct {
	Op   string // 操作描述
	Args string // 参数信息
	Err  error  // 底层错误
}

func (e *NetToolError) Error() string {
	if e.Args == "" {
		return fmt.Sprintf("%s 失败: %v", e.Op, e.Err)
	}
	return fmt.Sprintf("%s %s 失败: %v", e.Op, e.Args, e.Err)
}

func (e *NetToolError) Unwrap() error { return e.Err }

// wrapErr 封装错误
func wrapErr(op, args string, err error) error {
	if err == nil {
		return nil
	}
	return &NetToolError{Op: op, Args: args, Err: err}
}

// getLink 根据接口名获取 Link 对象
func getLink(iface string) (netlink.Link, error) {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return nil, fmt.Errorf("获取接口 %s 失败: %v", iface, err)
	}
	return link, nil
}

// SetLinkUp 启用网络接口
func (n *NetTools) SetLinkUp(iface string) error {
	link, err := getLink(iface)
	if err != nil {
		return wrapErr("link set up", iface, err)
	}
	return wrapErr("link set up", iface, netlink.LinkSetUp(link))
}

// SetLinkDown 禁用网络接口
func (n *NetTools) SetLinkDown(iface string) error {
	link, err := getLink(iface)
	if err != nil {
		return wrapErr("link set down", iface, err)
	}
	return wrapErr("link set down", iface, netlink.LinkSetDown(link))
}

// DeleteLink 删除网络设备（如 TUN）
func (n *NetTools) DeleteLink(iface string) error {
	link, err := getLink(iface)
	if err != nil {
		return wrapErr("link del", iface, err)
	}
	return wrapErr("link del", iface, netlink.LinkDel(link))
}

// SetMTU 设置接口 MTU
func (n *NetTools) SetMTU(iface string, mtu int) error {
	link, err := getLink(iface)
	if err != nil {
		return wrapErr("link set mtu", fmt.Sprintf("%s %d", iface, mtu), err)
	}
	return wrapErr("link set mtu", fmt.Sprintf("%s %d", iface, mtu), netlink.LinkSetMTU(link, mtu))
}

// AddAddress 添加 IPv4 地址（例如 "10.0.0.1/24"）
func (n *NetTools) AddAddress(iface string, cidr string) error {
	link, err := getLink(iface)
	if err != nil {
		return wrapErr("addr add", fmt.Sprintf("%s dev %s", cidr, iface), err)
	}

	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		return wrapErr("addr add", fmt.Sprintf("%s dev %s", cidr, iface), fmt.Errorf("解析地址失败: %v", err))
	}

	return wrapErr("addr add", fmt.Sprintf("%s dev %s", cidr, iface), netlink.AddrAdd(link, addr))
}

// DelAddress 删除 IPv4 地址
func (n *NetTools) DelAddress(iface string, cidr string) error {
	link, err := getLink(iface)
	if err != nil {
		return wrapErr("addr del", fmt.Sprintf("%s dev %s", cidr, iface), err)
	}

	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		return wrapErr("addr del", fmt.Sprintf("%s dev %s", cidr, iface), fmt.Errorf("解析地址失败: %v", err))
	}

	return wrapErr("addr del", fmt.Sprintf("%s dev %s", cidr, iface), netlink.AddrDel(link, addr))
}

// AddAddress6 添加 IPv6 地址（例如 "2001:db8::1/64"），带重试机制
func (n *NetTools) AddAddress6(iface string, cidr string) error {
	link, err := getLink(iface)
	if err != nil {
		return wrapErr("addr add -6", fmt.Sprintf("%s dev %s", cidr, iface), err)
	}

	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		return wrapErr("addr add -6", fmt.Sprintf("%s dev %s", cidr, iface), fmt.Errorf("解析地址失败: %v", err))
	}

	// 设置 nodad 标志（禁用 DAD）
	addr.Flags = addr.Flags | unix.IFA_F_NODAD

	// 重试机制：设备刚创建时可能需要等待
	var lastErr error
	for i := 0; i < 5; i++ {
		err = netlink.AddrAdd(link, addr)
		if err == nil {
			return nil
		}
		lastErr = err
		// 如果是 Invalid argument 错误，等待后重试
		if i < 4 {
			time.Sleep(80 * time.Millisecond)
		}
	}
	return wrapErr("addr add -6", fmt.Sprintf("%s dev %s", cidr, iface), lastErr)
}

// DelAddress6 删除 IPv6 地址
func (n *NetTools) DelAddress6(iface string, cidr string) error {
	return n.DelAddress(iface, cidr)
}

// AddRoute 添加 IPv4 路由
func (n *NetTools) AddRoute(cidr string, gw string, iface string) error {
	_, dst, err := net.ParseCIDR(cidr)
	if err != nil {
		return wrapErr("route add", cidr, fmt.Errorf("解析目标地址失败: %v", err))
	}

	route := &netlink.Route{
		Dst: dst,
	}

	// 设置网关
	if gw != "" {
		route.Gw = net.ParseIP(gw)
		if route.Gw == nil {
			return wrapErr("route add", cidr, fmt.Errorf("无效的网关地址: %s", gw))
		}
	}

	// 设置设备
	if iface != "" {
		link, err := getLink(iface)
		if err != nil {
			return wrapErr("route add", cidr, err)
		}
		route.LinkIndex = link.Attrs().Index
	}
	// 忽略路由已存在错误（多设备可能共享 P-CSCF 等目标地址）
	err = netlink.RouteAdd(route)
	if err != nil && isRouteExists(err) {
		return nil
	}
	return wrapErr("route add", cidr, err)
}

// DelRoute 删除 IPv4 路由
func (n *NetTools) DelRoute(cidr string, gw string, iface string) error {
	_, dst, err := net.ParseCIDR(cidr)
	if err != nil {
		return wrapErr("route del", cidr, fmt.Errorf("解析目标地址失败: %v", err))
	}

	route := &netlink.Route{
		Dst: dst,
	}

	if gw != "" {
		route.Gw = net.ParseIP(gw)
	}

	if iface != "" {
		link, err := getLink(iface)
		if err != nil {
			return wrapErr("route del", cidr, err)
		}
		route.LinkIndex = link.Attrs().Index
	}
	// 忽略路由不存在错误（可能已被其他设备会话删除）
	err = netlink.RouteDel(route)
	if err != nil && isRouteNotFound(err) {
		return nil
	}
	return wrapErr("route del", cidr, err)
}

// AddRoute6 添加 IPv6 路由
func (n *NetTools) AddRoute6(cidr string, gw string, iface string) error {
	return n.AddRoute(cidr, gw, iface)
}

// DelRoute6 删除 IPv6 路由
func (n *NetTools) DelRoute6(cidr string, gw string, iface string) error {
	return n.DelRoute(cidr, gw, iface)
}

// isRouteExists 判断是否为路由已存在错误 (EEXIST)
func isRouteExists(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == syscall.EEXIST
	}
	return false
}

// isRouteNotFound 判断是否为路由不存在错误 (ESRCH)
func isRouteNotFound(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == syscall.ESRCH
	}
	return false
}
