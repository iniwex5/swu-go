# swu-go

纯 Go 实现的 SWu 客户端库，用于 VoWiFi 建立到 ePDG (Evolved Packet Data Gateway) 的 IPSec 隧道。

## 功能特性

- **IKEv2 协议** — 完整实现 IKE_SA_INIT、IKE_AUTH、CREATE_CHILD_SA
- **EAP-AKA 认证** — 支持 SIM/USIM 卡认证
- **双数据平面**
  - **XFRMI 模式** — 内核态 XFRM Interface（linux下推荐，性能更优）
  - **TUN 模式** — 用户态 ESP 加解密（AES-CBC + HMAC-SHA1）
- **XFRM 管理** — SA/SP 安装、`AF_UNSPEC` 跨族匹配、策略路由
- **网络配置** — 自动接口配置、策略路由、冲突路由清理、sysctl 管理
- **IPv4/IPv6** — 双栈支持
- **网络命名空间** — 可选的隔离网络环境

## 安装

```bash
go get github.com/iniwex5/swu-go
```

## 依赖

- Go 1.24+
- Linux（需要 XFRM / TUN/TAP / Netlink 支持）
- Root 权限（网络配置需要）
- [github.com/iniwex5/netlink](https://github.com/iniwex5/netlink) — vishvananda/netlink 的 fork，增加了 `XFRM_STATE_AF_UNSPEC` 支持

## 使用示例

```go
package main

import (
    "github.com/iniwex5/swu-go/pkg/swu"
    "github.com/iniwex5/swu-go/pkg/sim"
)

func main() {
    // 创建 SIM 卡提供者
    simProvider := sim.NewATModem("/dev/ttyUSB2")

    // 配置 SWu 会话
    cfg := &swu.Config{
        EPDGAddress:   "epdg.example.com:500",
        IMSI:          "123456789012345",
        SIM:           simProvider,
        DataPlaneMode: "xfrmi",       // "xfrmi" 或 "tun"
        XFRMIfName:    "ims0",
    }

    // 创建并启动会话
    session := swu.NewSession(cfg, nil)
    defer session.Shutdown()

    // 连接到 ePDG
    if err := session.Connect(ctx); err != nil {
        panic(err)
    }

    // 会话建立后，XFRM 接口已配置完成
    // 可以通过 ims0 接口访问 IMS 网络

    // 优雅关闭时等待清理完成
    session.WaitDone()
}
```

## 项目结构

```
pkg/
├── crypto/     # 加密算法 (AES, HMAC, DH, PRF)
├── driver/     # 系统驱动
│   ├── nettools.go   # 网络配置 (netlink API)
│   ├── xfrm.go       # XFRM SA/SP/Interface 管理
│   ├── netns.go       # 网络命名空间
│   └── tun.go         # TUN 设备
├── eap/        # EAP 协议编解码
├── ikev2/      # IKEv2 协议
├── ipsec/      # ESP 数据平面与 Socket 管理
├── logger/     # 日志封装 (zap)
├── sim/        # SIM 卡接口 (AT 命令)
└── swu/        # SWu 会话管理
    ├── session.go          # 核心会话逻辑
    ├── config.go           # 配置结构体
    ├── state_*.go          # IKE 状态机
    └── informational.go    # IKE Informational 交换
```

## 许可证

MIT License
