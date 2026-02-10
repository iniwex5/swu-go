# swu-go

纯 Go 实现的 SWu 客户端库，主要用于vowifi建立到 ePDG (Evolved Packet Data Gateway) 的 IPSec 隧道。

## 功能特性

- **IKEv2 协议** — 完整实现 IKE_SA_INIT、IKE_AUTH、CREATE_CHILD_SA
- **EAP-AKA 认证** — 支持 SIM/USIM 卡认证
- **ESP 数据平面** — 用户态 ESP 加解密（AES-CBC + HMAC-SHA1）
- **TUN 设备** — 自动配置 TUN 接口、路由和地址
- **IPv4/IPv6** — 双栈支持
- **网络命名空间** — 可选的隔离网络环境

## 安装

```bash
go get github.com/iniwex5/swu-go
```

## 依赖

- Linux (需要 TUN/TAP 和 Netlink 支持)
- Root 权限 (网络配置需要)

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
    cfg := swu.Config{
        EPDGAddress: "epdg.example.com:500",
        IMSI:        "123456789012345",
        SIM:         simProvider,
        TUNName:     "ims0",
    }
    
    // 创建并启动会话
    session, err := swu.NewSession(cfg)
    if err != nil {
        panic(err)
    }
    defer session.Close()
    
    // 会话建立后，TUN 设备已配置完成
    // 可以通过 ims0 接口访问 IMS 网络
}
```

## 项目结构

```
pkg/
├── crypto/     # 加密算法 (AES, HMAC, DH, PRF)
├── driver/     # 系统驱动 (TUN, Netlink, NetNS)
├── eap/        # EAP 协议编解码
├── ikev2/      # IKEv2 协议
├── ipsec/      # ESP 数据平面
├── logger/     # 日志封装
├── sim/        # SIM 卡接口
└── swu/        # SWu 会话管理
```

## 许可证

MIT License
