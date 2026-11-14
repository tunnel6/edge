# Edge Service | Edge 服务

[English](#english) | [中文](#chinese)

---

<a name="english"></a>
## English

### Overview

Edge is the edge node service in the Yat tunnel system. It serves as a standalone edge node providing:

- **Certificate Bootstrap**: Local self-signed CA generation and certificate management
- **mTLS Communication**: Mutual TLS authentication for secure client connections  
- **Client Certificate Signing**: Sign client certificates as Edge Sub-CA
- **Tunnel Management**: Handle client sessions and channel creation

### Tunnel Coordination and Actor Context (New)

Edge now acts as the authoritative tunnel coordinator for subscribed clients under the same account.

- **Edge-sourced tunnel sync**: tunnel definitions are synced from Edge (`TUNNEL_SYNC_*`, `TUNNEL_EVENT_PUSH`).
- **Actor-aware channel state**: `ChannelInfo` now carries business actor fields:
  - `actor_role` (`publisher` / `consumer` / `controller`)
  - `actor_session_id`
  - `actor_device_id`
- **Actor-aware tunnel metadata**: `TunnelDefinitionInfo` persists and syncs:
  - `actor_role`
  - `actor_session_id`
  - `actor_device_id`
- **Strict semantics**:
  - Transport identity (`session_id` / `device_id`) stays at mTLS/session layer.
  - Actor identity (`actor_*`) represents business intent and is propagated to protocol + store + status.

### Architecture

```
┌─────────┐                    ┌──────────┐
│  yat-fe │ ◄───── mTLS ─────► │   Edge   │
└─────────┘                    └──────────┘
     │                              │
     │  1. Request Cert             │
     │ ────────────────────────────►│
     │                              │
     │  2. Local Edge CA Signs      │
     │                              │
     │  3. Return Cert              │
     │ ◄────────────────────────────│
     │                              │
     │  4. mTLS Connection          │
     │ ════════════════════════════►│
```

### Certificate Chain

```
Edge Root CA (self-signed, local)
    └── Edge Sub-CA
            └── Edge TLS Certificate (server cert for tunnel)
            └── Client Certificate (yat-fe)
```

### Module Structure

```
edge/
├── cmd/                 # CLI commands
├── internal/
│   ├── server/          # Edge server core
│   ├── upstream/
│   │   ├── certmgr/     # Certificate management (local self-signed CA)
│   │   └── controller/  # Controller interface (no-op in standalone mode)
│   ├── tunnel/          # Tunnel server
│   └── channel/         # Channel management
├── pkg/                 # Shared packages
└── scripts/             # Deployment scripts
```
│   ├── session.go       # Session management
│   └── protocol.go      # FlatBuffers protocol handler
├── channel/             # Channel management (HTTP/TCP/WireGuard)
├── config/              # Configuration
└── cmd/                 # CLI commands
```

### Certificate Bootstrap

Edge uses local self-signed CA for certificate generation:

1. Edge generates local Root CA on first start
2. Edge Sub-CA is created for signing client certificates
3. TLS certificates are saved locally

```bash
# Start Edge
./edge server
```

#### Certificate Re-issuance

**Scenario**: Edge certificates are lost or corrupted, need to regenerate.

**Solution**: Delete old certificates and restart Edge:

```bash
# Delete old certificates
rm -rf ./certs/*

# Restart Edge - new certificates will be generated
./edge server
```

### Client Certificate Signing

Edge uses **Local Signing Mode** (EdgeCA) for signing client certificates.

Edge generates and manages its own CA hierarchy locally:

```go
// EdgeCA signs client CSR locally
signedCert, err := edgeCA.SignClientCSR(csrPEM, userID, deviceID, validity)
```

**Certificate CN Format**: `user_{userID}_device_{deviceID}`

### Hybrid TLS/mTLS Security Model

**Problem**: How to support initial certificate request (no client cert) while enforcing mTLS for business operations?

**Solution**: Application-layer protocol differentiation

#### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Edge Tunnel Server                       │
├─────────────────────────────────────────────────────────────┤
│  TLS Layer: RequestClientCert (Optional client cert)        │
├─────────────────────────────────────────────────────────────┤
│  Application Layer:                                          │
│  ┌──────────────────────┬──────────────────────────────┐   │
│  │  No Client Cert      │  Has Client Cert (mTLS)      │   │
│  ├──────────────────────┼──────────────────────────────┤   │
│  │  Allows:             │  Allows:                      │   │
│  │  - CERT_REQUEST      │  - AUTH_REQUEST              │   │
│  │    (cert signing)    │  - TUNNEL_START_REQUEST      │   │
│  │                      │  - TUNNEL_STOP_REQUEST       │   │
│  │  Rejects:            │  - DATA_PACKET               │   │
│  │  - All other ops     │  - All business operations   │   │
│  └──────────────────────┴──────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

#### TLS Configuration

```go
tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{cert},
    ClientCAs:    caCertPool,
    ClientAuth:   tls.RequestClientCert,  // Optional client cert
    MinVersion:   tls.VersionTLS12,
    VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
        // If no client cert, skip verification (cert request allowed)
        if len(rawCerts) == 0 {
            return nil
        }
        // If has client cert, verify EKU and certificate chain
        clientCert, _ := x509.ParseCertificate(rawCerts[0])
        // 1. Verify EKU contains clientAuth
        // 2. Verify chain: Client -> Edge Sub-CA -> Root CA
        return verifyClientCert(clientCert, caCertPool, interPool)
    },
}
```

#### Connection Handling

```go
func (s *Server) handleConnection(conn net.Conn) {
    tlsConn := conn.(*tls.Conn)
    
    // Extract user info from client certificate
    userID, deviceID, err := extractUserInfo(tlsConn)
    if err == ErrNoClientCertificate {
        // No cert: Only allow CERT_REQUEST
        s.handleCertRequestOnly(tlsConn)
        return
    }
    
    // Has cert: Full mTLS session with all operations
    s.handleAuthenticatedSession(tlsConn, userID, deviceID)
}
```

#### Security Benefits

- ✅ Business operations require mTLS (strict authentication)
- ✅ Initial certificate request works without cert (cold start)
- ✅ Single port, simple configuration
- ✅ Application-layer access control
- ✅ Clear separation of authenticated/unauthenticated paths

### Configuration Example

```yaml
# config.yaml
node:
  id: ""  # Auto-generated

tunnel:
  listen: ":8443"
  tls:
    enabled: true
    cert: "./certs/edge-tls.crt"
    key: "./certs/edge-tls.key"
    ca: "./certs/root-ca.crt"
```

### Key Components

| Component | Description |
|-----------|-------------|
| `EdgeCA` | Local certificate authority for signing client certs |
| `CertCache` | Cache signed certificates with TTL and revocation support |
| `Bootstrap` | Local self-signed CA generation |

---

<a name="chinese"></a>
## 中文

### 概述

Edge 是 Yat 隧道系统中的边缘节点服务。作为独立运行的边缘节点，提供：

- **证书引导**: 本地自签名 CA 生成和证书管理
- **mTLS 通信**: 双向 TLS 认证确保客户端连接安全
- **客户端证书签发**: 作为 Edge 子 CA 签发客户端证书
- **隧道管理**: 处理客户端会话和通道创建

### Tunnel 协调与 Actor 上下文（新增）

Edge 现在作为同账号多端的隧道协调中心，为已订阅客户端提供统一的 tunnel 状态与变更流。

- **Edge 源同步**: tunnel 定义通过 Edge 的 `TUNNEL_SYNC_*` 与 `TUNNEL_EVENT_PUSH` 同步。
- **带 Actor 的通道状态**: `ChannelInfo` 增加业务字段：
  - `actor_role`（`publisher` / `consumer` / `controller`）
  - `actor_session_id`
  - `actor_device_id`
- **带 Actor 的 tunnel 元数据**: `TunnelDefinitionInfo` 持久化并同步：
  - `actor_role`
  - `actor_session_id`
  - `actor_device_id`
- **语义分层保持严格一致**:
  - `session_id` / `device_id` 仍表示 mTLS/连接层身份。
  - `actor_*` 表示业务动作身份，并透传到协议面、状态面和存储面。

### 架构

```
┌─────────┐                    ┌──────────┐
│  yat-fe │ ◄───── mTLS ─────► │   Edge   │
└─────────┘                    └──────────┘
     │                              │
     │  1. 申请证书                 │
     │ ────────────────────────────►│
     │                              │
     │  2. 本地 Edge CA 签发        │
     │                              │
     │  3. 返回证书                 │
     │ ◄────────────────────────────│
     │                              │
     │  4. mTLS 连接                │
     │ ════════════════════════════►│
```

### 证书链

```
Edge Root CA（本地自签名）
    └── Edge Sub-CA（Edge 子 CA）
            └── Edge TLS 证书（隈道服务器证书）
            └── 客户端证书（yat-fe）
```

### 模块结构

```
edge/
├── cmd/                 # CLI 命令
├── internal/
│   ├── server/          # Edge 服务器核心
│   ├── upstream/
│   │   ├── certmgr/     # 证书管理（本地自签名 CA）
│   │   └── controller/  # 控制器接口（独立模式下为空实现）
│   ├── tunnel/          # 隈道服务器
│   └── channel/         # 通道管理
├── pkg/                 # 共享包
└── scripts/             # 部署脚本
```

### 证书引导流程

Edge 使用本地自签名 CA 生成证书：

1. Edge 首次启动时生成本地 Root CA
2. 创建 Edge Sub-CA 用于签发客户端证书
3. TLS 证书保存到本地

```bash
# 启动 Edge
./edge server
```

#### 证书重新签发

**场景**：Edge 证书丢失或损坏，需要重新生成。

**解决方案**：删除旧证书并重启 Edge：

```bash
# 删除旧证书
rm -rf ./certs/*

# 重启 Edge - 将生成新证书
./edge server
```

### 客户端证书签发

Edge 使用**本地签发模式**（EdgeCA）签发客户端证书。

Edge 在本地生成和管理自己的 CA 层级：

```go
// EdgeCA 在本地签发客户端证书
signedCert, err := edgeCA.SignClientCSR(csrPEM, userID, deviceID, validity)
```

**证书 CN 格式**：
- SaaS 模式：`user_{userID}_device_{deviceID}`
- OSS 模式：`device_{deviceID}`（device-only 证书，无 user ID）

### TLS/mTLS 混合安全模型

**问题**：如何支持首次证书申请（无客户端证书）的同时，对业务操作强制 mTLS 认证？

**解决方案**：应用层协议区分

#### 架构设计

```
┌─────────────────────────────────────────────────────────────┐
│                     Edge Tunnel 服务器                    │
├─────────────────────────────────────────────────────────────┤
│  TLS 层：RequestClientCert（可选客户端证书）          │
├─────────────────────────────────────────────────────────────┤
│  应用层：                                               │
│  ┌──────────────────────┬──────────────────────────────┐   │
│  │  无客户端证书        │  有客户端证书（mTLS）        │   │
│  ├──────────────────────┼──────────────────────────────┤   │
│  │  允许：               │  允许：                        │   │
│  │  - CERT_REQUEST      │  - AUTH_REQUEST              │   │
│  │    （证书签发）      │  - TUNNEL_START_REQUEST      │   │
│  │                      │  - TUNNEL_STOP_REQUEST       │   │
│  │  拒绝：               │  - DATA_PACKET               │   │
│  │  - 其他所有操作     │  - 所有业务操作              │   │
│  └──────────────────────┴──────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

#### TLS 配置

```go
tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{cert},
    ClientCAs:    caCertPool,
    ClientAuth:   tls.RequestClientCert,  // 可选客户端证书
    MinVersion:   tls.VersionTLS12,
    VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
        // 如果没有客户端证书，跳过验证（允许证书申请）
        if len(rawCerts) == 0 {
            return nil
        }
        // 如果有客户端证书，验证 EKU 和证书链
        clientCert, _ := x509.ParseCertificate(rawCerts[0])
        // 1. 验证 EKU 包含 clientAuth
        // 2. 验证链：客户端证书 -> Edge 子 CA -> 根 CA
        return verifyClientCert(clientCert, caCertPool, interPool)
    },
}
```

#### 连接处理

```go
func (s *Server) handleConnection(conn net.Conn) {
    tlsConn := conn.(*tls.Conn)
    
    // 从客户端证书中提取用户信息
    userID, deviceID, err := extractUserInfo(tlsConn)
    if err == ErrNoClientCertificate {
        // 无证书：只允许 CERT_REQUEST
        s.handleCertRequestOnly(tlsConn)
        return
    }
    
    // 有证书：完整的 mTLS 会话，允许所有操作
    s.handleAuthenticatedSession(tlsConn, userID, deviceID)
}
```

#### 安全优势

- ✅ 业务操作要求 mTLS（严格认证）
- ✅ 首次证书申请无需证书（解决冷启动问题）
- ✅ 单一端口，配置简单
- ✅ 应用层访问控制
- ✅ 清晰区分认证/未认证路径

### 配置示例

```yaml
# config.yaml
node:
  id: ""  # 从 EDGE_SECRET 自动填充
tunnel:
  listen: ":8443"
  tls:
    enabled: true
    cert: "./certs/edge-tls.crt"
    key: "./certs/edge-tls.key"
    ca: "./certs/root-ca.crt"
```

### 核心组件

| 组件 | 描述 |
|------|------|
| `SecretBootstrap` | 使用一次性 Secret 进行初始证书注册 |
| `EdgeCA` | 本地 CA 用于签发客户端证书 |
| `CSRForwarder` | 将客户端 CSR 转发给 Captain 签发 |
| `CertCache` | 证书缓存，支持 TTL 和吊销 |
| `EmbeddedCA` | 嵌入的 Captain CA 证书，用于引导验证 |

### 证书文件

引导完成后，`certs/` 目录包含：

| 文件 | 描述 |
|------|------|
| `edge-tls.crt` | Edge TLS 服务器证书 |
| `edge-tls.key` | Edge TLS 私钥 |
| `edge-sub-ca.crt` | Edge 子 CA 证书 |
| `root-ca.crt` | 根 CA 证书 |
| `edge-id` | Edge 节点 ID |

### 安全特性

2. **一次性 Secret**: 注册 Secret 使用后立即失效
3. **证书链验证**: mTLS 连接强制验证完整证书链
4. **EKU 校验**: 客户端证书必须包含 `clientAuth` 扩展密钥用途
5. **证书吊销**: 支持 CRL 订阅和本地吊销缓存

