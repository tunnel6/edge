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

controller:
  address: "captain.example.com:443"
  bootstrap:
    enabled: true
    cert_dir: "./certs"
    client_cert_validity: 8760h  # 1年

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

1. **嵌入式 CA 验证**: Captain CA 证书编译到二进制中，防止中间人攻击
2. **一次性 Secret**: 注册 Secret 使用后立即失效
3. **证书链验证**: mTLS 连接强制验证完整证书链
4. **EKU 校验**: 客户端证书必须包含 `clientAuth` 扩展密钥用途
5. **证书吊销**: 支持 CRL 订阅和本地吊销缓存

---

## Recent Changes / 近期更新

### 2026-02 Local Signing Mode with EdgeCA / 本地签发模式（EdgeCA）

#### 1. Local Certificate Signing / 本地证书签发

**Implementation / 实现**: Edge now signs client certificates locally using Sub-CA private key received from Captain.

**Benefits / 优势**:
- Lower latency (no network round-trip to Captain)
- Offline capability (Edge can sign without Captain)
- Reduced Captain load

**Modified Files / 修改文件**:
- `edge/internal/upstream/certmgr/edge_ca.go`: EdgeCA implementation for local signing
- `edge/internal/server/tls.go`: Hybrid strategy (local signing with CSR forwarding fallback)
- `captain/service/edge.go`: Push Sub-CA private key to Edge during registration

#### 2. Sub-CA Private Key Distribution / Sub-CA 私钥分发

**Problem / 问题**: How to securely distribute Sub-CA private key to Edge?

**Solution / 解决方案**: 
- Captain encrypts Sub-CA private key and stores in database/Vault
- During Edge registration, Captain pushes encrypted Sub-CA private key via gRPC streaming
- Edge stores Sub-CA private key locally with 600 permissions

**Modified Files / 修改文件**:
- `api/proto/node/certificate.proto`: Added `sub_ca_private_key` field to `EdgeCertificateBundle`
- `edge/internal/upstream/certmgr/loader.go`: Load Sub-CA private key from local file
- `edge/internal/upstream/certmgr/secret_bootstrap.go`: Save Sub-CA private key during bootstrap

#### 3. Hybrid Signing Strategy / 混合签发策略

**Strategy / 策略**: 
1. Try local signing first (if Sub-CA private key available)
2. Fallback to CSR forwarding if local signing fails
3. Return error if both methods unavailable

**Code / 代码**:
```go
if edgeCA, err := s.certBundle.GetEdgeCA(); err == nil {
    result, err := edgeCA.SignClientCSR(...)
    if err == nil {
        return result  // Local signing succeeded
    }
}
// Fallback to CSR forwarding
result, err := s.csrForwarder.ForwardCSR(...)
```

**Modified Files / 修改文件**:
- `edge/internal/server/tls.go`: Implemented hybrid strategy

#### 4. Legacy CSR Forwarding Mode Documented / CSR 转发模式文档化

**Documentation / 文档**: Created comprehensive documentation for CSR Forwarding mode as legacy/fallback implementation.

**Location / 位置**: [`edge/docs/CSR_FORWARDING_MODE.md`](./docs/CSR_FORWARDING_MODE.md)

**Content / 内容**:
- Architecture and flow diagrams
- Implementation details for Edge and Captain
- Protobuf definitions
- Performance considerations
- Comparison with local signing mode

### 2026-01 mTLS Certificate Architecture Improvements / mTLS 证书架构改进

#### 1. Fixed CaUsedAsEndEntity Error / 修复 CaUsedAsEndEntity 错误

**Problem / 问题**: Edge TLS certificate was incorrectly signed as CA certificate (`IsCA: true`), causing TLS handshake failure.

**Solution / 解决方案**: Modified `SignEdgeCSR` to generate proper end-entity certificate with `IsCA: false`.

**Modified Files / 修改文件**:
- `captain/pkg/certificate/authority.go`: Fixed certificate template

#### 2. Corrected Certificate Chain Construction / 修正证书链构建

**Problem / 问题**: edge-sub-ca was incorrectly added to edge-tls certificate chain.

**Solution / 解决方案**: 
- edge-tls.crt is signed directly by Root CA (no intermediate)
- edge-sub-ca is only used in ClientCAs pool for client certificate verification
- Clarified sibling certificate relationship and verification logic

**Modified Files / 修改文件**:
- `edge/internal/upstream/certmgr/bundle.go`: Removed incorrect certificate chain construction

#### 3. Hybrid TLS/mTLS Security Model / TLS/mTLS 混合安全模型

**Problem / 问题**: Initial certificate requests require TLS (no client cert), but business operations require mTLS.

**Solution / 解决方案**: Application-layer protocol differentiation

- TLS Layer: `RequestClientCert` (optional client cert)
- Application Layer:
  - No cert → Only `CERT_REQUEST` allowed
  - Has cert → Full mTLS with all operations

**Modified Files / 修改文件**:
- `edge/internal/server/server.go`: Added connection handling logic
- `edge/internal/server/tls.go`: Implemented `handleCertRequestOnly()` and hybrid security model

#### 4. Certificate Re-issuance Support / 证书重新签发支持

**Problem / 问题**: Cannot re-bootstrap with consumed EDGE_SECRET after certificate loss.

**Solution / 解决方案**: Allow active nodes to re-register using consumed secrets.

**Modified Files / 修改文件**:
- `captain/service/edge.go`: Updated `RegisterEdge()` to check node status when secret validation fails

#### 5. Edge TLS Certificate SAN Extension / Edge TLS 证书 SAN 扩展

**Problem / 问题**: TLS handshake fails with "certificate not valid for name"

**Solution / 解决方案**: Added Subject Alternative Name (SAN) extension to Edge TLS certificates.

**Modified Files / 修改文件**:
- `captain/pkg/certificate/authority.go`: Added SAN generation from `publicAddress`
- `captain/service/edge.go`: Pass `publicAddress` to certificate signing

#### 6. PublicAddress Handling / PublicAddress 处理

**Problem / 问题**: `0.0.0.0` in PublicAddress causes SAN validation failure.

**Solution / 解决方案**: 
- Bootstrap sets PublicAddress from config (fallback to `127.0.0.1` if `0.0.0.0`)
- Controller Client doesn't override it
- Captain only updates PublicAddress when non-empty

**Modified Files / 修改文件**:
- `edge/internal/server/server.go`: Added PublicAddress fallback logic
- `edge/internal/upstream/captain/controller.go`: Removed PublicAddress override
- `captain/service/edge.go`: Conditional PublicAddress update

---
