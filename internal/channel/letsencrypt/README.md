# letsencrypt 模块说明

`letsencrypt` 是 `edge` 内部的独立证书挑战与签发编排模块，负责：

1. 按优先级选择挑战方式（`http-01` / `tls-alpn-01` / `dns-01`）。
2. 管理初始化状态（token 恢复或申请）与 ACME Directory 配置。
3. 执行 `NewCert` / `RenewCert` 流程。
4. 将签发结果保存到本地目录（默认 `data/custome_certs`）。

本模块支持两种接入方式：

1. 自定义 `Executor` / `Issuer`。
2. 使用内置 `ACMEProvider`（基于 `golang.org/x/crypto/acme`）直连 ACME Directory。

---

## 1. 目录结构

- `letsencrypt.go`：模块入口、Builder、挑战工厂、签发主流程。
- `options.go`：`Options` 与 `With...` 选项。
- `types.go`：类型、错误、回调/执行器签名。
- `http01.go`：`http-01` 挑战实现。
- `tlsalpn01.go`：`tls-alpn-01` 挑战实现。
- `dns01.go`：`dns-01` 挑战实现。
- `challenge_probe.go`：内置探测逻辑（TCP/TLS 预检）。
- `storage.go`：token/证书元数据持久化。

---

## 2. 核心 API

默认 ACME Directory：

- Staging: `https://acme-staging-v02.api.letsencrypt.org/directory`
- Production: `https://acme-v02.api.letsencrypt.org/directory`

可通过 `WithACMEDirectoryURL(...)` / `WithACMEStaging()` / `WithACMEProduction()` 覆盖。

### 2.1 构建实例（链式 Build）

```go
le, err := letsencrypt.NewBuilder(
    letsencrypt.WithDataDir("data"),
    letsencrypt.WithCertDir("data/custome_certs"),
    letsencrypt.WithHTTPListener(httpLn),
    letsencrypt.WithHTTPSListener(httpsLn),
).With(
    letsencrypt.WithPreferredMethods(
        letsencrypt.ChallengeHTTP01,
        letsencrypt.ChallengeTLSALPN01,
        letsencrypt.ChallengeDNS01,
    ),
).Build(ctx)
if err != nil {
    return err
}
```

也可使用快捷函数：

```go
le, err := letsencrypt.Build(ctx, letsencrypt.WithDataDir("data"))
```

### 2.2 申请与续期

```go
stored, err := le.NewCert(ctx, "api.example.com")
if err != nil {
    return err
}

renewed, err := le.RenewCert(ctx, "api.example.com")
if err != nil {
    return err
}
_ = stored
_ = renewed
```

---

## 3. 当前挑战实现行为

## 3.1 http-01

- 必须有 `HTTPListener`。
- 必须把 `le.HTTP01Handler()`（或 `WithHTTP01Handler(...)` 传入的 handler）挂到你的 HTTP server 路由：`/.well-known/acme-challenge/`。
- 若配置 `WithHTTP01Executor(...)`：执行自定义逻辑。
- 执行器会收到统一凭据：`Token`、`KeyAuthorization`、`ChallengePath`。
- 内置流程会构造标准挑战路径：`/.well-known/acme-challenge/<token>`。
- 若未配置 executor，内置流程会先做 listener TCP 探测，再对本地 listener 发起带 Host 头的 GET 并校验响应体是否等于 `KeyAuthorization`。

## 3.2 tls-alpn-01

- 必须有 `HTTPSListener`。
- 若配置 `WithTLSALPN01Executor(...)`：执行自定义逻辑。
- 执行器会收到统一凭据：`Token` 与 `KeyAuthorization`。
- 否则走内置预检：对 listener 做 TLS 连接探测。
- `BuildTLSConfig` 会自动确保 `NextProtos` 包含 `acme-tls/1`。

## 3.3 dns-01

- 若配置 `WithDNS01Executor(...)`：执行自定义 DNS 提交/校验逻辑。
- 执行器会收到统一凭据：`Token` 与 `KeyAuthorization`。
- 否则走内置预检：检查 `_acme-challenge.<domain>` 的 TXT 记录是否存在非空值。

> 注意：内置逻辑是“可用性预检”，不是完整 ACME 协议流程。完整签发动作请在 `Issuer` 或 `Executor` 中对接 ACME 服务端。

---

## 4. 持久化策略

## 4.1 token / keyAuthorization

- 文件默认：`<DataDir>/letsencrypt.token.json`
- 每次签发会优先调用 `ChallengeCredentialRequester`（按 `domain+method` 动态请求 challenge 凭据）。
- 若未配置 `ChallengeCredentialRequester`，则调用 `TokenRequester`。
- 若 `TokenRequester` 也未配置，会回退读取本地 token 文件。

`TokenRequester` 返回结构：

```go
type ChallengeCredential struct {
    Token            string
    KeyAuthorization string
}
```

`ChallengeCredentialRequester` 请求结构：

```go
type ChallengeCredentialRequest struct {
    Domain           string
    Method           ChallengeMethod
    ACMEDirectoryURL string
}
```

## 4.2 证书文件

默认目录：`<DataDir>/custome_certs`（可用 `WithCertDir` 覆盖）。

单域名会生成：

1. `<domain>.crt`
2. `<domain>.key`
3. `<domain>.chain.crt`（有 chain 时）
4. `<domain>.json`（元数据）

---

## 5. 回调与扩展点

## 5.1 Issuer（签发回调）

- `WithNewCertIssuer(...)`
- `WithRenewCertIssuer(...)`

模块在挑战成功后调用 issuer，issuer 返回：

```go
type CertMaterial struct {
    CertificatePEM []byte
    PrivateKeyPEM  []byte
    ChainPEM       []byte
    NotAfter       time.Time
}
```

## 5.2 生命周期回调

- `WithNewCertCallback(...)`
- `WithRenewCertCallback(...)`

阶段：

1. `started`
2. `succeeded`
3. `failed`

## 5.3 内置 ACME Provider

可用 `NewACMEProvider(accountKey, contactEmail)` 创建 provider，然后通过 `WithACMEProvider(provider)` 一次性注入：

1. `ChallengeCredentialRequester`
2. `NewCertIssuer`
3. `RenewCertIssuer`

账户密钥可用以下工具函数管理：

1. `CreateACMEAccountKey()`
2. `SaveACMEAccountKey(path, key)`
3. `LoadACMEAccountKey(path)`
4. `LoadOrCreateACMEAccountKey(path)`

---

## 6. 推荐接入方式

生产环境建议：

1. 若希望模块直接对接 ACME，优先使用 `WithACMEProvider(...)`。
2. 自定义链路时再显式传入 `HTTP01Executor` / `TLSALPN01Executor` / `DNS01Executor`。
3. `ChallengeTimeout` 按实际网络环境设置（默认 5s）。
4. `ChallengeCredentialRequester` / `Issuer` 做重试、日志和可观测性埋点。
5. 多证书并发时，模块已按域名串行化签发流程，建议上层仍避免同域名重复触发。
6. `NewCert` 与 `RenewCert` 失败时使用 `Guidance()` 给用户提示（尤其是 DNS-01 引导）。

### 6.1 Edge + Captain DNS-01 委托（通配符证书场景）

当 Edge 启用 HTTPS（例如 `channel.https.port > 0`）并希望自动申请 `*.<baseDomain>` 证书时，建议使用 `dns-01` 委托链路：

1. Edge 只负责发起 ACME DNS-01（不持有 Cloudflare Token）。
2. Edge 通过 `NodeService.ReportStatus.dns01_challenges` 上报挑战状态（`PRESENT/CLEANUP`）。
3. Captain 在处理 `ReportStatus` 时统一执行 TXT 写入/清理。

相关可调环境变量（Edge 侧）：

1. `EDGE_LE_DNS01_PROPAGATION_WAIT`：TXT 传播等待上限（默认 `20s`）。
2. `EDGE_LE_DNS01_PROPAGATION_TICKER`：TXT 轮询间隔（默认 `2s`）。
3. `EDGE_LE_DNS01_CLEANUP_TIMEOUT`：清理超时（默认 `12s`）。

`http-01` 挂载示例：

```go
mux := http.NewServeMux()
mux.Handle("/.well-known/acme-challenge/", le.HTTP01Handler())
```

---

## 7. 最小可运行示例

```go
accountKey, err := letsencrypt.LoadOrCreateACMEAccountKey(filepath.Join("data", "acme-account.key"))
if err != nil {
    return err
}
provider, err := letsencrypt.NewACMEProvider(accountKey, "ops@example.com")
if err != nil {
    return err
}

le, err := letsencrypt.NewBuilder(
    letsencrypt.WithDataDir("data"),
    letsencrypt.WithACMEStaging(),
    letsencrypt.WithHTTPListener(httpLn),
    letsencrypt.WithACMEProvider(provider),
).Build(context.Background())
if err != nil {
    return err
}

_, err = le.NewCert(context.Background(), "api.example.com")
if err != nil {
    return err
}
```
