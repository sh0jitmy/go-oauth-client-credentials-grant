# OAuth 2.0 Client Credentials Grant & ACME Challenge 保護仕様書

本ドキュメントは、Go (Gin) を用いた **OAuth 2.0 Client Credentials Grant (RFC 6749)**、**RFC 8707 (Resource Indicators for OAuth 2.0)**、および **ACME HTTP-01 Challenge (RFC 8555)** の連携アーキテクチャ、セキュリティ設計、OpenTelemetry可観測性仕様、およびシーケンス定義を規定します。

---

## 1. 概要とアーキテクチャ

### 1.1 背景と目的
マイクロサービス間通信（M2M: Machine-to-Machine）において、高特権なAPI（特に ACME Challenge の実行・終了やドメイン検証用トークンの配置）を安全に保護するため、以下の要件を満たす認可機構を構築します：
- **Client Credentials Grant (RFC 6749)**: 人間の介在しないサービス間認証。
- **Resource Indicators (RFC 8707)**: アクセス対象の証明書・チャレンジを「絶対URI」として指定し、最小権限の原則（PoLP）を強制。
- **Opaque Token & SHA-256 保存**: クライアントには暗号学的ランダム文字列（不透明トークン）を返却し、DB/ストレージには SHA-256 ハッシュ値のみをインデックス保存。
- **ACME HTTP-01 チャレンジ保護 (RFC 8555)**: `/.well-known/acme-challenge/` へのファイル配置・削除APIを対象証明書のResourceトークンでのみ操作可能とする。
- **OpenTelemetry & 監査ログ**: 認可成功（OK）および認可失敗（NG）の双方で、メトリクス・トレース・監査ログを完全計装。

---

## 2. 準拠プロトコルと標準仕様

| プロトコル / RFC | 規格名 | 本実装における役割 |
| :--- | :--- | :--- |
| **RFC 6749** | The OAuth 2.0 Authorization Framework | Section 4.4 Client Credentials Grant によるサービス間認証・トークン発行 |
| **RFC 8707** | Resource Indicators for OAuth 2.0 | トークン要求時パラメータ `resource`（フラグメントなしの絶対URI）の検証とリソースバインド |
| **RFC 3986** | Uniform Resource Identifier (URI): Generic Syntax | `resource` パラメータの構文検証（Scheme, Host, Path を含む絶対URI） |
| **RFC 7662** | OAuth 2.0 Token Introspection | トークンの有効性・紐づくClient/Resource/Scopeを照会するエンドポイント |
| **RFC 7009** | OAuth 2.0 Token Revocation | 発行済みトークンの安全な失効（無効化） |
| **RFC 8555** | Automatic Certificate Management Environment (ACME) | Section 8.3 HTTP-01 Challenge の開始（プロビジョニング）および終了（クリーンアップ） |

---

## 3. セキュリティアーキテクチャ

```
┌─────────────────────────────────────────────────────────────┐
│                    Security Architecture                    │
├──────────────────────────────┬──────────────────────────────┤
│ 1. Client Secret             │ bcrypt (Cost 10) でハッシュ化して保存 │
│                              │ 発行時のみ平文返却（一度きり表示）       │
├──────────────────────────────┼──────────────────────────────┤
│ 2. Opaque Token              │ crypto/rand で 256bit 生成   │
│                              │ base64.RawURLEncoding (43文字)│
├──────────────────────────────┼──────────────────────────────┤
│ 3. Token Storage             │ 平文保存禁止。SHA-256 ハッシュを   │
│                              │ ユニークインデックスとして保存(Stripe方式)│
├──────────────────────────────┼──────────────────────────────┤
│ 4. Resource Validation       │ RFC 8707 絶対URI構文を厳格チェック│
│                              │ クライアント認可URIリストと完全照合 │
└──────────────────────────────┴──────────────────────────────┘
```

---

## 4. OpenTelemetry (OTel) & 監査ログ仕様

認可OKおよび認可NGの双方で、一貫した可観測性とセキュリティ監査証跡を担保します。

### 4.1 Metrics (`go.opentelemetry.io/otel/metric`)

| メトリクス名 | タイプ | ラベル (Low-Cardinality) | 説明 |
| :--- | :--- | :--- | :--- |
| `oauth2_token_requests_total` | Counter | `status`: `ok`, `invalid_client`, `invalid_resource`, `invalid_grant`, `error` | トークン発行エンドポイントの試行総数 |
| `oauth2_auth_checks_total` | Counter | `status`: `ok`, `missing_token`, `invalid_token`, `expired_token`, `resource_mismatch`, `scope_mismatch` | ミドルウェアでの認可判定総数 |
| `oauth2_token_duration_seconds` | Histogram | `operation`: `issue_token`, `verify_token` | トークン処理・ハッシュ計算のレイテンシ |

### 4.2 Traces (`go.opentelemetry.io/otel/trace`)

Span: `oauth2.issue_token`, `oauth2.authorize_request`
- **認可OK時**:
  - `oauth2.status = "ok"`
  - `oauth2.client_id = "<client_id>"`
  - `oauth2.resource = "<target_resource_uri>"`
- **認可NG時**:
  - `oauth2.status = "error"`
  - `oauth2.error_reason = "<missing_token | invalid_token | ...>"`
  - `span.RecordError(err)`
  - `span.SetStatus(codes.Error, reason)`

### 4.3 構造化監査ログ (`log/slog`)

全ての認可判定において、`log_type: "audit"` 属性を付与した構造化ログを出力します：
- **平文トークン・シークレットは完全マスキング**（ログへの出力厳禁）。
- 成功時: `LevelInfo`, `msg: "OAuth2 authorization granted"`, `client_id`, `resource`, `method`, `path`, `remote_ip`
- 失敗時: `LevelWarn`, `msg: "OAuth2 authorization denied"`, `error_reason`, `resource`, `method`, `path`, `remote_ip`

---

## 5. プロトコルシーケンス図 (Mermaid)

### Sequence 1: クライアント利用申請 (Client Registration)

外部サービスがOAuthクライアントとしての利用を申請し、認証情報（ID/Secret）を取得します。

```mermaid
sequenceDiagram
    autonumber
    actor Admin/Client as 利用サービス
    participant API as Gin Server (/oauth/clients)
    participant Svc as oauth2.Service
    participant Store as oauth2.Store

    Admin/Client->>API: POST /oauth/clients<br/>{name, allowed_resources, allowed_scopes}
    API->>Svc: RegisterClient(ctx, req)
    Note over Svc: 1. RFC 8707 絶対URI検証<br/>2. Client ID 生成 (UUIDv4)<br/>3. Client Secret 生成 (crypto/rand 32bytes)<br/>4. bcrypt.GenerateFromPassword(secret)
    Svc->>Store: CreateClient(ctx, &Client{ID, SecretHash, ...})
    Store-->>Svc: 完了
    Svc-->>API: Client情報 + 平文Client Secret
    API-->>Admin/Client: 201 Created<br/>{client_id, client_secret, allowed_resources, ...}
```

---

### Sequence 2: トークン発行 (Client Credentials Grant with RFC 8707 Resource)

利用サービスが、アクセス対象の証明書URIを `resource` として指定し、Opaque Tokenを取得します。

```mermaid
sequenceDiagram
    autonumber
    actor Client as 利用サービス
    participant API as Gin Server (/oauth/token)
    participant Svc as oauth2.Service
    participant Store as oauth2.Store
    participant OTel as OpenTelemetry/slog

    Client->>API: POST /oauth/token<br/>grant_type=client_credentials<br/>resource=https://api.example.com/v1/certificates/cert-001<br/>Authorization: Basic base64(id:secret)
    API->>Svc: IssueToken(ctx, req)
    
    rect rgb(240, 248, 255)
        Note over Svc: 1. RFC 8707 絶対URI構文検証<br/>2. Client 取得 & bcrypt.CompareHashAndPassword<br/>3. Resource 権限照合 (allowed_resources と一致するか)
    end

    alt 認証またはResource権限NG
        Svc->>OTel: RecordMetric("oauth2_token_requests_total", status="invalid_...")<br/>LogAudit(Warn, "authorization denied")
        Svc-->>API: ErrInvalidClient / ErrInvalidTarget
        API-->>Client: 400 Bad Request / 401 Unauthorized
    else 認可OK
        Note over Svc: 4. Opaque Token 生成 (crypto/rand 32bytes)<br/>5. SHA-256(token) 計算<br/>6. 有効期限設定 (ExpiresAt = now + TTL 3600s)
        Svc->>Store: SaveToken(ctx, &Token{TokenHash, ClientID, Resource, ExpiresAt})
        Store-->>Svc: 完了
        Svc->>OTel: RecordMetric("oauth2_token_requests_total", status="ok")<br/>LogAudit(Info, "token issued")
        Svc-->>API: TokenResponse{access_token, token_type="Bearer", expires_in=3600, resource}
        API-->>Client: 200 OK<br/>{access_token: "opq_xxx", token_type: "Bearer", expires_in: 3600, ...}
    end
```

---

### Sequence 3: ACME HTTP-01 チャレンジ実行・検証・終了シーケンス

証明書オーケストレータが Opaque Token を用いて Web サーバー上の ACME Challenge を制御し、外部 ACME サーバー（Let's Encrypt 等）が検証を行います。

```mermaid
sequenceDiagram
    autonumber
    actor Orch as 証明書オーケストレータ
    participant MW as TokenAuthMiddleware & RequireResource
    participant Server as Web Server (sample-server)
    participant Svc as oauth2.Service
    actor ACME as ACME CA (Let's Encrypt)

    %% Step 3.1: チャレンジ開始
    Note over Orch,Server: Phase 1: HTTP-01 チャレンジの開始（トークン配置）
    Orch->>MW: POST /v1/certificates/cert-001/challenges/http-01/start<br/>Authorization: Bearer <opaque_token><br/>{token: "challenge-xyz", key_auth: "xyz.123"}
    MW->>Svc: ValidateToken(ctx, rawToken)
    Note over Svc: SHA-256(rawToken) でStore検索 & 期限・失効チェック
    Svc-->>MW: TokenInfo{ClientID, Resource, ...}
    MW->>MW: RequireResource 判定<br/>Request URI ("https://.../certificates/cert-001") == Token.Resource
    MW->>Server: 認可OK -> ハンドラ実行
    Server->>Server: メモリ上に challenge-xyz -> key_auth を登録
    Server-->>Orch: 200 OK {status: "ready"}

    %% Step 3.2: ACMEサーバーによる外部検証
    Note over ACME,Server: Phase 2: ACME CA によるパブリック検証 (認証不要)
    ACME->>Server: GET /.well-known/acme-challenge/challenge-xyz
    Server-->>ACME: 200 OK (Content-Type: text/plain)<br/>"xyz.123"
    Note over ACME: ドメイン所有権の確認成功！

    %% Step 3.3: チャレンジ終了
    Note over Orch,Server: Phase 3: HTTP-01 チャレンジの終了（クリーンアップ）
    Orch->>MW: POST /v1/certificates/cert-001/challenges/http-01/complete<br/>Authorization: Bearer <opaque_token><br/>{token: "challenge-xyz"}
    MW->>Svc: ValidateToken & RequireResource 照合
    MW->>Server: 認可OK -> ハンドラ実行
    Server->>Server: メモリから challenge-xyz を安全に削除
    Server-->>Orch: 200 OK {status: "cleaned"}
```

---

### Sequence 4: トークン検証 (Introspection) & 失効 (Revocation)

Resource Server や管理ツールがトークンの有効状態を確認、または不要になったトークンを破棄します。

```mermaid
sequenceDiagram
    autonumber
    actor Caller as Resource Server / CLI
    participant API as Gin Server
    participant Svc as oauth2.Service
    participant Store as oauth2.Store

    %% Introspection
    Note over Caller,Store: Token Introspection (RFC 7662)
    Caller->>API: POST /oauth/introspect<br/>token=opq_xxx<br/>Authorization: Basic (Client認証)
    API->>Svc: IntrospectToken(ctx, token)
    Svc->>Svc: SHA-256(token) 計算
    Svc->>Store: GetTokenByHash(ctx, hash)
    alt 有効なトークン
        Store-->>Svc: Token{active: true, client_id, resource, exp, ...}
        Svc-->>API: IntrospectResponse{active: true, ...}
    else 期限切れ または 失効済み または 存在しない
        Svc-->>API: IntrospectResponse{active: false}
    end
    API-->>Caller: 200 OK {active: true/false, ...}

    %% Revocation
    Note over Caller,Store: Token Revocation (RFC 7009)
    Caller->>API: POST /oauth/revoke<br/>token=opq_xxx<br/>Authorization: Basic (Client認証)
    API->>Svc: RevokeToken(ctx, token)
    Svc->>Svc: SHA-256(token) 計算
    Svc->>Store: RevokeToken(ctx, hash)
    Store-->>Svc: 完了
    Svc-->>API: 成功
    API-->>Caller: 200 OK (RFC 7009 規定)
```
