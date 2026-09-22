# OAuth 2.0 シーケンス動作・ロジック対応マッピング表

本ドキュメントは、[`docs/oauth2_design.md`](file:///Users/shjtmy/gravity/go-oauth-client-credentials-grant/docs/oauth2_design.md) に定義された各シーケンスの動作ステップと、それを実行する Go 実装コード（パッケージ・ファイル・型・関数）の完全な対応関係を説明するトレーサビリティマトリクスです。

---

## 1. Sequence 1: クライアント利用申請 (Client Registration)

| Step # | シーケンス動作 | 担当パッケージ | ファイル | 構造体 / 関数 | 処理内容・ロジックの概要 |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **1-1** | `POST /oauth/clients` リクエスト受付 | `pkg/oauth2` | [`handlers.go`](file:///Users/shjtmy/gravity/go-oauth-client-credentials-grant/pkg/oauth2/handlers.go) | `RegisterClientHandler` | JSONリクエストボディのバインド・基本バリデーション |
| **1-2** | RFC 8707 絶対URI構文の検証 | `pkg/oauth2` | [`types.go`](file:///Users/shjtmy/gravity/go-oauth-client-credentials-grant/pkg/oauth2/types.go) | `ValidateAbsoluteURI` | `net/url` で `IsAbs()` かつ `Fragment == ""` を検査 |
| **1-3** | Client ID の生成 | `pkg/oauth2` | [`service.go`](file:///Users/shjtmy/gravity/go-oauth-client-credentials-grant/pkg/oauth2/service.go) | `Service.RegisterClient` | 暗号学的乱数/UUIDに基づく一意な `client_id` の生成 |
| **1-4** | Client Secret の生成 | `pkg/oauth2` | [`service.go`](file:///Users/shjtmy/gravity/go-oauth-client-credentials-grant/pkg/oauth2/service.go) | `generateSecret` | `crypto/rand` による 256bit ランダムバイト生成 (Base64URL) |
| **1-5** | Client Secret のハッシュ化 | `pkg/oauth2` | [`service.go`](file:///Users/shjtmy/gravity/go-oauth-client-credentials-grant/pkg/oauth2/service.go) | `bcrypt.GenerateFromPassword` | コスト10でのセキュアハッシュ生成 |
| **1-6** | クライアント情報の永続化 | `pkg/oauth2` | [`store.go`](file:///Users/shjtmy/gravity/go-oauth-client-credentials-grant/pkg/oauth2/store.go)<br>[`store_memory.go`](file:///Users/shjtmy/gravity/go-oauth-client-credentials-grant/pkg/oauth2/store_memory.go) | `Store.CreateClient` | ストレージ（メモリまたはDB）への保存（平文シークレットは保存しない） |
| **1-7** | 監査ログおよびメトリクス記録 | `pkg/oauth2` | [`telemetry.go`](file:///Users/shjtmy/gravity/go-oauth-client-credentials-grant/pkg/oauth2/telemetry.go) | `Telemetry.LogClientRegistered` | `log_type: "audit"` ログ出力とメトリクス更新 |
| **1-8** | 201 Created レスポンス返却 | `pkg/oauth2` | [`handlers.go`](file:///Users/shjtmy/gravity/go-oauth-client-credentials-grant/pkg/oauth2/handlers.go) | `RegisterClientHandler` | 生成された平文 Secret（一度のみ表示）を含むJSON返却 |

---

## 2. Sequence 2: トークン発行 (Client Credentials Grant with Resource)

| Step # | シーケンス動作 | 担当パッケージ | ファイル | 構造体 / 関数 | 処理内容・ロジックの概要 |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **2-1** | `POST /oauth/token` 受付 | `pkg/oauth2` | [`handlers.go`](file:///Users/shjtmy/gravity/go-oauth-client-credentials-grant/pkg/oauth2/handlers.go) | `TokenHandler` | Basic認証ヘッダーまたはPOSTボディからの Client 認証情報抽出 |
| **2-2** | Grant Type 検証 | `pkg/oauth2` | [`service.go`](file:///Users/shjtmy/gravity/go-oauth-client-credentials-grant/pkg/oauth2/service.go) | `Service.IssueToken` | `grant_type == "client_credentials"` の検証 |
| **2-3** | RFC 8707 Resource 構文検証 | `pkg/oauth2` | [`types.go`](file:///Users/shjtmy/gravity/go-oauth-client-credentials-grant/pkg/oauth2/types.go) | `ValidateAbsoluteURI` | リクエストの `resource` が絶対URI（フラグメントなし）か検証 |
| **2-4** | Client 認証 (Secret 検証) | `pkg/oauth2` | [`service.go`](file:///Users/shjtmy/gravity/go-oauth-client-credentials-grant/pkg/oauth2/service.go) | `bcrypt.CompareHashAndPassword` | 保存されたハッシュと送信された平文 Secret の照合 |
| **2-5** | Resource 認可チェック | `pkg/oauth2` | [`service.go`](file:///Users/shjtmy/gravity/go-oauth-client-credentials-grant/pkg/oauth2/service.go) | `Service.validateResourceAccess` | 要求された Resource が Client の `allowed_resources` に合致するか照合 |
| **2-6** | 認証/認可NG処理 | `pkg/oauth2` | [`telemetry.go`](file:///Users/shjtmy/gravity/go-oauth-client-credentials-grant/pkg/oauth2/telemetry.go) | `Telemetry.RecordTokenRequest` | `status="invalid_client" / "invalid_resource"` メトリクス加算、OTel Span エラー記録、`log_type: "audit"` 警告ログ出力 |
| **2-7** | Opaque Token 生成 | `pkg/oauth2` | [`service.go`](file:///Users/shjtmy/gravity/go-oauth-client-credentials-grant/pkg/oauth2/service.go) | `generateOpaqueToken` | `crypto/rand` による 256bit エントロピー文字列生成 (例: `opq_...`) |
| **2-8** | Token SHA-256 ハッシュ計算 | `pkg/oauth2` | [`service.go`](file:///Users/shjtmy/gravity/go-oauth-client-credentials-grant/pkg/oauth2/service.go) | `computeSHA256` | 保存・インデックス引き当て用のハッシュ文字列を計算 |
| **2-9** | トークン保存 | `pkg/oauth2` | [`store.go`](file:///Users/shjtmy/gravity/go-oauth-client-credentials-grant/pkg/oauth2/store.go) | `Store.SaveToken` | `TokenHash`, `ClientID`, `Resource`, `ExpiresAt` を永続化 |
| **2-10** | 認可OK記録 & 返却 | `pkg/oauth2` | [`telemetry.go`](file:///Users/shjtmy/gravity/go-oauth-client-credentials-grant/pkg/oauth2/telemetry.go)<br>[`handlers.go`](file:///Users/shjtmy/gravity/go-oauth-client-credentials-grant/pkg/oauth2/handlers.go) | `RecordTokenRequest`<br>`TokenHandler` | `status="ok"` メトリクス加算、Span正常終了、RFC 6749 形式のJSONレスポンス返却 |

---

## 3. Sequence 3: ACME HTTP-01 チャレンジ実行・検証・終了シーケンス

| Step # | シーケンス動作 | 担当パッケージ | ファイル | 構造体 / 関数 | 処理内容・ロジックの概要 |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **3-1** | `Authorization: Bearer` 抽出 | `pkg/oauth2` | [`middleware.go`](file:///Users/shjtmy/gravity/go-oauth-client-credentials-grant/pkg/oauth2/middleware.go) | `TokenAuthMiddleware` | HTTP ヘッダーから Opaque Token 文字列を抽出 |
| **3-2** | トークン検証 (ハッシュ検索) | `pkg/oauth2` | [`service.go`](file:///Users/shjtmy/gravity/go-oauth-client-credentials-grant/pkg/oauth2/service.go) | `Service.ValidateToken` | `SHA-256(token)` を計算し、Store から取得。有効期限 (`ExpiresAt`) および失効 (`RevokedAt`) を検査 |
| **3-3** | トークン検証NG処理 | `pkg/oauth2` | [`telemetry.go`](file:///Users/shjtmy/gravity/go-oauth-client-credentials-grant/pkg/oauth2/telemetry.go) | `Telemetry.RecordAuthCheck` | `status="invalid_token" / "expired_token"` メトリクス加算、401 Unauthorized 返却、監査ログ記録 |
| **3-4** | Gin Context への情報注入 | `pkg/oauth2` | [`middleware.go`](file:///Users/shjtmy/gravity/go-oauth-client-credentials-grant/pkg/oauth2/middleware.go) | `TokenAuthMiddleware` | `c.Set(TokenContextKey, token)` により後続ミドルウェアへ伝達 |
| **3-5** | Resource 照合判定 | `pkg/oauth2` | [`middleware.go`](file:///Users/shjtmy/gravity/go-oauth-client-credentials-grant/pkg/oauth2/middleware.go) | `RequireResource` | リクエストされた絶対URI（例: `https://.../certificates/cert-001`）と `Token.Resource` が完全一致するか検証。不一致時は 403 Forbidden |
| **3-6** | HTTP-01 チャレンジ開始 | `sample-server` | `sample-server/internal/certificate/handler.go` | `ChallengeHandler.StartHTTP01` | 受信した `token` と `key_authorization` をインメモリマッピングにプロビジョニング |
| **3-7** | ACME 外部検証の応答 | `sample-server` | `sample-server/internal/certificate/handler.go` | `ChallengeHandler.ServeHTTP01` | `/.well-known/acme-challenge/:token` にアクセスした ACME CA に対して、プレーンテキストで `key_authorization` を返却（パブリック・認証不要） |
| **3-8** | HTTP-01 チャレンジ終了 | `sample-server` | `sample-server/internal/certificate/handler.go` | `ChallengeHandler.CompleteHTTP01` | トークン認可・Resource検証後、プロビジョニングされた検証用データを安全にメモリからパージ |

---

## 4. Sequence 4: トークン検証 (Introspection) & 失効 (Revocation)

| Step # | シーケンス動作 | 担当パッケージ | ファイル | 構造体 / 関数 | 処理内容・ロジックの概要 |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **4-1** | Introspect リクエスト受付 | `pkg/oauth2` | [`handlers.go`](file:///Users/shjtmy/gravity/go-oauth-client-credentials-grant/pkg/oauth2/handlers.go) | `IntrospectHandler` | `POST /oauth/introspect` での Client 認証および `token` 引数取得 |
| **4-2** | トークン状態照会 | `pkg/oauth2` | [`service.go`](file:///Users/shjtmy/gravity/go-oauth-client-credentials-grant/pkg/oauth2/service.go) | `Service.IntrospectToken` | ハッシュ検索を行い、有効なら `active: true`、期限切れ/失効なら `active: false` を構築 |
| **4-3** | RFC 7662 レスポンス | `pkg/oauth2` | [`handlers.go`](file:///Users/shjtmy/gravity/go-oauth-client-credentials-grant/pkg/oauth2/handlers.go) | `IntrospectHandler` | JSON レスポンス返却 |
| **4-4** | Revoke リクエスト受付 | `pkg/oauth2` | [`handlers.go`](file:///Users/shjtmy/gravity/go-oauth-client-credentials-grant/pkg/oauth2/handlers.go) | `RevokeHandler` | `POST /oauth/revoke` での Client 認証および `token` 引数取得 |
| **4-5** | トークン失効実行 | `pkg/oauth2` | [`service.go`](file:///Users/shjtmy/gravity/go-oauth-client-credentials-grant/pkg/oauth2/service.go) | `Service.RevokeToken` | `Store.RevokeToken` を呼び出し、`RevokedAt` を記録（または物理削除） |
| **4-6** | RFC 7009 レスポンス | `pkg/oauth2` | [`handlers.go`](file:///Users/shjtmy/gravity/go-oauth-client-credentials-grant/pkg/oauth2/handlers.go) | `RevokeHandler` | 200 OK 空レスポンス返却 |

---

## 5. クライアントSDK (`pkg/oauth2/client`) の動作マッピング

| ユースケース | メソッド / 関数 | 内部ロジック |
| :--- | :--- | :--- |
| **利用申請の実行** | `Client.RegisterClient(ctx, req)` | サーバーの `/oauth/clients` に HTTP POST を送信し、発行された `client_id`, `client_secret` を受領 |
| **トークン自動取得・キャッシュ** | `Client.GetToken(ctx, resourceURI)` | メモリキャッシュ内に当該 `resourceURI` の有効なトークン（有効期限まで一定のバッファがあるもの）があればそれを即座に返却。存在しないまたは期限切れの場合は、自動で `/oauth/token` へ `grant_type=client_credentials` かつ `resource` を送信して新規取得しキャッシュ更新 |
| **保護APIの透過的呼び出し** | `Client.Do(req)` / `Transport` | HTTP リクエストの対象URL（絶対URI）を Resource と見なし、`GetToken` で取得したトークンを `Authorization: Bearer <opaque_token>` として付与して透過送信 |
