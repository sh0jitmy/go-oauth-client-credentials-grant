# CLAUDE.md

## プロジェクトの概要

このプロジェクトは、**RFC 8707 (Resource Indicators)** に準拠した **OAuth 2.0 Client Credentials Grant (RFC 6749)** 認可サーバー、Gin 保護ミドルウェア、クライアント SDK、および **ACME HTTP-01 Challenge (RFC 8555)** 制御用リファレンス実装を提供するプロダクション品質のリポジトリです。
`pkg/oauth2` および `pkg/oauth2/client` は外部リポジトリから `go get` 可能なスタンドアロン設計となっており、単体テストカバレッジ **100.0%** を維持しています。

## AIエージェント（Claude Code）への指示

> [!IMPORTANT]
> - **スキルの厳格な適用**: 本プロジェクトにおけるコードの実装、設計、リファクタリング、およびコードレビューを行う際は、必ず `.claude/skills/` にある各スキル（`golang-design`、`golang-implementation`、`quality-inspector`、`sre-deployment`、`git-strategy` 等）の指針に準拠してください。
> - **言語の統一**: コミットメッセージは**英語**、それ以外のPR説明、Issue、およびAIによるレビューレポートは**完全な日本語**で記述してください。
> - **ライセンスヘッダーの維持**: 新規追加した Go ソースコードには必ず Apache-2.0 ライセンスヘッダーを付与し、`make license-check` をパスさせてください。
> - **単体テストカバレッジ 100% の維持**: `pkg/oauth2` および `pkg/oauth2/client` のステートメントカバレッジは 100.0% を必須要件とします。

## 開発・検証コマンド一覧

### Go開発 & ローカル実行
- **OAuth2 & ACME E2E テスト**: `make oauth-e2e`
- **単体テスト & カバレッジ検証**: `make test` (カバレッジ 100% アサーション実行)
- **静的解析の実行**: `make lint` (`golangci-lint`)
- **マルチバイナリビルド**: `make build` (`app`, `web`, `oauth-cli`, `sample-server`)
- **コードフォーマット**: `make fmt`
- **脆弱性スキャンの実行**: `make vulncheck`
- **ライセンスヘッダー検証**: `make license-check`
- **ローカル一括起動 (API + Web)**: `make run`
- **静的サイト生成 (SSG)**: `make ssg-build`

### 多層 E2E テスト
- **OAuth2 & ACME HTTP-01 E2E**: `make oauth-e2e`
- **No-Docker SQLite E2E**: `make sqlite-e2e`
- **スタンドアロン HTMX フロントエンド E2E**: `make frontend-e2e`
- **Docker Compose フルスタック E2E**: `make docker-e2e`
- **フルスタックライブデモ**: `make demo`

### リファレンスサーバー & CLI 実行
```bash
# 1. ACME チャレンジ保護 Gin サーバー起動
go run ./sample-server/main.go

# 2. 評価用 CLI ツールによる操作
go run ./cmd/oauth-cli/main.go --help
```
