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
> - **E2E レポートの整合性**: `make oauth-e2e` 実行時に `test_reports/index.html` および `history.json` が生成されます。トークン等の機密情報はマスキングされ、GitHub Pages に自動連携されます。

## 開発・検証コマンド一覧

### Go開発 & ローカル実行
- **OAuth2 & ACME E2E テスト (HTML レポート自動生成)**: `make oauth-e2e`
- **単体テスト & カバレッジ検証**: `make test` (カバレッジ 100% アサーション実行)
- **静的解析の実行**: `make lint` (`golangci-lint`)
- **マルチバイナリビルド**: `make build` (`bin/oauth-cli`, `bin/sample-server`)
- **コードフォーマット**: `make fmt`
- **脆弱性スキャンの実行**: `make vulncheck`
- **ライセンスヘッダー検証**: `make license-check`
- **リリース設定の検証**: `make release-check`
- **ビルド成果物のクリーンアップ**: `make clean`

### リファレンスサーバー & CLI 実行
```bash
# 1. ACME チャレンジ保護 Gin サーバー起動
go run ./sample-server/main.go

# 2. 評価用 CLI ツールによる操作
go run ./cmd/oauth-cli/main.go --help
```
