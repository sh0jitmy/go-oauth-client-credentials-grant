#!/bin/bash
# Copyright 2026 [Copyright Holder]
# Licensed under the Apache License, Version 2.0 (the "License");

set -e

# カバレッジ測定用の対象パッケージリストの生成（自動生成コード ent, ogen を除外）
COVERPKG=$(go list ./... | grep -v -E '/ent|/ogen' | paste -sd, -)

# 全パッケージのテスト実行とカバレッジプロファイルの出力
echo "==> Running tests with coverage profile..."
go test -v -race -coverprofile=coverage.out -coverpkg="$COVERPKG" ./...

# internal/service/ および internal/domain/ 配下の合計ステートメントカバー率を検証
echo "==> Verifying business logic and OAuth2 package coverage..."
awk '
BEGIN {
    biz_total = 0; biz_cov = 0;
    oauth_total = 0; oauth_cov = 0;
    client_total = 0; client_cov = 0;
}
/:/ {
    block = $1;
    stmts = $2;
    count = $3;

    if ($0 ~ /\/internal\/(service|domain)\//) {
        biz_stmts[block] = stmts;
        if (count > biz_max[block]) { biz_max[block] = count; }
    } else if ($0 ~ /\/pkg\/oauth2\/client\//) {
        client_stmts[block] = stmts;
        if (count > client_max[block]) { client_max[block] = count; }
    } else if ($0 ~ /\/pkg\/oauth2\//) {
        oauth_stmts[block] = stmts;
        if (count > oauth_max[block]) { oauth_max[block] = count; }
    }
}
END {
    for (b in biz_stmts) {
        biz_total += biz_stmts[b];
        if (biz_max[b] > 0) { biz_cov += biz_stmts[b]; }
    }
    for (b in oauth_stmts) {
        oauth_total += oauth_stmts[b];
        if (oauth_max[b] > 0) { oauth_cov += oauth_stmts[b]; }
    }
    for (b in client_stmts) {
        client_total += client_stmts[b];
        if (client_max[b] > 0) { client_cov += client_stmts[b]; }
    }

    printf "=========================================\n"
    printf "Code Coverage Verification Summary:\n"
    printf "=========================================\n"

    # Business Logic Check (>= 80.0%)
    if (biz_total > 0) {
        biz_rate = (biz_cov / biz_total) * 100
        printf "  Business Logic (service/domain): %d/%d (%.2f%%)\n", biz_cov, biz_total, biz_rate
        if (biz_rate < 80.0) {
            printf "ERROR: Business logic coverage is %.2f%%, below required 80.0%%!\n", biz_rate
            exit 1
        }
    }

    # pkg/oauth2 Check (== 100.0%)
    if (oauth_total > 0) {
        oauth_rate = (oauth_cov / oauth_total) * 100
        printf "  OAuth2 Server (pkg/oauth2):      %d/%d (%.2f%%)\n", oauth_cov, oauth_total, oauth_rate
        if (oauth_rate < 100.0) {
            printf "ERROR: pkg/oauth2 coverage is %.2f%%, below strictly required 100.0%%!\n", oauth_rate
            exit 1
        }
    }

    # pkg/oauth2/client Check (== 100.0%)
    if (client_total > 0) {
        client_rate = (client_cov / client_total) * 100
        printf "  OAuth2 Client SDK (client):      %d/%d (%.2f%%)\n", client_cov, client_total, client_rate
        if (client_rate < 100.0) {
            printf "ERROR: pkg/oauth2/client coverage is %.2f%%, below strictly required 100.0%%!\n", client_rate
            exit 1
        }
    }

    printf "=========================================\n"
    printf "SUCCESS: All coverage thresholds satisfied!\n"
}
' coverage.out
