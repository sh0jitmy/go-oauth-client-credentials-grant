#!/bin/bash
# Copyright 2026 [Copyright Holder]
# Licensed under the Apache License, Version 2.0 (the "License");

set -e

# カバレッジ測定対象パッケージの生成 (pkg 配下の OAuth2 モジュール)
COVERPKG=$(go list ./pkg/... | paste -sd, -)

# 全パッケージのテスト実行とカバレッジプロファイルの出力
echo "==> Running tests with coverage profile..."
go test -v -race -coverprofile=coverage.out -coverpkg="$COVERPKG" ./pkg/oauth2/... ./pkg/oauth2/client/... ./sample-server/...

# pkg/oauth2 および pkg/oauth2/client のステートメントカバー率 (100.0%) を検証
echo "==> Verifying OAuth2 package 100% statement coverage..."
awk '
BEGIN {
    oauth_total = 0; oauth_cov = 0;
    client_total = 0; client_cov = 0;
}
/:/ {
    block = $1;
    stmts = $2;
    count = $3;

    if ($0 ~ /\/pkg\/oauth2\/client\//) {
        client_stmts[block] = stmts;
        if (count > client_max[block]) { client_max[block] = count; }
    } else if ($0 ~ /\/pkg\/oauth2\//) {
        oauth_stmts[block] = stmts;
        if (count > oauth_max[block]) { oauth_max[block] = count; }
    }
}
END {
    for (b in oauth_stmts) {
        oauth_total += oauth_stmts[b];
        if (oauth_max[b] > 0) { oauth_cov += oauth_stmts[b]; }
    }
    for (b in client_stmts) {
        client_total += client_stmts[b];
        if (client_max[b] > 0) { client_cov += client_stmts[b]; }
    }

    printf "=========================================\n"
    printf "OAuth 2.0 Coverage Verification Summary:\n"
    printf "=========================================\n"

    # pkg/oauth2 Check (== 100.0%)
    if (oauth_total == 0) {
        printf "ERROR: No statements found in pkg/oauth2!\n"
        exit 1
    }
    oauth_rate = (oauth_cov / oauth_total) * 100
    printf "  OAuth2 Server & Middleware (pkg/oauth2): %d/%d (%.2f%%)\n", oauth_cov, oauth_total, oauth_rate
    if (oauth_rate < 100.0) {
        printf "ERROR: pkg/oauth2 coverage is %.2f%%, below strictly required 100.0%%!\n", oauth_rate
        exit 1
    }

    # pkg/oauth2/client Check (== 100.0%)
    if (client_total == 0) {
        printf "ERROR: No statements found in pkg/oauth2/client!\n"
        exit 1
    }
    client_rate = (client_cov / client_total) * 100
    printf "  OAuth2 Client SDK (client):              %d/%d (%.2f%%)\n", client_cov, client_total, client_rate
    if (client_rate < 100.0) {
        printf "ERROR: pkg/oauth2/client coverage is %.2f%%, below strictly required 100.0%%!\n", client_rate
        exit 1
    }

    printf "=========================================\n"
    printf "SUCCESS: 100.0%% unit test statement coverage satisfied!\n"
}
' coverage.out
