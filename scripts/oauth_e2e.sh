#!/bin/bash
# Copyright 2026 [Copyright Holder]
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Author: [YOUR_NAME]

set -u

REPORT_DIR="test_reports"
RAW_JSON="${REPORT_DIR}/e2e_raw.json"
REPORT_HTML="${REPORT_DIR}/index.html"
HISTORY_JSON="${REPORT_DIR}/history.json"

mkdir -p "${REPORT_DIR}"

echo "==> Running OAuth2 & ACME HTTP-01 E2E tests with JSON logging..."

# Run go test with -json and stream output to both console and raw json file
# Temporarily allow non-zero exit code so report generation always runs
set +e
go test -v -race -json ./sample-server/... | tee "${RAW_JSON}"
TEST_EXIT_CODE=${PIPESTATUS[0]}
set -e

echo ""
echo "==> Generating E2E HTML Report and updating history..."
python3 scripts/generate_e2e_report.py "${RAW_JSON}" "${REPORT_HTML}" "${HISTORY_JSON}"
REPORT_EXIT_CODE=$?

if [ ${TEST_EXIT_CODE} -ne 0 ]; then
    echo "❌ E2E Tests Failed (exit code: ${TEST_EXIT_CODE}). Report generated at ${REPORT_HTML}" >&2
    exit ${TEST_EXIT_CODE}
fi

if [ ${REPORT_EXIT_CODE} -ne 0 ]; then
    echo "⚠️ Report generator reported errors (exit code: ${REPORT_EXIT_CODE})" >&2
    exit ${REPORT_EXIT_CODE}
fi

echo "✅ E2E Tests Passed successfully! Report available at ${REPORT_HTML}"
exit 0
