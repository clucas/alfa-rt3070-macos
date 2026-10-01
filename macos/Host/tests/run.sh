#!/bin/bash
set -euo pipefail
host_dir=$(cd "$(dirname "$0")/.." && pwd)
project_dir=$(cd "$host_dir/../.." && pwd)
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/alfa-host-tests.XXXXXX")
trap 'rm -rf "$test_dir"' EXIT
xcrun swiftc -swift-version 5 -target arm64-apple-macos15.0 \
    "$host_dir/DriverClient.swift" "$host_dir/RadioProcess.swift" \
    "$host_dir/RadioSession.swift" \
    "$host_dir/tests/main.swift" -framework IOKit -o "$test_dir/host-tests"
"$test_dir/host-tests" "$project_dir"
