#!/bin/bash
set -euo pipefail
driver_dir=$(cd "$(dirname "$0")/.." && pwd)
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/alfa-driver-tests.XXXXXX")
trap 'rm -rf "$test_dir"' EXIT
xcrun --sdk macosx clang++ -std=c++17 -fsanitize=address,undefined \
    -I "$driver_dir" -I "$driver_dir/../Shared" \
    "$driver_dir/tests/frame_queue_test.cpp" -o "$test_dir/frame_queue_test"
"$test_dir/frame_queue_test"
echo "Frame queue and protocol tests passed."
