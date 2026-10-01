#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
uv python install cpython-3.13-macos-aarch64-none
if [ ! -x .venv/bin/python ]; then
    uv venv --python cpython-3.13-macos-aarch64-none .venv
fi
uv pip install --python .venv/bin/python -r requirements.lock
uv pip install --python .venv/bin/python --no-deps -e .
.venv/bin/python -m pytest -q
