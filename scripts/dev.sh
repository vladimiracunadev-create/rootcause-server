#!/usr/bin/env sh
set -eu

if [ -z "${ROOTCAUSE_API_TOKEN:-}" ]; then
  echo "ROOTCAUSE_API_TOKEN is required. Generate one with: cargo run -p rootcause-server -- token" >&2
  exit 1
fi

exec cargo run -p rootcause-server -- serve "$@"
