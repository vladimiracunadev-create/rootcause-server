#!/usr/bin/env sh
set -eu

if [ -z "${ROOTCAUSE_API_TOKEN:-}" ]; then
  echo "ROOTCAUSE_API_TOKEN is required." >&2
  exit 1
fi

exec rootcause-agent "$@"
