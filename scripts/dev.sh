#!/usr/bin/env bash
# Levanta el plano de control para desarrollo. Si no hay token, genera uno y lo
# muestra: pedirle a alguien que "genere un token primero" es una fricción
# gratuita cuando el binario ya sabe hacerlo.
set -euo pipefail

cd "$(dirname "$0")/.."

if [ -z "${ROOTCAUSE_API_TOKEN:-}" ]; then
  ROOTCAUSE_API_TOKEN="$(cargo run --quiet -p rootcause-server -- token)"
  export ROOTCAUSE_API_TOKEN
  echo "Token generado para esta sesión:"
  echo "  ${ROOTCAUSE_API_TOKEN}"
  echo "Cópialo en la consola cuando te lo pida."
  echo
fi

exec cargo run -p rootcause-server -- serve "$@"
