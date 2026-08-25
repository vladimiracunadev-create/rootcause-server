#!/usr/bin/env bash
# Ejecuta el sensor contra el plano de control local.
set -euo pipefail

if [ -z "${ROOTCAUSE_API_TOKEN:-}" ]; then
  echo "Falta ROOTCAUSE_API_TOKEN. Genera uno con: rootcause-server token" >&2
  exit 1
fi

# Sin argumentos, un solo ciclo: enrolar por accidente un servicio permanente
# no debería ser lo que ocurre al probar el sensor por primera vez.
if [ "$#" -eq 0 ]; then
  set -- --once
fi

exec rootcause-agent "$@"
