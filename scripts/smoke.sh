#!/usr/bin/env bash
# End-to-end smoke test: a real server, a real agent, a real machine.
#
# Unit and integration tests drive the router in-process. This one starts the
# actual binaries, points the agent at the actual socket and checks what an
# operator would check by hand — because "it compiles and the tests pass" has
# never been the same claim as "it runs".
set -euo pipefail

PORT="${ROOTCAUSE_SMOKE_PORT:-18080}"
BASE="http://127.0.0.1:${PORT}"
WORKDIR="$(mktemp -d)"
SERVER_PID=""

cleanup() {
  if [ -n "${SERVER_PID}" ] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  rm -rf "${WORKDIR}"
}
trap cleanup EXIT

fail() {
  echo "::error::smoke: $1" >&2
  [ -f "${WORKDIR}/server.log" ] && tail -40 "${WORKDIR}/server.log" >&2
  exit 1
}

echo "==> compilando los binarios"
cargo build --workspace --locked

SERVER="${CARGO_TARGET_DIR:-target}/debug/rootcause-server"
AGENT="${CARGO_TARGET_DIR:-target}/debug/rootcause-agent"
[ -x "${SERVER}" ] || fail "no se encontró el binario del servidor en ${SERVER}"
[ -x "${AGENT}" ] || fail "no se encontró el binario del agente en ${AGENT}"

echo "==> generando token"
TOKEN="$("${SERVER}" token)"
[ "${#TOKEN}" -ge 32 ] || fail "el token generado es demasiado corto"

echo "==> el catálogo de reglas se publica desde el binario"
RULES_OUTPUT="$("${SERVER}" rules)"
echo "${RULES_OUTPUT}" | grep -q "exposure.service.public" \
  || fail "el catálogo no incluye la regla de exposición"
RULE_COUNT="$(echo "${RULES_OUTPUT}" | grep -c '^[a-z]*\.[a-z._]*  *' || true)"
echo "    reglas listadas: ${RULE_COUNT}"

echo "==> la política por omisión es válida y reimportable"
"${SERVER}" policy > "${WORKDIR}/policy.json"
"${SERVER}" policy --file "${WORKDIR}/policy.json" >/dev/null \
  || fail "la política impresa no se pudo volver a cargar"

echo "==> arrancando el servidor"
ROOTCAUSE_API_TOKEN="${TOKEN}" "${SERVER}" serve \
  --bind "127.0.0.1:${PORT}" \
  --database-url "sqlite://${WORKDIR}/rootcause.db" \
  > "${WORKDIR}/server.log" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 40); do
  if curl -fsS "${BASE}/healthz" >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done
curl -fsS "${BASE}/healthz" >/dev/null || fail "el servidor no respondió a /healthz"

echo "==> la API rechaza a quien no trae token"
STATUS_CODE="$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/api/v1/status")"
[ "${STATUS_CODE}" = "401" ] || fail "sin token se esperaba 401 y llegó ${STATUS_CODE}"

echo "==> un token equivocado tampoco entra"
STATUS_CODE="$(curl -s -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer $(printf 'x%.0s' $(seq 1 40))" "${BASE}/api/v1/status")"
[ "${STATUS_CODE}" = "401" ] || fail "con token inválido se esperaba 401 y llegó ${STATUS_CODE}"

echo "==> el agente reporta un ciclo real de esta máquina"
"${AGENT}" --once \
  --server-url "${BASE}" \
  --api-token "${TOKEN}" \
  --label role=edge \
  --label environment=ci > "${WORKDIR}/agent.log" 2>&1 \
  || { cat "${WORKDIR}/agent.log" >&2; fail "el agente no pudo entregar telemetría"; }

STATUS_JSON="$(curl -fsS -H "Authorization: Bearer ${TOKEN}" "${BASE}/api/v1/status")"
echo "${STATUS_JSON}" | grep -q '"assets_total":1' \
  || fail "el servidor no registró el activo: ${STATUS_JSON}"
echo "${STATUS_JSON}" | grep -q '"detectors":' \
  || fail "el estado no publica el número de reglas"
echo "${STATUS_JSON}" | grep -q '"posture"' \
  || fail "el estado no publica la postura"

echo "==> las cabeceras de seguridad viajan en toda respuesta"
HEADERS="$(curl -fsS -D - -o /dev/null -H "Authorization: Bearer ${TOKEN}" "${BASE}/api/v1/status")"
for header in content-security-policy x-content-type-options x-frame-options referrer-policy; do
  echo "${HEADERS}" | tr 'A-Z' 'a-z' | grep -q "^${header}:" \
    || fail "falta la cabecera ${header}"
done
if echo "${HEADERS}" | grep -qi "unsafe-inline"; then
  fail "la CSP admite script en línea"
fi

echo "==> la superficie y las métricas responden"
curl -fsS -H "Authorization: Bearer ${TOKEN}" "${BASE}/api/v1/exposure" | grep -q '"entries"' \
  || fail "la superficie expuesta no devolvió entradas"
curl -fsS -H "Authorization: Bearer ${TOKEN}" "${BASE}/metrics" | grep -q 'rootcause_posture_score' \
  || fail "las métricas no exponen la postura"

echo "==> la evidencia se exporta como NDJSON"
curl -fsS -H "Authorization: Bearer ${TOKEN}" "${BASE}/api/v1/export" > "${WORKDIR}/evidence.ndjson"
head -1 "${WORKDIR}/evidence.ndjson" | grep -q '"kind":"export"' \
  || fail "la exportación no empieza por su cabecera"

echo "==> la consola embebida se sirve desde el binario"
curl -fsS "${BASE}/" | grep -q "RootCause" || fail "la consola no se sirvió"

echo "smoke: todo correcto"
