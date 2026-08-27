#!/usr/bin/env bash
# Back up the RootCause database, and prove the copy is readable.
#
# Incidents and the audit trail are the only things in this system that cannot
# be regenerated: telemetry comes back on the next cycle, the surface comes back
# on the next cycle, evidence does not. A volume that survives a container
# restart is not a backup of them.
#
# `.backup` is used rather than `cp` on purpose: with WAL enabled, copying the
# file while the server writes can produce a torn snapshot unless `-wal` and
# `-shm` travel with it. `.backup` is safe against a live writer.
#
# The copy is verified before this script claims success. A backup nobody read
# back is a hope, not a backup.
set -euo pipefail

SOURCE="${1:-${ROOTCAUSE_DB_PATH:-rootcause.db}}"
DEST_DIR="${2:-${ROOTCAUSE_BACKUP_DIR:-./backups}}"
KEEP="${ROOTCAUSE_BACKUP_KEEP:-14}"

fail() {
  echo "respaldo: $1" >&2
  exit 1
}

command -v sqlite3 >/dev/null 2>&1 \
  || fail "falta sqlite3. Instálalo (Debian: apt-get install sqlite3) y vuelve a intentarlo."

# A URL is accepted for convenience: it is what the service file already holds.
case "${SOURCE}" in
  sqlite://*) SOURCE="${SOURCE#sqlite://}" ;;
  sqlite:*)   SOURCE="${SOURCE#sqlite:}" ;;
esac

[ -f "${SOURCE}" ] || fail "no existe la base de datos ${SOURCE}"

mkdir -p "${DEST_DIR}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
TARGET="${DEST_DIR}/rootcause-${STAMP}.db"

echo "==> copiando ${SOURCE} → ${TARGET}"
sqlite3 "${SOURCE}" ".backup '${TARGET}'" \
  || fail "sqlite3 no pudo completar la copia"
[ -s "${TARGET}" ] || fail "la copia quedó vacía"

echo "==> comprobando la integridad de la copia"
INTEGRITY="$(sqlite3 "${TARGET}" 'PRAGMA integrity_check;' 2>/dev/null || true)"
[ "${INTEGRITY}" = "ok" ] || fail "la copia no pasa integrity_check: ${INTEGRITY:-sin respuesta}"

# What matters is not that the file opens: it is that the evidence is inside.
count() {
  sqlite3 "$1" "SELECT COUNT(*) FROM $2;" 2>/dev/null || echo "error"
}

for table in incidents audit_log assets; do
  ORIGIN="$(count "${SOURCE}" "${table}")"
  COPY="$(count "${TARGET}" "${table}")"
  [ "${COPY}" != "error" ] || fail "la copia no puede leer la tabla ${table}"
  # The origin may have grown between the snapshot and this read; it must never
  # hold *less* than the copy.
  if [ "${COPY}" -gt "${ORIGIN}" ]; then
    fail "la copia de ${table} tiene más filas (${COPY}) que el origen (${ORIGIN})"
  fi
  echo "    ${table}: ${COPY} filas en la copia (${ORIGIN} en el origen)"
done

SIZE="$(du -h "${TARGET}" | cut -f1)"
echo "==> respaldo verificado: ${TARGET} (${SIZE})"

if [ "${KEEP}" -gt 0 ] 2>/dev/null; then
  # Newest first; anything past the retention window goes.
  mapfile -t OLD < <(ls -1t "${DEST_DIR}"/rootcause-*.db 2>/dev/null | tail -n "+$((KEEP + 1))")
  if [ "${#OLD[@]}" -gt 0 ]; then
    echo "==> conservando los ${KEEP} más recientes; se retiran ${#OLD[@]}"
    for stale in "${OLD[@]}"; do
      rm -f -- "${stale}"
      echo "    retirado ${stale}"
    done
  fi
fi

cat <<RESTORE

Para restaurar:
  1. systemctl stop rootcause-server
  2. cp "${TARGET}" /var/lib/rootcause/rootcause.db
  3. rm -f /var/lib/rootcause/rootcause.db-wal /var/lib/rootcause/rootcause.db-shm
  4. systemctl start rootcause-server

Las migraciones pendientes se aplican solas al arrancar. Restaurar un respaldo
en un binario *anterior* al que lo creó no está probado: no hay migraciones
descendentes.
RESTORE
