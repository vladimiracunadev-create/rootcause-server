# Contrato del API

Versión del protocolo: **1.1**. El servidor acepta también agentes `1.0`, que
simplemente no reportan superficie de seguridad; el servidor lo declara como
observación en la respuesta de ingesta.

Todo endpoint bajo `/api/v1` y `/metrics` exige `Authorization: Bearer <token>`.
`/healthz` y `/readyz` son públicos a propósito: un comprobador de salud no
debería necesitar la credencial de administración.

## Errores

```json
{ "error": "falta el token bearer o no es válido", "code": "unauthorized" }
```

| Código | HTTP | Cuándo |
|---|---|---|
| `bad_request` | 400 | Entrada fuera de contrato o de los límites declarados |
| `unauthorized` | 401 | Token ausente o incorrecto |
| `not_found` | 404 | El recurso no existe |
| `rate_limited` | 429 | La dirección superó su presupuesto; trae `Retry-After` |
| `locked_out` | 429 | La dirección está bloqueada por fallos repetidos |
| `internal` | 500 | Fallo inesperado; el detalle queda en el registro del servidor |

Un error nunca lleva traza, consulta ni credencial: el detalle va al registro,
el llamador recibe un código estable.

---

## Salud

### `GET /healthz`

```json
{ "status": "ok", "service": "rootcause-server", "version": "0.2.0" }
```

### `GET /readyz`

Igual, pero comprueba primero el almacenamiento. Úsalo como *readiness probe*.

---

## Estado y catálogo

### `GET /api/v1/status`

```json
{
  "service": "rootcause-server",
  "version": "0.2.0",
  "protocol_version": "1.1",
  "uptime_seconds": 3600,
  "assets_total": 12,
  "assets_online": 11,
  "open_incidents": 4,
  "critical_incidents": 1,
  "exposed_services": 7,
  "blocked_sources": 2,
  "detectors": 18,
  "posture": {
    "score": 41,
    "grade": "F",
    "dimensions": [{ "category": "exposure", "score": 55, "findings": 1, "summary": "…" }],
    "uninspected_surfaces": ["auth-events: sin permiso de lectura"],
    "computed_at": "2026-08-25T20:00:00Z"
  },
  "hardening": {
    "authentication": true,
    "bind_is_loopback": true,
    "rate_limit_per_minute": 600,
    "lockout_threshold": 10,
    "retention_days": 30
  }
}
```

`hardening` existe para que la consola pueda advertir con honestidad cuando la
instancia corre sin token o escucha fuera de loopback.

### `GET /api/v1/rules`

El catálogo de las 18 reglas implementadas, cada una con su categoría, la
pregunta operativa que responde, su severidad máxima y sus técnicas ATT&CK. Es
la misma lista que imprime `rootcause-server rules`.

### `GET /api/v1/policy`

La política de detección vigente, en el mismo formato que acepta
`--policy-file`. Sirve para versionarla junto al despliegue.

---

## Activos

### `POST /api/v1/assets/register` → `204`

```json
{
  "agent_id": "11111111-2222-3333-4444-555555555555",
  "hostname": "srv-prod-01",
  "platform": "linux",
  "os_version": "Debian 13",
  "kernel_version": "6.12.0",
  "architecture": "x86_64",
  "agent_version": "0.2.0",
  "labels": { "role": "edge", "environment": "production" }
}
```

Límites: nombre de equipo de 1 a 255 caracteres, hasta 32 etiquetas, claves de
64 y valores de 256 caracteres.

### `GET /api/v1/assets`

Inventario con la última muestra, la superficie reportada y la postura calculada
por equipo.

### `GET /api/v1/assets/{id}`

Detalle: el activo, sus incidentes y hasta 120 muestras de historial.

---

## Telemetría

### `POST /api/v1/telemetry`

```json
{
  "protocol_version": "1.1",
  "asset": { "…": "registro opcional, evita una llamada aparte" },
  "sample": {
    "agent_id": "11111111-2222-3333-4444-555555555555",
    "observed_at": "2026-08-25T20:00:00Z",
    "cpu_percent": 11.0,
    "memory_percent": 42.0,
    "disk_percent": 55.0,
    "uptime_seconds": 3600,
    "load_average": [0.2, 0.3, 0.4],
    "network_rx_bytes": 1000,
    "network_tx_bytes": 2000,
    "disk_free_bytes": 80000000000,
    "process_count": 210
  },
  "security": {
    "listeners": [
      { "protocol": "tcp", "address": "0.0.0.0", "port": 5432, "scope": "public",
        "process": "postgres", "pid": 901 }
    ],
    "peers": [
      { "remote_address": "203.0.113.8", "remote_port": 51514, "local_port": 22,
        "connections": 2 }
    ],
    "auth_events": [
      { "service": "sshd", "source_address": "203.0.113.10", "username": "root",
        "outcome": "failure", "count": 120, "last_seen": "2026-08-25T19:59:00Z" }
    ],
    "watched_files": [
      { "path": "/etc/ssh/sshd_config", "digest": "…", "size_bytes": 3200,
        "mode": 384 }
    ],
    "firewall": { "engine": "ufw", "enabled": true, "rule_count": 12,
                  "default_inbound_deny": true },
    "pending_security_updates": 3,
    "collection_gaps": [
      { "surface": "auth-events", "reason": "sin permiso de lectura" }
    ]
  }
}
```

Respuesta:

```json
{ "accepted": true, "incidents_touched": 2,
  "warnings": ["superficie no inspeccionada — auth-events: sin permiso de lectura"] }
```

Reglas de admisión:

- La marca de tiempo debe caer dentro de las últimas 24 horas y no más de 5
  minutos en el futuro.
- El activo debe estar registrado antes de enviar telemetría.
- `security` es opcional; su ausencia se devuelve como observación.
- Límites por envío: 1024 sockets, 4096 conexiones, 1024 eventos de
  autenticación, 512 archivos vigilados, 64 brechas.
- `scope` lo deriva el propio modelo de la dirección de enlace: un agente no
  puede declararse en loopback estando en `0.0.0.0`.

---

## Hallazgos

### `GET /api/v1/incidents`

Filtros: `status` (`open`, `acknowledged`, `resolved`), `severity`
(`info`…`critical`), `category` (`intrusion`, `exposure`, `integrity`,
`hygiene`, `availability`, `resource`), `asset` (UUID) y `limit`.

Un valor que el servidor no entiende devuelve `400`: se rechaza en vez de
ignorarse en silencio, porque un filtro ignorado hace que una consulta parezca
vacía cuando no lo está.

```json
{
  "id": "…", "fingerprint": "…:exposure.service.public:tcp/5432",
  "asset_id": "…", "title": "PostgreSQL alcanzable fuera de srv-prod-01",
  "summary": "…", "severity": "critical", "category": "exposure",
  "status": "open", "root_cause": "…", "confidence": 0.99,
  "first_seen": "…", "last_seen": "…", "occurrences": 4,
  "evidence": [
    { "kind": "network.listener", "summary": "tcp/5432 · PostgreSQL · alcance public",
      "detail": "0.0.0.0:5432 → postgres (pid 901)", "observed_at": "…" }
  ],
  "recommended_actions": ["…"],
  "runbook": [
    { "description": "Identifica qué proceso publica PostgreSQL en el puerto 5432.",
      "kind": "inspect", "platform": "linux", "command": "ss -ltnp 'sport = :5432'",
      "requires_privileges": true, "reversible": true }
  ],
  "techniques": ["T1190"]
}
```

### `GET /api/v1/incidents/{id}` · `GET /api/v1/incidents/{id}/runbook`

### `POST /api/v1/incidents/{id}/status`

```json
{ "status": "acknowledged", "actor": "vladimir" }
```

Queda en la auditoría con el estado anterior y el nuevo.

---

## Vistas agregadas

### `GET /api/v1/exposure`

La superficie de toda la flota, ordenada por severidad, con
`uninspected_assets`: los equipos de los que no se pudo leer la superficie. Un
equipo sin superficie reportada **no** es un equipo sin puertos abiertos.

### `GET /api/v1/threats`

Orígenes agregados por dirección, con fallidos, concedidos, servicios, usuarios
probados y equipos afectados, más `control_plane_defense`: lo que el propio
plano de control rechazó, por motivo.

### `GET /api/v1/topology`

Nodos y aristas por zona (`internet`, `zone:expuesto`, `zone:interno`,
`rootcause-server`, `asset:*`), cada endpoint con sus puertos públicos y sus
hallazgos abiertos.

### `GET /api/v1/audit?limit=200`

### `GET /api/v1/export`

Paquete de evidencia como NDJSON, un documento por línea, tipado por `kind`
(`export`, `asset`, `incident`, `audit`). Pensado para archivarse fuera del
servidor.

### `GET /metrics`

Exposición Prometheus:

```text
rootcause_uptime_seconds
rootcause_assets_total
rootcause_assets_online
rootcause_incidents_open
rootcause_incidents_critical
rootcause_exposed_services
rootcause_blocked_sources
rootcause_posture_score
rootcause_perimeter_locked_sources
rootcause_perimeter_tracked_clients
rootcause_incidents_by_category{category="…"}
```
