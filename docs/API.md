# API v1

Base: `/api/v1`

Todas las rutas, excepto `/healthz` y los recursos de la consola, requieren:

```http
Authorization: Bearer <ROOTCAUSE_API_TOKEN>
```

El cuerpo máximo aceptado es 1 MiB. El protocolo del agente se versiona
independientemente del paquete.

## Rutas

| Método | Ruta | Uso |
|---|---|---|
| GET | `/healthz` | Salud de proceso y almacenamiento |
| GET | `/api/v1/status` | Contadores y versión |
| POST | `/api/v1/assets/register` | Crear o actualizar un activo |
| GET | `/api/v1/assets` | Inventario y última telemetría |
| POST | `/api/v1/telemetry` | Ingerir una muestra `1.0` |
| GET | `/api/v1/incidents` | Incidentes priorizados |
| POST | `/api/v1/incidents/{id}/status` | Reconocer o resolver |
| GET | `/api/v1/topology` | Nodos y relaciones actuales |

## Registro de activo

```json
{
  "agent_id": "a94a8fe5-ccb1-55b0-90f7-3dce3f15745b",
  "hostname": "workstation-01",
  "platform": "windows",
  "os_version": "Windows 11",
  "kernel_version": "10.0.26100",
  "architecture": "x86_64",
  "agent_version": "0.1.0",
  "labels": { "site": "hq" }
}
```

## Telemetría

```json
{
  "protocol_version": "1.0",
  "asset": null,
  "sample": {
    "agent_id": "a94a8fe5-ccb1-55b0-90f7-3dce3f15745b",
    "observed_at": "2026-08-25T15:00:00Z",
    "cpu_percent": 24.2,
    "memory_percent": 61.8,
    "disk_percent": 72.0,
    "uptime_seconds": 34020,
    "load_average": null,
    "network_rx_bytes": 1048576,
    "network_tx_bytes": 524288
  }
}
```

Por ahora, el API usa token compartido. No debe exponerse a múltiples usuarios
sin implementar RBAC, rotación, revocación y separación de credenciales.
