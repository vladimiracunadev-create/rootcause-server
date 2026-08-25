# Matriz de capacidades

Esta tabla existe para que nadie confunda una base funcional con una plataforma
empresarial terminada. Lo que dice **Implementado** está cubierto por pruebas;
lo que dice **Planificado** no existe todavía, por mucho que suene razonable.

## Detección

| Capacidad | Estado 0.2 | Alcance real |
|---|---|---|
| Catálogo de reglas publicado por el binario | Implementado | `rootcause-server rules` y `GET /api/v1/rules` |
| Superficie expuesta con alcance derivado | Implementado | loopback / red interna / público, por socket |
| Ráfagas, barridos y campañas de autenticación | Implementado | Linux (`journalctl`, `auth.log`) y Windows (evento 4625) |
| Acceso concedido tras ráfaga fallida | Implementado | Cruce de dos hechos que ningún registro guarda junto |
| Integridad de archivos críticos | Implementado | Huella SHA-256; nunca se envía contenido |
| Permisos debilitados | Implementado | Solo en plataformas con bits POSIX |
| Firewall del host | Implementado | ufw, firewalld, nftables, Windows, macOS |
| Parches de seguridad pendientes | Implementado | Debian y derivados; RHEL y derivados |
| Desviación de reloj | Implementado | Agente contra servidor |
| Silencio del agente | Implementado | Evaluado en el servidor, no en el agente |
| Recursos con ventana temporal | Implementado | CPU sostenida, memoria, disco y proyección |
| Salida de datos anómala | Inicial | Línea base propia del host, confianza declarada |
| Concentración de orígenes | Inicial | Señal de reconocimiento, no prueba |
| Inventario de procesos y firma | Planificado | Requiere permisos elevados y una decisión de alcance |
| Descubrimiento activo de red | Fuera de alcance | RootCause no escanea redes ajenas |
| Motor de firmas de malware | Fuera de alcance | Es trabajo del antivirus y del EDR |

## Plano de control

| Capacidad | Estado 0.2 | Alcance real |
|---|---|---|
| Servidor y agente multiplataforma | Implementado | Windows, Linux y macOS, probados en CI |
| Consola web embebida en el binario | Implementado | Ocho vistas, sin dependencias web |
| Persistencia | Implementado | SQLite con WAL y migraciones |
| Autenticación | Inicial | Token bearer compartido, comparación en tiempo constante |
| Perímetro propio | Implementado | Límite de tasa y bloqueo por dirección, antes del token |
| Cabeceras de seguridad y CSP | Implementado | Sin `unsafe-inline`; verificado en CI |
| Auditoría | Implementado | Cambios de estado y cierres automáticos |
| Retención y limpieza | Implementado | Configurable en días, aplicada por el vigilante |
| Exportación de evidencia | Implementado | NDJSON tipado por `kind` |
| Métricas Prometheus | Implementado | Postura, incidentes por categoría, perímetro |
| Política de detección versionable | Implementado | JSON validado al arrancar |
| Respuesta guiada | Implementado | Runbook con inverso; **nunca se ejecuta** |
| Identidad individual por agente y mTLS | Planificado | Hoy todos comparten un token |
| RBAC, MFA y SSO | Planificado | Requisito antes de uso multiusuario remoto |
| Multi-tenencia | Planificado | Aislamiento estricto por organización |
| Alta disponibilidad | Planificado | PostgreSQL, bus durable y varios nodos |
| Conectores SIEM, EDR y firewall | Planificado | API y complementos; no reimplementación |
| NetFlow, syslog y OpenTelemetry | Planificado | Pasarelas de ingesta |
| Playbooks con simulación y aprobación | Planificado | Hoy el runbook es texto revisado |
| Asistente explicativo | Planificado | Solo sobre evidencia recuperable |

## Lo que RootCause Server no es

- **No es un antivirus ni un EDR.** No inspecciona memoria, no engancha
  syscalls y no tiene firmas. Los complementa.
- **No es un firewall.** Lee su estado y escribe el comando; no lo aplica.
- **No es un SIEM.** No ingiere los registros de tus aplicaciones: correlaciona
  la superficie del sistema que esos registros no cubren.
- **No es una alternativa completa a una plataforma como FortiOS.** Esa
  comparación necesitaría, como mínimo, todo lo que esta tabla marca como
  planificado.
