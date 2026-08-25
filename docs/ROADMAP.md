# Hoja de ruta

## Fase 1 — Fundamento multiplataforma (`0.1`)

- [x] Workspace Rust.
- [x] Servidor, agente y consola embebida.
- [x] Inventario, métricas y topología básica.
- [x] Incidentes con evidencia y confianza.
- [x] SQLite, token, auditoría inicial y CI de tres sistemas.

## Fase 2 — Observabilidad profunda

- [ ] Ventanas temporales, baselines y resolución automática verificada.
- [ ] Procesos, servicios, eventos del sistema y cambios de software opt-in.
- [ ] OpenTelemetry, syslog, SNMP y NetFlow mediante gateways.
- [ ] Mapa de dependencias de aplicaciones y red.
- [ ] Retención, compactación y exportación.

## Fase 3 — Seguridad y control empresarial

- [ ] Identidad individual de agentes y mTLS.
- [ ] RBAC, MFA/SSO y separación por organización.
- [ ] Firmas, SBOM, actualizador seguro y rotación de credenciales.
- [ ] Conectores con SIEM, EDR, firewall y gestores de vulnerabilidades.
- [ ] Políticas y perfiles de detección versionados.

## Fase 4 — Respuesta orquestada

- [ ] Playbooks declarativos y modo simulación.
- [ ] Aprobación humana, mínimo privilegio y rollback.
- [ ] Integraciones para aislar, reiniciar, revertir o abrir tickets.
- [ ] Registro completo de decisiones y resultados.

## Fase 5 — Escala y alta disponibilidad

- [ ] PostgreSQL para control y almacén especializado para telemetría.
- [ ] Bus durable, backpressure y reintentos idempotentes.
- [ ] Clúster activo-activo y recuperación ante desastre.
- [ ] Agregación por sedes y operación desconectada temporal.

## Fase 6 — Inteligencia asistida

- [ ] Asistente que explica incidentes sólo desde evidencia recuperada.
- [ ] Hipótesis alternativas y nivel de confianza calibrado.
- [ ] Correlación con cambios de código y despliegues.
- [ ] Evaluaciones reproducibles contra datasets etiquetados.
