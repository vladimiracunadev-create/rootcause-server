# Matriz de capacidades

Esta tabla evita confundir una base funcional con una plataforma empresarial
terminada.

| Capacidad | Estado 0.1 | Alcance |
|---|---:|---|
| Servidor Rust multiplataforma | Implementado | Windows, Linux y macOS |
| Agente Rust multiplataforma | Implementado | CPU, memoria, disco, red, carga y uptime |
| Consola web embebida | Implementado | Resumen, topología, activos, incidentes y sistema |
| Persistencia | Implementado | SQLite, WAL y migraciones |
| Autenticación | Inicial | Token bearer compartido |
| Motor RCA determinista | Inicial | Saturación de CPU, memoria y disco |
| Evidencia y confianza | Implementado | Incluidas en cada incidente |
| Auditoría | Inicial | Cambio de estado de incidentes |
| Topología física de red | Planificado | Descubrimiento mediante conectores autorizados |
| RBAC, MFA y SSO | Planificado | Requerido antes de uso multiusuario remoto |
| Multi-tenancy | Planificado | Aislamiento estricto por organización |
| Alta disponibilidad | Planificado | PostgreSQL, bus durable y múltiples nodos |
| Integración SIEM/EDR/firewall | Planificado | APIs y plugins; no reimplementación |
| NetFlow, syslog y OpenTelemetry | Planificado | Gateways de ingestión |
| Playbooks | Planificado | Simulación, aprobación y rollback |
| IA explicativa | Planificado | Sólo sobre evidencia recuperable |
| Antivirus/EDR propio | Fuera de alcance | RootCause los complementa |
| Driver kernel/motor de firmas | Fuera de alcance | No pertenece al producto |
