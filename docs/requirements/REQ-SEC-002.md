# REQ-SEC-002 — Autoprotección y resiliencia

## Objetivo

RootCause debe continuar entregando evidencia confiable durante fallas y debe
resistir abuso, suplantación, manipulación de telemetría y acciones no
autorizadas.

## Criterios

1. Autenticación y cifrado para conexiones remotas.
2. Identidad revocable por agente y organización.
3. Validación estricta, límites de tamaño y control de tasa.
4. Auditoría inmutable o exportable de decisiones y acciones.
5. Firma y verificación de actualizaciones.
6. Respaldos cifrados y recuperación probada.
7. Degradación controlada ante pérdida de red o almacenamiento.
8. Acciones con simulación, aprobación, mínimo privilegio y rollback.
9. Separación entre plano de datos y plano de control.

## Implementación 0.1

- Token obligatorio salvo modo local explícito.
- Bind local por defecto.
- Rechazo de tokens sobre HTTP remoto desde el agente.
- Límite de cuerpo de 1 MiB.
- SQLite WAL, migraciones y cierre ordenado.
- Agente de sólo lectura.

## Pendiente antes de producción empresarial

- mTLS e identidad individual de agentes.
- RBAC, MFA/SSO, revocación y rotación.
- Control de tasa y protección distribuida.
- Firma de binarios, SBOM y canal seguro de actualización.
- Alta disponibilidad y simulacros de recuperación.
