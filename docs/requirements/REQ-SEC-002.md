# REQ-SEC-002 — Autoprotección y resiliencia

## Objetivo

Seguir entregando evidencia confiable durante fallas, y resistir abuso,
suplantación y manipulación de telemetría.

## Criterios

1. Autenticación y cifrado para conexiones remotas.
2. Identidad revocable por agente y por organización.
3. Validación estricta, límites de tamaño y control de tasa.
4. Auditoría exportable de decisiones y acciones.
5. Firma y verificación de las publicaciones.
6. Respaldos y recuperación probada.
7. Degradación controlada ante pérdida de red o de almacenamiento.
8. Acciones con simulación, aprobación, mínimo privilegio y reversión.
9. Separación entre el plano de datos y el plano de control.

## Implementación 0.2

- Token obligatorio salvo modo local explícito, comparado en tiempo constante.
- Enlace en loopback por omisión, con advertencia visible en la propia consola
  si se cambia.
- El agente se niega a enviar el token por HTTP remoto salvo autorización
  deliberada.
- Perímetro propio: límite de tasa por dirección y bloqueo tras fallos
  repetidos, evaluados **antes** de comparar la credencial.
- `X-Forwarded-For` ignorado salvo declaración explícita de proxy inverso, y esa
  declaración se rechaza si el servidor escucha en loopback.
- Límites por envío en cada colección de la superficie, y cuerpo máximo
  configurable.
- Cabeceras de seguridad en toda respuesta; `Cache-Control: no-store` en el API.
- Auditoría de cambios de estado y de cierres automáticos, exportable en NDJSON.
- Retención aplicada por un vigilante en segundo plano.
- Publicaciones con suma SHA-256, SBOM CycloneDX y atestación de procedencia.
- Acciones destructivas: **ninguna**. El runbook se escribe, no se ejecuta.

## Pendiente antes de uso empresarial

- mTLS e identidad individual por agente.
- Firma del sobre de telemetría.
- RBAC, MFA y SSO; revocación y rotación sin reinstalar la flota.
- Cifrado en reposo de la evidencia.
- Alta disponibilidad y simulacros de recuperación.
