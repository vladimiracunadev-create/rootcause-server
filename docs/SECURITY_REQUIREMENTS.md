# Requerimientos de seguridad

## Requerimientos obligatorios

- [REQ-SEC-001 — Detección de comportamiento anómalo y actividad maliciosa](requirements/REQ-SEC-001.md)
- [REQ-SEC-002 — Autoprotección y resiliencia](requirements/REQ-SEC-002.md)

Estos requerimientos son permanentes. Todo cambio debe indicar qué controles
afecta, cómo se prueba y qué evidencia queda disponible para auditoría.

## Límites

RootCause observa, correlaciona, diagnostica y coordina. No se transforma en:

- Antivirus completo.
- EDR empresarial de reemplazo.
- Sandbox de malware.
- Plataforma de ingeniería inversa.
- Driver de kernel.
- Motor propio de firmas.

Las integraciones con esas categorías deben ser explícitas, desacopladas y
revocables.
