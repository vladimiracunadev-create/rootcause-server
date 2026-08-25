# Requisitos de seguridad

## Requisitos permanentes

- [REQ-SEC-001 — Detección de comportamiento anómalo y actividad maliciosa](requirements/REQ-SEC-001.md)
- [REQ-SEC-002 — Autoprotección y resiliencia](requirements/REQ-SEC-002.md)
- [REQ-SEC-003 — Honestidad de la cobertura](requirements/REQ-SEC-003.md)

Son permanentes: no se cierran con una versión. Todo cambio debe declarar qué
control toca, cómo se prueba y qué evidencia deja para una auditoría posterior.

## Invariantes que CI hace cumplir

Estos no son deseos: si dejan de ser ciertos, el build falla.

| Invariante | Dónde se comprueba |
|---|---|
| Ningún comando de un runbook es destructivo | `runbook.rs`, test `no_destructive_commands` |
| Todo paso de contención va precedido de una inspección | `runbook.rs`, test |
| La CSP no admite `unsafe-inline` ni `unsafe-eval` | `headers.rs` + `scripts/guard_console.py` |
| La consola no tiene manejadores en línea, origen externo ni sumideros de marcado | `scripts/guard_console.py` |
| El número de reglas de la documentación es el que compila | `scripts/guard_claims.py` |
| Toda acción de GitHub está pinneada a un SHA completo | `scripts/guard_claims.py` |
| Todo workflow declara sus permisos | `scripts/guard_claims.py` |
| El perímetro se evalúa antes de comparar el token | pruebas de integración `control_plane.rs` |
| Una política contradictoria impide arrancar | `policy.rs`, test |
| El agente solo ejecuta comandos de la lista blanca | `probe.rs`, test |
| Ningún control de CI puede quedar sin ejecutar | trabajo `gate` de `ci.yml` |

## Límites del producto

RootCause observa, correlaciona, diagnostica y propone. No se convierte en:

- antivirus completo,
- EDR de reemplazo,
- sandbox de malware,
- plataforma de ingeniería inversa,
- driver de kernel,
- motor propio de firmas.

Cualquier integración con esas categorías debe ser explícita, desacoplada y
revocable.

## Regla de las afirmaciones

Ninguna afirmación de seguridad entra en la documentación sin una de estas dos
cosas detrás:

1. una prueba que falla si deja de ser cierta, o
2. la palabra «planificado».
