# REQ-SEC-003 — Honestidad de la cobertura

## Objetivo

Que nadie pueda confundir «no se encontró nada» con «no se pudo mirar». Este
requisito existe porque el modo de fallo más peligroso de una herramienta de
seguridad no es el falso positivo: es el silencio tranquilizador.

## Criterios

1. **Toda superficie que no se pudo inspeccionar se declara**, con el motivo, y
   viaja hasta la consola y hasta la puntuación de postura.
2. Una lista vacía por falta de permisos **nunca** se presenta igual que una
   lista vacía por ausencia de hallazgos.
3. Una plataforma sin recolector implementado lo dice; no reporta cero.
4. La puntuación de postura viaja siempre acompañada de sus superficies no
   inspeccionadas.
5. El catálogo de lo que se detecta lo publica el binario, no la documentación.
6. La documentación no puede afirmar un número que el código contradiga.
7. Todo hallazgo declara su confianza, y el texto del hallazgo dice qué no puede
   distinguir.

## Implementación 0.2

- `CollectionGap { surface, reason }` en el propio sobre de telemetría; el
  servidor lo devuelve como observación al agente y lo muestra en la consola.
- El agente declara brecha cuando falta `ufw`/`firewalld`/`nft`, cuando
  `wevtutil` no puede leer el registro de seguridad, cuando un archivo vigilado
  existe pero no se puede leer, y cuando la plataforma no tiene recolector.
- `--metrics-only` no oculta la superficie: la declara desactivada.
- `PostureScore.uninspected_surfaces` acompaña a cada puntuación.
- `ExposureReport.uninspected_assets` lista los equipos sin superficie
  reportada, con el texto «un equipo sin superficie reportada no es un equipo
  sin puertos abiertos».
- La regla de silencio dice explícitamente que un apagado planificado, una
  caída de red y un agente detenido a propósito se ven idénticos desde el plano
  de control.
- `scripts/guard_claims.py` falla el build si un número de la documentación deja
  de coincidir con el código.
- `docs/CAPABILITIES.md` y `docs/DETECCION_AMENAZAS.md` incluyen una sección
  explícita de lo que **no** se detecta.

## Pendiente

- Cobertura por activo visible en la consola: qué superficies se inspeccionaron
  y cuáles no, equipo por equipo y no solo en agregado.
- Antigüedad de la última inspección exitosa por superficie.
