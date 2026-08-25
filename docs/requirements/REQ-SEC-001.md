# REQ-SEC-001 — Detección de comportamiento anómalo y actividad maliciosa

## Objetivo

RootCause debe detectar desviaciones operativas y señales de posible actividad
maliciosa mediante telemetría observable, sin declararse antivirus o EDR.

## Criterios

1. Cada detección identifica activo, tiempo, regla/modelo y evidencia.
2. La severidad y confianza son campos separados.
3. Una señal individual no se presenta como causa confirmada sin correlación.
4. Las reglas son versionadas, comprobables y reversibles.
5. Las integraciones de inteligencia de amenazas conservan fuente y fecha.
6. Los falsos positivos pueden reconocerse sin borrar el historial.
7. El motor soportará métricas, logs, trazas, cambios y señales externas.

## Implementación 0.1

- Validación de rangos.
- Reglas deterministas para CPU, memoria y disco.
- Huellas estables para deduplicación.
- Evidencia, umbral y confianza por incidente.

## Pendiente

- Ventanas temporales y líneas base por activo.
- Correlación de procesos, servicios, despliegues, logs y conexiones.
- Reglas Sigma y conectores autorizados.
- Pruebas con datasets etiquetados y medición de falsos positivos.
