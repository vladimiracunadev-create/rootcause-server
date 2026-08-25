# REQ-SEC-001 — Detección de comportamiento anómalo y actividad maliciosa

## Objetivo

Detectar desviaciones operativas y señales de actividad maliciosa sobre
telemetría observable, sin declararse antivirus ni EDR.

## Criterios

1. Cada detección identifica activo, momento, regla y evidencia.
2. Severidad y confianza son campos separados, y ambos viajan al operador.
3. Una señal aislada no se presenta como causa confirmada. La regla de CPU
   exige una racha; la de salida anómala declara confianza 0.55 y lo dice en su
   propio texto.
4. Las reglas son versionadas, comprobables y reversibles: el catálogo lo
   publica el binario y la política se valida al arrancar.
5. Los falsos positivos se reconocen sin borrar historial: un incidente se marca
   reconocido o resuelto, y el cambio queda auditado con su autor.
6. Un hallazgo cuya condición deja de observarse se cierra solo **y registra el
   motivo**; los que describen algo que ocurrió no se cierran solos.

## Implementación 0.2

- 18 reglas publicadas, cada una con la pregunta operativa que responde y su
  técnica MITRE ATT&CK.
- Alcance derivado por el servidor a partir de la dirección de enlace: un agente
  no puede declararse en loopback estando en `0.0.0.0`.
- Ventana temporal por activo: racha de CPU, línea base de salida y proyección
  de disco se calculan sobre las muestras previas del propio equipo.
- Huellas estables por regla y clave, con fusión de las que coinciden en el
  mismo ciclo.
- Cruce de hechos que ningún registro guarda junto: acceso concedido después de
  una ráfaga fallida desde la misma dirección.
- Evidencia con valor observado y umbral, o con el hecho categórico y su
  detalle.

## Pendiente

- Correlación entre equipos: una campaña que toca cinco servidores debería ser
  un hallazgo, no cinco.
- Inventario de procesos y servicios.
- Reglas Sigma y conectores de inteligencia de amenazas con fuente y fecha.
- Medición de falsos positivos contra conjuntos de datos etiquetados.
