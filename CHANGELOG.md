# Changelog

Todos los cambios relevantes quedan aquí. El proyecto seguirá versionado
semántico en cuanto el API pública alcance su primera versión estable.

## [0.2.0] - 2026-08-25

El repositorio pasa de una base de observabilidad a **una plataforma de defensa
orientada a servidores y a la red que los rodea**. No duplica lo que ya
registran PHP, la base de datos o el sistema operativo: correlaciona lo que
ninguno de ellos ve por separado.

### Añadido — detección

- **Catálogo de 18 reglas publicadas por el propio binario**
  (`rootcause-server rules`, `GET /api/v1/rules`), cada una con la pregunta
  operativa que responde y su técnica MITRE ATT&CK.
- **Superficie expuesta**: sockets en escucha con el alcance derivado de la
  propia dirección de enlace (loopback, red interna, público) y un catálogo
  curado de puertos que nombra el servicio detrás de cada uno.
- **Presión sobre la autenticación**: ráfagas desde un origen, barridos de
  usuarios, campañas distribuidas y —el hallazgo que ningún registro guarda
  junto— **acceso concedido después de una ráfaga fallida**.
- **Integridad**: huellas SHA-256 de los archivos que deciden quién entra, con
  detección de cambios y de permisos debilitados. Nunca se envía contenido.
- **Higiene**: firewall del host, parches de seguridad pendientes y desviación
  de reloj.
- **Disponibilidad**: silencio del agente, evaluado en el servidor porque un
  sensor silenciado no puede reportar que lo silenciaron.
- **Recursos con memoria**: la CPU exige una racha sostenida, y el disco se
  proyecta a horas de agotarse.
- **Concentración de orígenes** y **salida de datos fuera de la línea base
  propia del host**, ambas con su confianza declarada.
- Rol del activo (`--label role=edge|internal|database`) como parte de la
  política: cambia qué se considera normal.

### Añadido — plano de control

- **Perímetro propio**: límite de tasa y bloqueo por dirección, evaluados
  **antes** de comparar el token.
- Cabeceras de seguridad en toda respuesta, con CSP sin `unsafe-inline`.
- Vigilante en segundo plano: silencio, retención y limpieza del perímetro.
- **Cierre automático** de los hallazgos cuya condición dejó de observarse, con
  el motivo registrado en la auditoría.
- Política de detección versionable y validada al arrancar: una política que no
  puede dispararse impide el arranque.
- Nuevos endpoints: `/api/v1/exposure`, `/threats`, `/rules`, `/policy`,
  `/audit`, `/export` (NDJSON), `/assets/{id}`, `/incidents/{id}/runbook`,
  `/readyz` y `/metrics` en formato Prometheus.
- Puntuación de postura por flota y por equipo, **siempre acompañada de las
  superficies que no se pudieron inspeccionar**.

### Añadido — agente

- Recolección de sockets, autenticación, integridad y controles de base en
  Linux, Windows y macOS, con un parser puro y probado por formato de salida.
- Toda ejecución externa pasa por una lista blanca de solo lectura con tiempo
  límite (`crates/rootcause-agent/src/probe.rs`).
- `--dry-run` imprime exactamente el sobre que se enviaría, antes de enrolar.
- `--watch-file` y `--watch-list` para vigilar archivos propios;
  `--metrics-only` para desactivar la superficie de seguridad declarándolo.

### Añadido — consola

- Ocho vistas: panel de defensa con postura y dimensiones, superficie expuesta
  filtrable, amenazas, incidentes con cajón de detalle, activos, topología por
  zonas, catálogo de reglas y sistema con auditoría.
- Cajón de incidente con evidencia, causa probable, acciones y **runbook
  copiable**, indicando plataforma, privilegios necesarios y reversibilidad.
- Todo el árbol se construye con la API del DOM: un nombre de equipo reportado
  por un agente no puede interpretarse como marcado.

### Añadido — ingeniería

- **247 pruebas**, incluidas 24 de integración sobre el router real y una prueba
  de humo que levanta el servidor y el agente de verdad.
- CI con catorce controles y un trabajo final que falla si **cualquiera** de
  ellos no llegó a ejecutarse.
- Guardianes propios: la consola no puede ganar script en línea ni origen
  externo; los números de la documentación se derivan del código; toda acción de
  GitHub debe estar pinneada a un SHA completo.
- SBOM CycloneDX generado en el repositorio, sin acciones de terceros.
- Publicaciones con suma SHA-256 y atestación de procedencia firmada por GitHub.
- Un test impide que un comando destructivo llegue a un runbook.

### Cambiado

- Protocolo `1.1`. Los agentes `1.0` siguen siendo aceptados: no reportan
  superficie de seguridad, y el servidor lo declara como observación en cada
  respuesta en vez de dejar el panel vacío sin explicación.
- Migración `0002` aditiva: una base creada por `0.1` sigue funcionando.
- `RcaEngine` pasa a ser `DetectionEngine`, con categorías, runbooks y técnicas
  ATT&CK en cada hallazgo.

### Corregido

- Un servicio enlazado a `0.0.0.0` y a `::` vuelve a ser **un** hallazgo: antes
  el contador de ocurrencias avanzaba dos veces por ciclo y una condición
  estable se leía como una escalada.
- Un contador de red que retrocede se interpreta como reinicio de interfaz y ya
  no puede parecer una exfiltración.

## [0.1.0] - 2026-08-25

### Añadido

- Workspace Rust con dominio compartido, servidor central y agente nativo.
- Recolección base en Windows, Linux y macOS.
- Consola web embebida con panel y topología.
- Persistencia SQLite para activos, telemetría, incidentes y auditoría.
- Detección determinista de saturación de recursos con evidencia.
- Token de API, enlace local por omisión y límite de respuesta guiada.
- CI multiplataforma, plantillas de empaquetado y requisitos de seguridad.
