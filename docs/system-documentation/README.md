# Documentación del sistema — RootCause Server

Portada e índice navegable de la documentación de análisis, arquitectura,
código, datos, seguridad y operación del repositorio `rootcause-server`.

## El sistema, en una frase

**RootCause Server** es un plano de control escrito en Rust que vigila un
conjunto de servidores y la red que los rodea: recibe telemetría de un agente
de solo lectura instalado en cada equipo, aplica 18 reglas de detección
deterministas, y presenta cada hallazgo con su evidencia, su causa y un
*runbook* que nunca ejecuta por su cuenta.

## Propósito de esta documentación

Convertir la lectura completa del repositorio en material que sirva a cinco
públicos distintos sin obligar a ninguno a leer el código fuente:

| Público | Empieza por |
|---|---|
| Persona ajena al sistema | [01 · Descripción general](01-system-overview.md) y [17 · Resumen ejecutivo](17-executive-summary.md) |
| Desarrollador que se incorpora | [18 · Guía para un nuevo desarrollador](18-new-developer-guide.md) |
| Desarrollador experimentado | [05 · Referencia técnica](05-technical-reference.md) y [06 · Explicación profunda del código](06-deep-code-explanation.md) |
| Auditor | [11 · Seguridad](11-security.md), [15 · Riesgos y deuda técnica](15-risks-and-technical-debt.md), [19 · Matriz de trazabilidad](19-traceability-matrix.md) |
| Agente de IA | [04 · Mapa del código](04-code-map.md) y [19 · Matriz de trazabilidad](19-traceability-matrix.md) |

## Tabla de contenidos

| # | Documento | Contenido | Estado |
|---|---|---|---|
| — | [README](README.md) | Portada, índice y convenciones | Completo |
| 01 | [Descripción general del sistema](01-system-overview.md) | Qué es, qué resuelve, para quién, con una sección no técnica | Completo |
| 02 | [Instalación y ejecución](02-installation-and-execution.md) | Requisitos, compilación, arranque, pruebas, errores frecuentes | Completo |
| 03 | [Arquitectura](03-architecture.md) | Estilo, capas, patrones y siete diagramas Mermaid | Completo |
| 04 | [Mapa completo del código](04-code-map.md) | Inventario jerárquico de directorios, módulos y símbolos | Completo |
| 05 | [Referencia técnica](05-technical-reference.md) | Catálogo de tipos, funciones, variables de entorno, endpoints y errores | Completo |
| 06 | [Explicación profunda del código](06-deep-code-explanation.md) | Flujo interno, condicionales y casos límite módulo por módulo | Completo |
| 07 | [Base de datos](07-database.md) | Motor, esquema, diccionario de datos, migraciones y diagrama E-R | Completo |
| 08 | [Flujo de datos](08-data-flow.md) | Origen, validación, transformación, almacenamiento y consumo | Completo |
| 09 | [APIs e integraciones](09-apis-and-integrations.md) | Contrato HTTP, códigos de estado, Prometheus y exportación | Completo |
| 10 | [Configuración](10-configuration.md) | Variables, valores por omisión y consecuencias de equivocarse | Completo |
| 11 | [Seguridad](11-security.md) | Autenticación, perímetro, cabeceras, secretos y controles ausentes | Completo |
| 12 | [Pruebas y calidad](12-testing-and-quality.md) | Tipos de prueba, cobertura, CI y pruebas faltantes priorizadas | Completo |
| 13 | [Despliegue y operación](13-deployment-and-operations.md) | Entornos, contenedor, servicios del sistema, CI/CD y respaldo | Completo |
| 14 | [Solución de problemas](14-troubleshooting.md) | Síntoma, causa, diagnóstico y solución | Completo |
| 15 | [Riesgos y deuda técnica](15-risks-and-technical-debt.md) | Hallazgos clasificados por severidad, impacto y evidencia | Completo |
| 16 | [Glosario](16-glossary.md) | Términos técnicos y de dominio en lenguaje comprensible | Completo |
| 17 | [Resumen ejecutivo](17-executive-summary.md) | Presentación para decisión, sin detalle innecesario | Completo |
| 18 | [Guía para un nuevo desarrollador](18-new-developer-guide.md) | Itinerario de incorporación y primeras tareas | Completo |
| 19 | [Matriz de trazabilidad](19-traceability-matrix.md) | De la funcionalidad a la tabla y a la prueba | Completo |

### Recursos

- [`assets/`](assets/) — material gráfico de apoyo. Los diagramas viven
  embebidos en Mermaid dentro de los documentos, así que hoy esta carpeta
  contiene solo la nota que lo explica.
- [`pdf/`](pdf/) — los 20 documentos de esta carpeta en PDF, generados desde el
  Markdown —que es la única fuente— con
  [`scripts/docs_pdf.py`](../../scripts/docs_pdf.py):

  ```bash
  python3 scripts/docs_pdf.py
  ```

  El script convierte el Markdown a HTML con la biblioteca estándar de Python,
  dibuja los diagramas Mermaid con `mmdc` y manda imprimir con Chrome, Chromium
  o Edge en modo headless. Si falta `mmdc` o el navegador, avisa y entrega lo
  que sí puede producir en lugar de fallar en silencio.

## Documentación previa del repositorio

Esta carpeta **no reemplaza** la documentación que el proyecto ya mantenía en
[`docs/`](../): la referencia, la enlaza y la amplía. Los documentos originales
siguen siendo la fuente autoritativa de su tema.

| Documento existente | Tema |
|---|---|
| [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md) | Arquitectura, tal como la mantiene el equipo |
| [`docs/API.md`](../API.md) | Contrato del API |
| [`docs/CAPABILITIES.md`](../CAPABILITIES.md) | Matriz de capacidades y límites declarados |
| [`docs/DETECCION_AMENAZAS.md`](../DETECCION_AMENAZAS.md) | Catálogo de amenazas detectadas |
| [`docs/HARDENING.md`](../HARDENING.md) | Endurecimiento del despliegue |
| [`docs/INSTALLATION.md`](../INSTALLATION.md) | Instalación multiplataforma |
| [`docs/MANUAL_USUARIO.md`](../MANUAL_USUARIO.md) | Manual de operación |
| [`docs/THREAT_MODEL.md`](../THREAT_MODEL.md) | Modelo de amenazas |
| [`docs/SECURITY_REQUIREMENTS.md`](../SECURITY_REQUIREMENTS.md) | Requisitos de seguridad |
| [`docs/CROSS_PLATFORM.md`](../CROSS_PLATFORM.md) | Diferencias entre Windows, Linux y macOS |
| [`docs/POLITICA_DE_PRIVACIDAD_LOCAL.md`](../POLITICA_DE_PRIVACIDAD_LOCAL.md) | Qué datos se procesan y dónde quedan |
| [`docs/ROADMAP.md`](../ROADMAP.md) | Hoja de ruta |
| [`docs/MASTER_PROMPT.md`](../MASTER_PROMPT.md) | Prompt maestro del proyecto |
| [`docs/adr/`](../adr/) | Decisiones de arquitectura registradas |
| [`docs/requirements/`](../requirements/) | REQ-SEC-001, 002 y 003 |

## Datos del análisis

| Dato | Valor |
|---|---|
| Fecha del análisis | 2026-08-26 |
| Versión analizada | `0.2.0` (`Cargo.toml`, `[workspace.package]`) |
| Commit analizado | `2efedb2180dcecac6dc66e8e48a2cce90ebc6c3d` |
| Rama | `main` |
| Estado del árbol de trabajo | Limpio al iniciar el análisis |
| Lenguaje principal | Rust `1.95.0` (edición 2024) |
| Lenguajes auxiliares | JavaScript (consola), Python (guardianes y utilidades), SQL, HTML, CSS |
| Archivos de código analizados | 33 archivos Rust, 4 de consola, 4 scripts Python, 2 migraciones SQL |
| Reglas de detección publicadas | 18 |
| Anotaciones de prueba en el código | 253 (`#[test]` y `#[tokio::test]`) |

## Convenciones

**Marcadores de certeza.** Cuando una afirmación no se pudo comprobar contra el
repositorio, aparece marcada:

| Marcador | Significado |
|---|---|
| *No identificado* | Se buscó y no se encontró nada en el repositorio |
| *No documentado en el repositorio* | Existe en el código, pero el repositorio no explica la intención |
| *Requiere validación* | Solo puede confirmarlo una persona con acceso al entorno real |
| *Inferencia basada en el código* | Conclusión razonada a partir del código, no una afirmación del repositorio |

**Otras convenciones.**

- Los nombres de archivos, funciones, tipos, tablas y columnas se conservan
  literales, para que cualquier afirmación se pueda verificar con `grep`.
- Las rutas se escriben relativas a la raíz del repositorio.
- Los comandos son ejecutables tal cual; los valores sensibles siempre son
  ficticios (`reemplaza-por-...`, `203.0.113.10`, `pega-aqui-el-token`).
- Idioma: documentación en español, igual que el resto del proyecto. El código
  y sus comentarios están en inglés, por decisión del propio repositorio
  ([`AGENTS.md`](../../AGENTS.md)).
- Los diagramas van siempre acompañados de su explicación en texto: ningún
  diagrama es la única fuente de una idea.

## Pendiente de validar

Lista viva de lo que este análisis **no** pudo confirmar leyendo el repositorio.
Cada punto está desarrollado en el documento que lo menciona.

| # | Pendiente | Dónde se detalla |
|---|---|---|
| 1 | El directorio `config/` existe en la copia de trabajo pero **no está en el repositorio** (git no versiona directorios vacíos) | [04](04-code-map.md), [15](15-risks-and-technical-debt.md) |
| 2 | Que el respaldo se ejecute de forma programada, salga del anfitrión y **se restaure alguna vez**: el script existe, el proceso lo pone quien opera | [07](07-database.md), [13](13-deployment-and-operations.md) |
| 3 | La firma y la atestación de procedencia de los artefactos de publicación no se pudieron verificar sin ejecutar el workflow | [13](13-deployment-and-operations.md) |
| 4 | El comportamiento de los parsers frente a salidas de `ss` y `netstat` no cubiertas por fixtures | [12](12-testing-and-quality.md), [15](15-risks-and-technical-debt.md) |
| 5 | El instalador de Windows (`packaging/windows/rootcause-server.iss`) no se compiló en este análisis | [13](13-deployment-and-operations.md) |

---

*Generado por análisis directo del repositorio el 2026-08-26 sobre el commit
`2efedb2`. Toda cifra de este conjunto documental proviene del código, no de la
documentación previa.*
