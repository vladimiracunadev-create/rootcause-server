# Política de seguridad

## Versiones con soporte

| Versión | Estado |
|---|---|
| `0.2.x` | Con soporte |
| `0.1.x` | Sin soporte; actualiza |

## Reportar una vulnerabilidad

**No abras un issue público.** Usa el aviso privado de GitHub:

<https://github.com/vladimiracunadev-create/rootcause-server/security/advisories/new>

Incluye, en la medida de lo posible:

- versión afectada (`rootcause-server --version`) y plataforma,
- qué control se elude y con qué impacto,
- pasos reproducibles o una prueba de concepto mínima,
- si ya lo comunicaste en otro lugar.

Compromiso de respuesta:

| Momento | Qué ocurre |
|---|---|
| 72 horas | Acuso recibo y confirmo si puedo reproducirlo |
| 7 días | Evaluación de impacto y plan, contigo en copia |
| 90 días | Divulgación coordinada, o antes si ya hay corrección |

Se te acredita en el aviso salvo que pidas lo contrario.

## Qué cuenta como vulnerabilidad

Sí:

- Cualquier forma de leer o alterar la evidencia, el inventario o la superficie
  sin token válido.
- Eludir el límite de tasa o el bloqueo por dirección.
- Provocar que RootCause ejecute un comando, escriba un archivo o modifique la
  configuración de un equipo vigilado.
- Ejecución de script en la consola a partir de datos reportados por un agente.
- Fuga del token en un registro, en una respuesta del API o en un artefacto de
  publicación.
- Un agente que consigue que el servidor emita un hallazgo falso **para otro
  activo**.
- Cualquier salida de datos hacia un destino que no sea el servidor configurado.

No, y está documentado como riesgo aceptado en
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md):

- Que el token compartido sirva para toda la flota: no hay identidad individual
  todavía.
- Que quien tenga el token pueda inyectar telemetría: no hay firma de mensajes
  todavía.
- Que la base SQLite no esté cifrada en reposo.
- Que no exista RBAC: quien tiene el token lo puede todo.
- Que el identificador estable del agente sea reproducible: es por diseño, y por
  eso no constituye identidad criptográfica.

Si encuentras una forma de convertir uno de esos riesgos aceptados en algo peor
de lo documentado, **eso sí** es un reporte.

## Cómo se defiende este repositorio

- Todas las acciones de GitHub están pinneadas a un SHA completo, y un guardián
  falla el build si alguna deja de estarlo.
- `cargo audit` y `cargo deny` en cada cambio y cada semana.
- `gitleaks` sobre el histórico completo.
- `zizmor` y `actionlint` sobre los propios workflows.
- CodeQL sobre el JavaScript de la consola y sobre los workflows.
- Análisis de la imagen de contenedor.
- Cada publicación lleva suma SHA-256, SBOM CycloneDX y atestación de
  procedencia verificable con `gh attestation verify`.

Detalles de despliegue en [`docs/HARDENING.md`](docs/HARDENING.md).

## Lo que este producto nunca hará

- Ejecutar un comando de un runbook por su cuenta.
- Enviar datos a un destino que no hayas configurado.
- Pedirte una contraseña, una clave privada o una semilla.
- Instalar actualizaciones sin que las pidas.

Si alguna versión hace alguna de esas cosas, es un defecto de seguridad y quiero
enterarme.
