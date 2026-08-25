# Hoja de ruta

Lo que está marcado sin marcar no existe. La [matriz de
capacidades](CAPABILITIES.md) dice qué hay hoy; esto dice hacia dónde va.

## Fase 1 — Fundamento multiplataforma (`0.1`) ✅

- [x] Workspace Rust con dominio, servidor y agente.
- [x] Inventario, métricas y consola embebida.
- [x] Incidentes con evidencia y confianza.
- [x] SQLite, token, auditoría inicial y CI en tres sistemas.

## Fase 2 — Defensa del servidor y su red (`0.2`) ✅

- [x] Superficie expuesta con alcance derivado de la propia dirección de enlace.
- [x] Presión sobre la autenticación: ráfagas, barridos, campañas distribuidas y
      acceso concedido tras una ráfaga.
- [x] Integridad de archivos críticos por huella, sin enviar contenido.
- [x] Controles de base: firewall, parches pendientes, desviación de reloj.
- [x] Silencio del agente evaluado en el servidor.
- [x] Recursos con ventana temporal y proyección de disco.
- [x] Perímetro propio del plano de control: límite de tasa y bloqueo.
- [x] Runbooks no destructivos con inverso documentado, verificados en CI.
- [x] Postura con las superficies no inspeccionadas siempre a la vista.
- [x] Política de detección versionable y validada al arrancar.
- [x] Exportación de evidencia, métricas Prometheus y auditoría consultable.

## Fase 3 — Identidad y confianza del canal (`0.3`)

- [ ] Identidad individual por agente con inscripción y revocación.
- [ ] mTLS entre agente y plano de control.
- [ ] Firma del sobre de telemetría: que el token deje de ser suficiente para
      mentir sobre un equipo.
- [ ] Rotación de credenciales sin reinstalar la flota.
- [ ] Cifrado en reposo de la evidencia.

## Fase 4 — Observabilidad más profunda

- [ ] Inventario de procesos y servicios, con firma cuando la plataforma la
      expone.
- [ ] Correlación entre equipos: una campaña que toca a cinco servidores debería
      ser un hallazgo, no cinco.
- [ ] Líneas base por activo y por franja horaria.
- [ ] Ingesta opcional de syslog y OpenTelemetry mediante pasarelas.
- [ ] Retención por niveles y compactación del historial.

## Fase 5 — Operación en equipo

- [ ] RBAC con roles de lectura, operación y administración.
- [ ] MFA y SSO.
- [ ] Separación por organización con aislamiento estricto.
- [ ] Notificaciones salientes explícitas y revocables (correo, chat, SIEM).
- [ ] Conectores con EDR, firewall y gestores de vulnerabilidades.

## Fase 6 — Respuesta orquestada

- [ ] Playbooks declarativos con modo simulación.
- [ ] Aprobación humana obligatoria, mínimo privilegio y rollback.
- [ ] Registro completo de decisión, ejecución y resultado.

La regla que no cambia: **ninguna acción destructiva se ejecuta sin una decisión
humana registrada.** Cuando exista la orquestación, seguirá existiendo el
runbook que se puede leer antes de aceptar.

## Fase 7 — Escala

- [ ] PostgreSQL para el plano de control y almacén especializado para
      telemetría.
- [ ] Bus durable con reintentos idempotentes y contrapresión.
- [ ] Varios nodos activos y recuperación ante desastre probada.
- [ ] Agregación por sede y operación desconectada temporal.

## Fase 8 — Explicación asistida

- [ ] Asistente que explica un incidente **solo** desde la evidencia recuperada.
- [ ] Hipótesis alternativas con confianza calibrada.
- [ ] Correlación con despliegues y cambios de código.
- [ ] Evaluación reproducible contra conjuntos de datos etiquetados.
