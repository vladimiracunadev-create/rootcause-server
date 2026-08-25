# Modelo de amenazas

Alcance: RootCause Server `0.2`, desplegado como un nodo único que recibe
telemetría de agentes de solo lectura.

## Qué se protege

| Activo | Por qué importa |
|---|---|
| El token compartido | Alcanza a todos los agentes y a toda la evidencia |
| La evidencia de incidentes | Es lo que sostiene una decisión ante alguien más |
| El inventario y la superficie | Es un mapa de por dónde entrar a la flota |
| La base SQLite y sus respaldos | Contienen todo lo anterior |
| La disponibilidad del propio sensor | Un sensor callado es un sensor inútil |

Nótese el tercero: **el panel de superficie expuesta es exactamente el
documento que un atacante querría**. Esa es la razón por la que el plano de
control tiene perímetro propio y no solo autenticación.

## Adversarios

| Adversario | Capacidad | Qué intenta |
|---|---|---|
| Escaneo indiscriminado de Internet | Alcanza cualquier puerto publicado | Encontrar el panel o un servicio administrativo |
| Atacante que adivina credenciales | Muchos intentos, muchos orígenes | Entrar por SSH, RDP o el propio API |
| Atacante ya dentro de un servidor | Cuenta local, quizá privilegios | Ampliar acceso, borrar rastro, silenciar el sensor |
| Agente falso o comprometido | Habla el protocolo, tiene el token | Inundar el servidor o inyectar hallazgos falsos |
| Operador legítimo con error | Acceso administrativo | Publicar un servicio por accidente |
| Cadena de suministro | Controla una dependencia | Ejecutar código en el build o en el binario |

## Controles presentes en 0.2

| Amenaza | Control | Verificado por |
|---|---|---|
| Panel alcanzable desde Internet | Enlace en loopback por omisión; advertencia visible si cambia | `config.rs`, consola |
| Adivinación contra el API | Límite de tasa y bloqueo por dirección, **antes** del token | `defense.rs`, pruebas de integración |
| Fuga por comparación de token | Comparación en tiempo constante | `auth.rs` |
| Suplantación de origen | `X-Forwarded-For` ignorado salvo declaración explícita de proxy | `auth.rs`, `config.rs` |
| Inundación desde un agente | Límites por envío y cuerpo máximo de 1 MiB | `api.rs` |
| Telemetría manipulada | Ventana temporal de 24 h, validación de rangos, `scope` derivado por el servidor | `models.rs`, `security.rs` |
| Panel usado como vector | CSP sin `unsafe-inline`, árbol construido con la API del DOM | `headers.rs`, `guard_console.py` |
| Sensor silenciado | Regla de silencio evaluada en el servidor | `detect/availability.rs` |
| Registro alterado por deriva de reloj | Regla de desviación horaria | `detect/hygiene.rs` |
| Acción destructiva por el producto | El runbook nunca se ejecuta; un test prohíbe comandos destructivos | `runbook.rs` |
| Dependencia vulnerable o sustituida | `cargo audit`, `cargo deny`, SBOM, acciones pinneadas a SHA | CI |
| Secreto filtrado al repositorio | `gitleaks` sobre el histórico completo | CI |

## Riesgos aceptados

Estos riesgos existen, están decididos y no están mitigados en `0.2`:

1. **Token compartido sin revocación individual.** Un agente comprometido
   entrega el token de toda la flota. Mitigación operativa: red controlada y
   rotación manual. Solución: identidad por agente y mTLS (hoja de ruta).
2. **Sin firma de mensajes.** Quien tenga el token puede inyectar telemetría
   falsa, incluidos hallazgos que no ocurrieron o el silencio de un equipo real.
3. **Nodo único.** SQLite y el perímetro en memoria no se replican. Una caída
   del nodo es una ventana ciega.
4. **Sin cifrado en reposo.** La base se protege con los permisos del sistema de
   archivos, no con criptografía.
5. **Sin RBAC.** Quien tiene el token lo puede todo, incluido cerrar incidentes.
6. **El identificador estable del agente no es identidad criptográfica.** Se
   deriva de nombre de equipo, plataforma y arquitectura: es reproducible por
   diseño, y por lo tanto falsificable.

Por todo lo anterior: **`0.2` es apta para operar una flota propia detrás de
TLS y de una red controlada. No es apta para exponerse directamente a Internet
ni para administrar varias organizaciones.**

## Lo que un atacante consigue si gana

| Si compromete… | Obtiene | No obtiene |
|---|---|---|
| Un agente | El token, y la capacidad de mentirle al servidor sobre ese equipo | Escritura sobre otros equipos: el agente no ejecuta órdenes del servidor |
| El servidor | Inventario, superficie, evidencia y el token | Ejecución en los equipos: no existe un canal de mando |
| La base de datos | Toda la evidencia histórica | La capacidad de alterar lo ya exportado |

La ausencia de un canal de mando del servidor hacia los agentes es una decisión
de diseño, no una funcionalidad pendiente: es lo que impide que comprometer el
plano de control se convierta en comprometer la flota.
