# 03 · Arquitectura

> Estilo arquitectónico, capas, responsabilidades, patrones y diagramas.
> Complementa —no sustituye— a [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md),
> que es el documento que mantiene el equipo. Aquí se añade el mapa mental, el
> despliegue y el modelo de datos como diagramas, y se explica cada uno en texto.

## Estilo arquitectónico

Es un **núcleo funcional puro rodeado de adaptadores** —lo que suele llamarse
arquitectura hexagonal o *ports and adapters*—, desplegado como **cliente-servidor
con push**: los agentes empujan telemetría, el servidor nunca la solicita.

Tres decisiones definen la forma del sistema, y las tres están registradas como
ADR:

| ADR | Decisión | Consecuencia visible |
|---|---|---|
| [0001](../adr/0001-rust-first-cross-platform.md) | Rust en las tres plataformas | Un solo lenguaje de dominio a servidor a sensor; sin `unsafe` |
| [0002](../adr/0002-deteccion-determinista-y-politica-versionable.md) | Detección determinista y política versionable | El motor no tiene reloj ni red; los umbrales son datos, no código |
| [0003](../adr/0003-perimetro-propio-antes-del-token.md) | Perímetro propio antes del token | Límite de tasa y bloqueo se evalúan **antes** de comparar la credencial |

**La regla que sostiene todo:** `rootcause-core` no toca el mundo. Ni red, ni
archivos, ni reloj propio —recibe el instante del llamador—. Con la misma
entrada y la misma política produce exactamente la misma salida. De ahí que un
incidente sea reproducible meses después: la evidencia se guarda tal como llegó
y una regla nueva puede reevaluarla sin pedirle nada a la flota.

## Mapa mental del sistema

```mermaid
mindmap
  root(("RootCause<br/>Server"))
    ("Dominio · rootcause-core")
      ("models.rs · contratos")
      ("security.rs · lo observado")
      ("policy.rs · umbrales")
      ("detect/ · 18 reglas")
      ("posture.rs · puntuación")
      ("runbook.rs · respuesta guiada")
    ("Sensor · rootcause-agent")
      ("collector.rs · un ciclo")
      ("net.rs · sockets y pares")
      ("authlog.rs · autenticación")
      ("integrity.rs · huellas")
      ("baseline.rs · firewall y parches")
      ("probe.rs · lista blanca")
    ("Plano de control · rootcause-server")
      ("config.rs · contrato de arranque")
      ("defense.rs · perímetro propio")
      ("auth.rs · tasa, bloqueo, token")
      ("headers.rs · CSP y cabeceras")
      ("api.rs · 19 rutas")
      ("storage.rs · SQLite")
      ("watchdog.rs · silencio y retención")
      ("ui.rs · consola embebida")
    ("Superficie visible")
      ("Consola web")
      ("API JSON")
      ("Prometheus")
      ("Exportación NDJSON")
    ("Garantías")
      ("Sin unsafe")
      ("Sin telemetría a terceros")
      ("Nunca cero donde no se miró")
      ("Runbook escrito, no ejecutado")
```

**Lectura.** El mapa se divide en las tres piezas de código, la superficie que
ve un operador y las cuatro garantías que el proyecto se impone y que CI
verifica. Nótese que el sensor tiene un módulo dedicado (`probe.rs`) cuyo único
propósito es concentrar toda ejecución externa en un lugar auditable.

## Capas y responsabilidades

```mermaid
flowchart TD
    subgraph L4["Presentación"]
        C1["console/ · consola embebida"]
        C2["landing/ · página del producto"]
    end
    subgraph L3["Interfaz HTTP"]
        H1["api.rs · rutas y contratos"]
        H2["headers.rs · CSP y cabeceras"]
        H3["error.rs · errores estables"]
        H4["ui.rs · activos embebidos"]
    end
    subgraph L2["Perímetro y aplicación"]
        A1["auth.rs · tasa, bloqueo, token"]
        A2["defense.rs · cubeta y lockout"]
        A3["state.rs · estado compartido"]
        A4["watchdog.rs · trabajos de fondo"]
        A5["config.rs · contrato de arranque"]
    end
    subgraph L1["Dominio · sin E/S"]
        D1["models.rs"]
        D2["security.rs"]
        D3["policy.rs"]
        D4["detect/"]
        D5["posture.rs"]
        D6["runbook.rs"]
    end
    subgraph L0["Persistencia"]
        P1["storage.rs"]
        P2[("SQLite<br/>migrations/")]
    end

    C1 --> H1
    H1 --> H2
    H1 --> H3
    H1 --> H4
    H1 --> A1
    A1 --> A2
    A1 --> A3
    A4 --> A3
    A5 --> A3
    H1 --> D4
    D4 --> D3
    D4 --> D1
    D4 --> D2
    D4 --> D6
    H1 --> D5
    H1 --> P1
    A4 --> P1
    P1 --> P2
```

| Capa | Responsabilidad | Qué **no** hace |
|---|---|---|
| **Presentación** | Renderizar el estado que devuelve el API | No contiene lógica de detección ni umbrales |
| **Interfaz HTTP** | Traducir HTTP a llamadas de dominio y almacenamiento; fijar cabeceras y errores | No decide severidades |
| **Perímetro y aplicación** | Decidir si una petición entra; sostener estado compartido; ejecutar trabajos periódicos | No conoce el contenido del dominio |
| **Dominio** | Modelo, política, reglas, postura y runbooks | No abre sockets, no lee archivos, no consulta el reloj |
| **Persistencia** | Guardar y consultar; deduplicar por huella; auditar | No aplica reglas |

La dependencia va siempre hacia adentro: `rootcause-server` depende de
`rootcause-core` por ruta (`path = "../rootcause-core"`), y `rootcause-core` no
depende de ninguno de los otros dos.

## Diagrama de componentes

```mermaid
flowchart LR
    subgraph agent["rootcause-agent · binario"]
        MA["main.rs<br/>CLI, transporte, reintento"]
        CO["collector.rs"]
        NE["net.rs"]
        AU["authlog.rs"]
        IN["integrity.rs"]
        BA["baseline.rs"]
        PR["probe.rs<br/>lista blanca + timeout"]
        MA --> CO
        CO --> NE
        CO --> AU
        CO --> IN
        CO --> BA
        NE --> PR
        AU --> PR
        BA --> PR
    end

    subgraph core["rootcause-core · biblioteca"]
        MO["models.rs"]
        SE["security.rs"]
        PO["policy.rs"]
        DE["detect/"]
        PS["posture.rs"]
        RB["runbook.rs"]
        DE --> PO
        DE --> MO
        DE --> SE
        DE --> RB
        PS --> MO
    end

    subgraph server["rootcause-server · binario"]
        CF["config.rs"]
        ST["state.rs"]
        DF["defense.rs"]
        AT["auth.rs"]
        HD["headers.rs"]
        AP["api.rs"]
        SG["storage.rs"]
        WD["watchdog.rs"]
        UI2["ui.rs"]
        CF --> ST
        AT --> DF
        AP --> AT
        AP --> HD
        AP --> UI2
        AP --> SG
        WD --> SG
        AP --> ST
    end

    agent -->|"HTTP + JSON<br/>Bearer"| server
    agent -.->|"usa los tipos"| core
    server -.->|"usa los tipos y el motor"| core
    UI2 -->|"rust-embed"| CONS["console/"]
```

**Lectura.** Agente y servidor comparten `rootcause-core` pero no se conocen
entre sí más allá del contrato JSON y la versión de protocolo. Toda la ejecución
de comandos del agente pasa por `probe.rs`, y toda la consola entra al binario
del servidor a través de `ui.rs`.

## Flujo principal: un ciclo de telemetría

```mermaid
sequenceDiagram
    autonumber
    participant AG as rootcause-agent
    participant PE as Perímetro (defense.rs)
    participant AU as auth.rs
    participant AP as api.rs
    participant DB as storage.rs / SQLite
    participant EN as DetectionEngine

    AG->>PE: POST /api/v1/telemetry (Bearer)
    PE->>PE: 1· cubeta de tokens por dirección
    PE->>PE: 2· ¿bloqueo activo?
    alt rechazado por el perímetro
        PE-->>AG: 429 + Retry-After
        PE->>DB: record_defense_event
    else admitido
        PE->>AU: 3· comparación del token en tiempo constante
        alt token inválido
            AU->>DB: record_failure + defense_event
            AU-->>AG: 401 unauthorized
        else token válido
            AU->>AP: solicitud admitida
            AP->>AP: protocolo admitido · muestra válida · ventana de 24 h
            AP->>DB: upsert_asset (si viene registro)
            AP->>DB: asset_registration
            AP->>DB: store_sample · store_security · record_auth_pressure
            AP->>DB: recent_samples (12) · file_baseline
            AP->>EN: DetectionInput
            EN-->>AP: candidatos ordenados por severidad
            AP->>DB: upsert_incident por cada candidato
            AP->>DB: auto_resolve (solo superficies inspeccionadas)
            AP->>DB: update_file_baseline
            AP->>DB: store_posture
            AP-->>AG: 200 {accepted, incidents_touched, warnings}
        end
    end
```

**Lo que el diagrama hace explícito:** el orden `tasa → bloqueo → token` no es
un detalle de implementación, es el ADR 0003. Comparar el token antes del
perímetro convertiría el endpoint en un oráculo gratuito para quien esté
adivinando credenciales.

Otro detalle deliberado: `auto_resolve` corre **después** de insertar los
hallazgos y **solo** sobre las categorías cuya superficie se pudo inspeccionar
en ese ciclo (`self_healing_categories` en `api.rs`). Cerrar un hallazgo de
firewall porque el agente no pudo leer el firewall es exactamente el fallo que
REQ-SEC-003 existe para evitar.

## Secuencia: el sensor que se calló

```mermaid
sequenceDiagram
    autonumber
    participant WD as watchdog.rs
    participant DB as storage.rs
    participant AS as agent_silence()
    participant CO as Consola

    loop cada 30 s
        WD->>DB: asset_heartbeats()
        DB-->>WD: (registro, last_seen) por activo
        loop por activo
            WD->>AS: policy, registro, last_seen, ahora, intervalo
            alt silencio > intervalo × silence_intervals
                AS-->>WD: IncidentCandidate (availability)
                WD->>DB: upsert_incident
            else reporta con normalidad
                AS-->>WD: None
                WD->>DB: auto_resolve(Availability)
            end
        end
        WD->>WD: perimeter.prune(900 s)
        opt cada 120 ticks (1 hora)
            WD->>DB: purge(retention_days)
        end
    end
    CO->>DB: GET /api/v1/incidents
```

**Por qué esta regla vive en el servidor y no en el agente:** un agente que fue
silenciado no puede reportar que fue silenciado. Es la única regla que se
dispara por **ausencia** de evidencia, y por eso `availability.rs` expone
`agent_silence` como función pública que llama el vigilante, en vez de
participar en `DetectionEngine::analyze`.

## Diagrama de despliegue

```mermaid
flowchart TB
    subgraph internet["Internet"]
        ATT["Origen no confiable"]
    end
    subgraph edge["Perímetro del operador"]
        PX["Proxy inverso con TLS<br/>Caddy · Nginx · Traefik"]
    end
    subgraph cp["Anfitrión del plano de control"]
        direction TB
        SV["rootcause-server<br/>escucha 127.0.0.1:8080"]
        FS[("rootcause.db<br/>SQLite + WAL")]
        SV --- FS
    end
    subgraph fleet["Servidores administrados"]
        direction LR
        A1["rootcause-agent<br/>role=edge"]
        A2["rootcause-agent<br/>role=internal"]
        A3["rootcause-agent<br/>role=database"]
    end
    PRO["Prometheus"]

    ATT -->|"escaneo, intentos de acceso"| fleet
    A1 -->|"HTTPS + Bearer"| PX
    A2 -->|"HTTPS + Bearer"| PX
    A3 -->|"HTTPS + Bearer"| PX
    PX -->|"HTTP local"| SV
    PRO -->|"GET /metrics"| SV
```

**Notas de despliegue.**

- El servidor escucha **solo en loopback por omisión**. Todo acceso remoto pasa
  por el proxy con TLS; el propio servidor no termina TLS.
- `--trust-forwarded-for` solo se activa cuando existe ese proxy, y el servidor
  rechaza la combinación contradictoria al validar la configuración.
- En Docker, el contenedor enlaza `0.0.0.0:8080` y es `compose.yml` quien
  publica el puerto exclusivamente en `127.0.0.1` del anfitrión.
- La base de datos es un archivo local. No hay réplica ni alta disponibilidad
  en esta versión: está declarado como fuera de alcance en
  [`docs/CAPABILITIES.md`](../CAPABILITIES.md).

## Modelo de datos

```mermaid
erDiagram
    ASSETS ||--o{ TELEMETRY : "produce"
    ASSETS ||--o{ INCIDENTS : "acumula"
    ASSETS ||--o{ FILE_BASELINES : "vigila"
    ASSETS ||--o{ AUTH_PRESSURE : "recibe"

    ASSETS {
        TEXT agent_id PK
        TEXT hostname
        TEXT platform
        TEXT registration_json
        TEXT first_seen
        TEXT last_seen
        TEXT latest_metrics_json
        TEXT security_json
        TEXT role
        INTEGER exposed_services
        INTEGER posture_score
    }
    TELEMETRY {
        INTEGER id PK
        TEXT agent_id FK
        TEXT observed_at
        TEXT sample_json
    }
    INCIDENTS {
        TEXT id PK
        TEXT fingerprint UK
        TEXT asset_id FK
        TEXT severity
        TEXT status
        TEXT category
        TEXT first_seen
        TEXT last_seen
        TEXT incident_json
    }
    FILE_BASELINES {
        TEXT agent_id PK
        TEXT path PK
        TEXT digest
        TEXT observed_at
    }
    AUTH_PRESSURE {
        TEXT agent_id PK
        TEXT source_address PK
        TEXT service PK
        TEXT username PK
        INTEGER failures
        INTEGER successes
        TEXT first_seen
        TEXT last_seen
    }
    DEFENSE_EVENTS {
        INTEGER id PK
        TEXT observed_at
        TEXT reason
        TEXT source
        TEXT detail
    }
    AUDIT_LOG {
        INTEGER id PK
        TEXT observed_at
        TEXT actor
        TEXT action
        TEXT target
        TEXT detail_json
    }
```

**Lectura.** Cuatro tablas cuelgan de `assets` con clave foránea y borrado en
cascada. `defense_events` y `audit_log` no tienen relación formal: el primero
registra lo que el plano de control rechazó en **su propio** perímetro —un
origen que ni siquiera llegó a nombrar un activo—, y el segundo es el rastro
inmutable de quién cambió qué. El detalle columna por columna está en
[07 · Base de datos](07-database.md).

## Patrones de diseño identificados

| Patrón | Dónde | Para qué |
|---|---|---|
| **Núcleo puro / adaptadores** | `rootcause-core` frente a los dos binarios | Detección reproducible y testeable sin infraestructura |
| **Strategy sobre datos** | `DetectionPolicy` inyectada en `DetectionEngine` | Cambiar umbrales sin recompilar; validarlos antes de aplicarlos |
| **Builder encadenado** | `DetectionInput::new().with_security().with_history()` | Entrada opcional sin constructores combinatorios |
| **Middleware / cadena de responsabilidad** | `auth::require_auth`, `headers::apply`, capas `tower-http` | Preocupaciones transversales fuera de cada handler |
| **Repository** | `storage::Database` | Todo el SQL en un módulo; los handlers no escriben consultas |
| **Token bucket** | `defense::Perimeter::check` | Límite de tasa suave por dirección, con `Retry-After` calculado |
| **Deduplicación por huella** | `fingerprint()` + `UNIQUE(fingerprint)` | Un hallazgo persistente es un incidente que se repite, no cien incidentes |
| **Catálogo publicado** | `RULES: &[RuleInfo]` | «Qué detecta hoy» sale del código, no de un documento que envejece |
| **Fail-closed en la clasificación** | `BindScope::classify` devuelve `Public` ante una dirección ilegible | Ante evidencia ambigua se reporta el caso peor |
| **Null object explícito** | `CollectionGap` | Distinguir «no hay nada» de «no se pudo mirar» |

## Procesos síncronos y asíncronos

**Síncrono** (dentro de la petición): validación, almacenamiento de la muestra,
lectura de historial y línea base, ejecución del motor, deduplicación,
auto-resolución, recálculo de postura y auditoría. Todo el ciclo de detección
ocurre antes de responder al agente, que por eso recibe en la respuesta el
número de incidentes tocados.

**Asíncrono / periódico** (`watchdog.rs`, tarea de Tokio lanzada en `main.rs`):

| Trabajo | Cadencia | Constante |
|---|---|---|
| Barrido de silencio de agentes | cada 30 s | `TICK` |
| Poda del perímetro en memoria | cada 30 s, olvidando entradas inactivas 900 s | `PERIMETER_IDLE` |
| Retención de datos | cada 120 ticks ≈ 1 hora | `PURGE_EVERY_TICKS` |

**En el agente:** ciclo propio cada `--interval-seconds`, con reintento
exponencial que duplica el intervalo hasta un techo de 300 s (`MAX_BACKOFF`) y
vuelve al normal en cuanto un envío tiene éxito. El bucle se cancela
limpiamente con Ctrl+C mediante `tokio::select!`.

## Manejo de estado

- **Estado persistente:** SQLite. Es la única fuente de verdad para activos,
  telemetría, incidentes, líneas base, presión de autenticación, eventos de
  defensa y auditoría.
- **Estado en memoria del servidor:** `AppState`, clonable y compartido por
  `Arc`. Contiene el pool de la base de datos, el motor, el perímetro, el
  instante de arranque, el token y los hechos inmutables del arranque
  (`Runtime`).
- **Estado del perímetro:** deliberadamente **solo en memoria**
  (`Mutex<HashMap<IpAddr, ClientState>>`). El módulo lo justifica: el perímetro
  debe sobrevivir a una ráfaga, no a un reinicio, y un reinicio es justo cuando
  un operador quiere empezar de cero. Tope de 20 000 direcciones vigiladas con
  desalojo de la más antigua.
- **Estado del navegador:** el token en `sessionStorage`, más filtros de vista
  en memoria. Nada más.
- **Estado del agente:** los manejadores de `sysinfo` se conservan entre ciclos
  para que las tasas tengan sentido; no hay estado en disco.

## Manejo de errores

Cuatro niveles, cada uno con una regla:

1. **Configuración.** `ServeSettings::validate` y `detection_policy` fallan al
   arrancar. Una política contradictoria **impide arrancar** en vez de degradar
   silenciosamente.
2. **HTTP.** `ApiError` produce un cuerpo estable
   `{error, code, retry_after_seconds?}` con códigos `bad_request`,
   `unauthorized`, `not_found`, `rate_limited`, `locked_out` e `internal`. Un
   error interno **registra la causa y no la devuelve**: hay una prueba que
   verifica que una cadena de conexión con contraseña no acaba en la respuesta.
3. **Recolección.** Todo fallo del agente se convierte en `CollectionGap` con
   su razón textual, viaja al servidor, vuelve como advertencia al agente y se
   muestra en la consola. Nunca se convierte en un cero.
4. **Trabajos de fondo.** El vigilante registra el error y sigue: una lectura
   fallida de latidos no debe detener la retención ni la poda.

## Autenticación y autorización

**Autenticación:** un único token *bearer* compartido entre la consola y todos
los agentes. Comparación en tiempo constante con `subtle::ConstantTimeEq`,
precedida por una comprobación de longitud.

**Autorización:** no existe. No hay roles, ni permisos, ni usuarios. Quien
tiene el token accede a todo el API. Está declarado como límite conocido en
[`docs/CAPABILITIES.md`](../CAPABILITIES.md) y desarrollado en
[11 · Seguridad](11-security.md).

Rutas públicas: `GET /healthz` y `GET /readyz`. Todo lo demás —incluido
`/metrics`— exige token.

## Persistencia y caché

- **Persistencia:** SQLite con WAL, claves foráneas activas, `synchronous =
  NORMAL`, hasta 8 conexiones (1 si la base es en memoria).
- **Estrategia de guardado:** el JSON original del agente se conserva íntegro
  (`sample_json`, `security_json`, `incident_json`, `registration_json`) junto a
  las columnas que la consola necesita para filtrar. Eso permite reevaluar una
  regla nueva contra evidencia vieja.
- **Caché:** no hay caché de aplicación. Al contrario, se impide:
  toda respuesta bajo `/api/` lleva `Cache-Control: no-store`, porque la
  evidencia no debe servirse desde una caché compartida. Los activos de la
  consola llevan `no-cache`.

## Procesos en segundo plano

Ya detallados en «Procesos síncronos y asíncronos». Un matiz operativo: la
retención **no borra incidentes ni auditoría**. `purge` elimina filas de
`telemetry`, `auth_pressure` y `defense_events` anteriores al corte. Los
incidentes y el registro de auditoría son la evidencia, y la evidencia no
caduca por omisión.

---

**Anterior:** [02 · Instalación y ejecución](02-installation-and-execution.md) ·
**Siguiente:** [04 · Mapa completo del código](04-code-map.md) ·
**Índice:** [README](README.md)
