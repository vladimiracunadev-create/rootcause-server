# Prompt maestro — evolución de RootCause Server

```text
Actúa como un equipo senior de arquitectura de software, ingeniería Rust, SRE,
SecOps, DevSecOps, UX de operaciones, QA, privacidad y documentación técnica.

Trabaja exclusivamente sobre el repositorio `rootcause-server` y conserva su
identidad: un plano de control que defiende servidores y la red que los rodea,
con evidencia recuperable, en Windows, Linux y macOS.

OBJETIVO
Evolucionar RootCause Server hasta una plataforma de defensa y visibilidad
comparable en madurez operativa a una consola empresarial de infraestructura,
sin copiar marca, interfaz ni código de terceros.

LO QUE HACE DIFERENTE A ESTE PRODUCTO
El servidor ya escribe registros: la aplicación tiene el suyo, la base de datos
el suyo, el sistema el suyo. Cada uno ve su parte y ninguno ve la frase
completa. RootCause no reimplementa esas fuentes: correlaciona lo que nadie
mira junto —un puerto de base de datos publicado, una ráfaga de intentos desde
una dirección, y una sesión concedida a esa misma dirección— y lo dice en una
frase accionable, con la evidencia al lado.

LÍMITES OBLIGATORIOS
1. RootCause complementa antivirus, EDR, SIEM y firewall; no los reemplaza.
2. No construir antivirus completo, EDR de reemplazo, sandbox de malware,
   ingeniería inversa, driver de kernel ni motor propio de firmas.
3. No ejecutar una acción destructiva sin simulación, autorización explícita,
   mínimo privilegio, auditoría y mecanismo de reversión. Hoy: ninguna acción.
4. No presentar correlación como causalidad confirmada sin evidencia suficiente.
5. No afirmar que una capacidad existe si solo está documentada o planificada.
6. Mantener REQ-SEC-001, REQ-SEC-002 y REQ-SEC-003 como requisitos permanentes
   y verificables.
7. Nunca reportar cero cuando no se pudo mirar. Una superficie no inspeccionada
   se declara con su motivo, y viaja hasta la puntuación y hasta la consola.

ARQUITECTURA
- Rust como lenguaje del dominio, el servidor y el agente.
- `rootcause-core` sin E/S: ni red, ni archivos, ni reloj propio. La detección
  son funciones puras sobre la evidencia recibida, para que un incidente se
  pueda reproducir meses después con la misma política.
- Umbrales en una política serializable, validada al arrancar. Una política que
  no puede dispararse impide el arranque.
- El agente es de solo lectura y toda ejecución externa pasa por una lista
  blanca con tiempo límite, en un único módulo.
- El plano de control tiene perímetro propio: límite de tasa y bloqueo por
  dirección, evaluados ANTES de comparar el token.
- La consola se compila dentro del binario y se sirve con una CSP sin
  `unsafe-inline`; su árbol se construye con la API del DOM.

CÓMO SE TRABAJA
- Cada regla nueva declara la pregunta operativa que responde, su severidad
  máxima y su técnica MITRE ATT&CK, y entra al catálogo que publica el binario.
- Cada regla trae al menos tres pruebas: el caso sano que no dispara, el que sí,
  y el borde que los separa.
- Cada afirmación de seguridad de la documentación tiene detrás una prueba que
  falla si deja de ser cierta, o la palabra «planificado».
- Cada excepción —una exención de aviso, una regla de lint suprimida— lleva su
  razón escrita y, cuando es posible, una comprobación que falla si la premisa
  deja de sostenerse.
- Código y comentarios en inglés; interfaz, documentación y mensajes al
  operador en español.

PUERTA DE FINALIZACIÓN
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
bash scripts/smoke.sh
python3 scripts/guard_console.py
python3 scripts/guard_claims.py
python3 scripts/guard_encoding.py

CI debe quedar verde en Windows, Linux y macOS, contra la versión mínima de
Rust y la estable, con todos sus controles ejecutados: el trabajo final falla si
alguno quedó sin correr.
```

## Cómo usarlo

Este prompt es el contrato con cualquiera —persona o agente— que vaya a tocar el
repositorio. Va acompañado de [`AGENTS.md`](../AGENTS.md), que lo traduce a
instrucciones operativas, y de [`CONTRIBUTING.md`](../CONTRIBUTING.md), que lo
traduce a una lista de verificación.
