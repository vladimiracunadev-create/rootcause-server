# RootCause Server — instrucciones para agentes

## Misión

Un plano de control que defiende **servidores y la red que los rodea**, con
evidencia recuperable, en Windows, Linux y macOS. No duplica lo que ya registran
las aplicaciones, la base de datos o el sistema: correlaciona lo que ninguno de
ellos ve por separado.

## Lectura obligatoria antes de editar

1. `README.md`
2. `docs/ARCHITECTURE.md`
3. `docs/CAPABILITIES.md` — qué existe y qué no
4. `docs/DETECCION_AMENAZAS.md` — el catálogo real
5. `docs/SECURITY_REQUIREMENTS.md` y los tres `REQ-SEC`
6. `docs/THREAT_MODEL.md` — incluidos los riesgos aceptados
7. El ADR de la zona que vas a tocar

## Límites que no se negocian

- RootCause complementa antivirus, EDR, SIEM y firewall. **No los reemplaza.**
- No se añade sandbox de malware, ingeniería inversa, driver de kernel ni motor
  de firmas a este repositorio.
- El agente es de solo lectura. Toda ejecución externa pasa por la lista blanca
  de `probe.rs`, con tiempo límite.
- **Ninguna acción destructiva automática.** El runbook se escribe; ejecutarlo
  es una decisión humana registrada.
- Una correlación no se presenta como causalidad confirmada. La confianza es un
  campo, y el texto del hallazgo dice qué no puede distinguir.
- Nunca afirmar que una capacidad planificada existe.
- **Nunca reportar cero cuando no se pudo mirar.** REQ-SEC-003.

## Reglas de ingeniería

- Rust para dominio, servidor y agente.
- `rootcause-core` sin E/S: ni red, ni archivos, ni reloj propio. Recibe el
  instante del llamador.
- Compatibilidad de protocolo, o migración documentada **y probada**.
- Sin `unsafe`. El workspace lo prohíbe con `unsafe_code = "forbid"`.
- Dependencias mínimas, con las features por omisión desactivadas cuando sobran.
- Jamás registrar tokens, credenciales, datos personales ni cuerpos sin límite.
- Cada cambio actualiza pruebas, capacidades, modelo de amenazas y changelog.
- Código y comentarios en inglés; interfaz, documentación y mensajes al operador
  en español.

## Invariantes que CI hace cumplir

Si rompes uno de estos, el build falla. No son sugerencias:

- Ningún comando de runbook es destructivo, y la contención va precedida de
  inspección.
- La CSP no admite `unsafe-inline` ni `unsafe-eval`; la consola no tiene
  manejadores en línea, origen externo ni sumideros de marcado.
- El número de reglas de la documentación es el que compila.
- Toda acción de GitHub está pinneada a SHA completo y todo workflow declara sus
  permisos.
- Una política de detección contradictoria impide arrancar.
- Ningún control de CI puede quedar sin ejecutar.

## Puerta de finalización

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
bash scripts/smoke.sh
python3 scripts/guard_console.py
python3 scripts/guard_claims.py
```

La matriz de CI debe quedar verde en Windows, Linux y macOS, contra la versión
mínima de Rust **y** la estable.
