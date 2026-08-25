# Contribuir

## Antes de escribir código

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
bash scripts/smoke.sh
python3 scripts/guard_console.py
python3 scripts/guard_claims.py
```

Si eso pasa en tu máquina, CI casi siempre pasa también. `rust-toolchain.toml`
fija la versión del compilador: no hace falta elegirla.

## Cómo se estructura un cambio

| Si tocas… | También tienes que… |
|---|---|
| Una regla de detección | Añadirla a `RULES` con su pregunta y su técnica ATT&CK |
| El catálogo de reglas | Actualizar `docs/DETECCION_AMENAZAS.md`; el guardián comprueba el número |
| La superficie que recolecta el agente | Añadir un parser puro **con fixture real**, no un mock |
| Una cabecera o la CSP | `scripts/guard_console.py` debe seguir pasando |
| Un runbook | Ningún comando destructivo; el test lo hace cumplir |
| Un workflow | Pinnear a SHA completo y declarar `permissions:` |
| El esquema de la base | Migración **aditiva**: una base de la versión anterior debe seguir funcionando |

## Las reglas que no se negocian

1. **Una afirmación de seguridad necesita una prueba que falle si deja de ser
   cierta**, o la palabra «planificado». No hay tercera opción.
2. **Nunca reportar cero cuando no se pudo mirar.** Si una superficie no se
   pudo inspeccionar, se declara como `CollectionGap` con su motivo.
3. **El producto no ejecuta acciones destructivas.** El runbook se escribe y se
   revisa; ejecutarlo es una decisión humana.
4. **El núcleo no toca el mundo.** `rootcause-core` no abre sockets, no lee
   archivos y no consulta el reloj: lo recibe.
5. **La consola no gana script en línea.** Todo el árbol se construye con la API
   del DOM, porque un nombre de equipo reportado por un agente no puede
   convertirse en marcado.

## Estilo

- El código y los comentarios de código, en inglés. La interfaz, la
  documentación y los mensajes al operador, en español.
- Un comentario explica **por qué**, no qué. Si describe lo que la línea
  siguiente ya dice, sobra.
- Los nombres de las pruebas son frases: `a_public_database_is_critical`, no
  `test_exposure_1`.
- `cargo fmt` decide el formato. No discutas con él en la revisión.

## Nueva regla de detección: la lista

1. Añade la entrada a `RULES` en `crates/rootcause-core/src/detect/mod.rs`, con
   su categoría, la pregunta operativa que responde, su severidad máxima y sus
   técnicas ATT&CK.
2. Implementa el detector en el módulo de su categoría. Debe producir
   `evidence` con el valor observado y su umbral, o el hecho y su detalle.
3. Declara una `confidence` honesta. Si la señal admite una explicación
   inocente, dilo en el propio `summary` del hallazgo.
4. Si hay una respuesta posible, escribe el runbook: inspección primero,
   contención después, con el inverso documentado en la descripción.
5. Escribe al menos tres pruebas: el caso sano que **no** dispara, el caso que
   sí, y el borde que separa a los dos.
6. Actualiza `docs/DETECCION_AMENAZAS.md`.

## Commits y ramas

- Ramas desde `main`.
- Mensajes en imperativo, con el porqué en el cuerpo cuando no sea evidente.
- Un cambio, una intención. Si el mensaje necesita un «y además», probablemente
  son dos commits.

## Reportar un problema de seguridad

No abras un issue. Sigue [`SECURITY.md`](SECURITY.md).
