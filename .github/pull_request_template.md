## Qué cambia y por qué

<!-- Una frase. El detalle va en los commits. -->

## Verificación

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] `bash scripts/smoke.sh`
- [ ] `python3 scripts/guard_console.py` y `python3 scripts/guard_claims.py`

## Si tocaste detección

- [ ] La regla está en `RULES` con su pregunta operativa y su técnica ATT&CK
- [ ] Hay una prueba del caso sano que **no** dispara, del que sí, y del borde
- [ ] La confianza declarada es honesta, y el texto dice qué no puede distinguir
- [ ] `docs/DETECCION_AMENAZAS.md` está actualizado

## Si tocaste algo que se afirma en la documentación

- [ ] Lo que afirma tiene una prueba que falla si deja de ser cierto, **o** dice
      «planificado»
- [ ] `CHANGELOG.md` recoge el cambio
- [ ] Ninguna superficie no inspeccionada se reporta como cero
