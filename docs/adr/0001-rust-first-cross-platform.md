# ADR-0001: núcleo Rust y consola web embebida

- Estado: aceptada
- Fecha: 2026-08-25

## Contexto

RootCause Server debe operar en Windows, Linux y macOS con consumo acotado,
binarios fáciles de distribuir y contratos compartidos con el agente.

## Decisión

Usar un workspace Rust para dominio, servidor y agente. La consola HTML/CSS/JS
se embebe en el binario del servidor y consume la API REST.

## Consecuencias

- Un lenguaje para los componentes críticos.
- Seguridad de memoria y concurrencia sin recolector de basura.
- Distribución nativa por plataforma.
- La interfaz no requiere un runtime Node.js en producción.
- Firma, notarización e instaladores siguen siendo específicos de cada sistema.
