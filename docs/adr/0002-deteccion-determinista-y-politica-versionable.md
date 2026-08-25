# ADR-0002: detección determinista con política versionable

- Estado: aceptada
- Fecha: 2026-08-25
- Sustituye parcialmente a: ADR-0001 (que solo cubría la elección de lenguaje)

## Contexto

Un hallazgo de seguridad se defiende meses después de haberse emitido: ante un
cliente, ante una auditoría o ante uno mismo a las tres de la mañana. Eso exige
poder responder dos preguntas mucho después del hecho:

1. ¿Con qué evidencia exacta se emitió?
2. ¿Con qué umbrales estaba corriendo el sistema en ese momento?

Un motor que consulta el reloj, lee archivos o llama a la red por su cuenta no
puede responder ninguna de las dos de forma reproducible.

## Decisión

`rootcause-core` no tiene E/S. No abre sockets, no lee archivos y no consulta el
reloj: recibe la marca de tiempo del llamador. Toda la detección son funciones
puras sobre `DetectionInput`.

Los umbrales viven en un `DetectionPolicy` serializable, se validan al arrancar
y se pueden versionar junto al despliegue (`--policy-file`, `GET /api/v1/policy`).
Una política cuyos números se contradicen —un umbral alto por encima del
crítico, cero muestras sostenidas— **impide arrancar el servidor**.

El almacenamiento guarda el sobre original tal como llegó, además de las
columnas por las que la consola filtra.

## Consecuencias

- Un incidente se puede reproducir exactamente: misma entrada más misma política
  igual misma salida.
- Una regla nueva puede re-evaluar evidencia antigua sin pedirle nada a la
  flota.
- Las 92 pruebas del núcleo no necesitan servidor, red ni base de datos, y
  corren en milisegundos.
- El precio: la regla de silencio, que se dispara por **ausencia** de evidencia,
  no cabe en ese modelo y vive en el servidor como un barrido periódico.
- El precio: duplicar el JSON junto a las columnas cuesta espacio. Se acepta a
  cambio de poder volver a mirar.
