# ADR-0003: el plano de control tiene perímetro propio, evaluado antes del token

- Estado: aceptada
- Fecha: 2026-08-25

## Contexto

RootCause Server guarda dos cosas que un atacante quiere: el token que alcanza a
todos los agentes y **el mapa de la superficie expuesta de toda la flota**. El
panel de exposición es, literalmente, el documento que alguien usaría para
elegir por dónde entrar.

La respuesta habitual —«está detrás de autenticación»— es insuficiente por dos
motivos. Primero, comparar una credencial antes de limitar la tasa convierte el
tiempo de respuesta en un oráculo para quien está adivinando. Segundo, un
producto que detecta ráfagas de autenticación en los servidores de otros y no se
defiende de una ráfaga contra sí mismo no es creíble.

## Decisión

Toda ruta protegida pasa por un perímetro en memoria que se evalúa **en este
orden**:

1. ¿Esta dirección está cumpliendo un bloqueo? → `429` con `Retry-After`.
2. ¿Agotó su presupuesto de solicitudes por minuto? → `429` con `Retry-After`.
3. Recién entonces se compara el token, en tiempo constante.

Un cubo de fichas por dirección da el límite de tasa; un contador de fallos con
expiración da el bloqueo. Ambos son por dirección, nunca globales: bloquear a un
atacante no puede dejar fuera a la flota.

`X-Forwarded-For` se ignora salvo que el operador declare que hay un proxy
inverso delante, y esa declaración se rechaza si el servidor escucha en
loopback. Sin esa regla, cualquiera elegiría qué dirección se limita.

Cada rechazo se persiste como evento de defensa y se muestra en la consola.

## Consecuencias

- El propio panel muestra lo que RootCause rechazó en su perímetro, junto a lo
  que rechazaron los servidores vigilados. La simetría es deliberada.
- El estado del perímetro es **en memoria a propósito**: tiene que sobrevivir
  una ráfaga, no un reinicio, y un reinicio es exactamente cuando un operador
  quiere partir de cero.
- Una consola con el token equivocado se bloquea a sí misma tras diez intentos.
  Es el comportamiento correcto, y la consola lo explica en vez de mostrar un
  error genérico.
- La tabla de seguimiento está acotada y desaloja la entrada más antigua: el
  control no puede convertirse en el agotamiento de memoria que evita.
