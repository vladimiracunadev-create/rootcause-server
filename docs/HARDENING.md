# Endurecimiento del despliegue

Un plano de control que vigila servidores es, él mismo, un objetivo de alto
valor: guarda el token que alcanza a cada agente y la evidencia de cada
incidente. Este documento describe cómo se defiende por omisión y qué tienes
que decidir tú.

## Lo que ya viene puesto

| Control | Comportamiento por omisión | Cómo cambiarlo |
|---|---|---|
| Enlace | `127.0.0.1:8080` | `--bind` / `ROOTCAUSE_BIND` |
| Autenticación | Token bearer obligatorio, mínimo 32 caracteres | `--api-token` / `ROOTCAUSE_API_TOKEN` |
| Comparación del token | Tiempo constante (`subtle::ConstantTimeEq`) | — |
| Límite de tasa | 600 solicitudes por minuto y por dirección | `--rate-limit-per-minute` |
| Bloqueo | 10 fallos de autenticación → 300 s de bloqueo | `--lockout-threshold`, `--lockout-seconds` |
| Cuerpo máximo | 1 MiB | `--max-body-kib` |
| Tiempo máximo de solicitud | 30 s | — |
| Retención | 30 días de telemetría, presión y eventos de defensa | `--retention-days` |
| `X-Forwarded-For` | **No se confía** | `--trust-forwarded-for` (solo tras un proxy) |

### El orden importa

El perímetro se evalúa **antes** de comparar el token:

1. ¿Esta dirección está bloqueada? → `429` con `Retry-After`.
2. ¿Superó su presupuesto de solicitudes? → `429` con `Retry-After`.
3. Recién entonces se compara la credencial, en tiempo constante.

Una comparación de token que ocurre antes del perímetro es un oráculo gratis
para quien esté adivinando.

### Cabeceras en toda respuesta

`Content-Security-Policy` sin `unsafe-inline` ni `unsafe-eval`,
`X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
`Permissions-Policy` con todo denegado, `Cross-Origin-Opener-Policy` y
`Cross-Origin-Resource-Policy` en `same-origin`. Las respuestas del API llevan
además `Cache-Control: no-store`: la evidencia no se sirve desde una caché
compartida.

`Strict-Transport-Security` se envía solo cuando la solicitud llegó
demostrablemente por TLS (`X-Forwarded-Proto: https`).

Un test del repositorio y el guardián `scripts/guard_console.py` impiden que la
política se debilite sin que CI lo note.

## Lo que tienes que decidir tú

### 1. TLS, siempre, si sale de loopback

RootCause no termina TLS. Ponlo detrás de Caddy, Nginx, Traefik o un balanceador
y **recién entonces** cambia `ROOTCAUSE_BIND`. Ejemplo mínimo con Caddy:

```caddyfile
rootcause.example.cl {
    reverse_proxy 127.0.0.1:8080 {
        header_up X-Forwarded-Proto {scheme}
    }
}
```

Con un proxy delante, activa `--trust-forwarded-for`. Sin él, cualquiera podría
elegir qué dirección se limita y se bloquea — por eso el servidor rechaza esa
combinación cuando detecta que escucha en loopback.

### 2. Rotación del token

Hoy todos los agentes comparten un token. Eso significa que:

- rotarlo obliga a actualizar cada agente;
- un agente comprometido entrega el token de toda la flota.

Mientras la identidad individual por agente esté en la hoja de ruta, trata ese
token como una credencial de administración: guárdalo en el gestor de secretos
de tu plataforma, no en el historial del intérprete de comandos.

### 3. El sistema de archivos

La base SQLite contiene el inventario, la telemetría y la evidencia. No la
publiques y no la respaldes a un destino menos protegido que el propio servidor.

En contenedor, el `compose.yml` de este repositorio ya monta el sistema de
archivos como solo lectura, elimina todas las capacidades, prohíbe elevar
privilegios y publica el puerto únicamente en `127.0.0.1`.

### 4. Retención

La retención por omisión (30 días) es un compromiso. Súbela si tu marco de
cumplimiento lo exige y bájala si el equipo es sensible: la evidencia que no
existe no se puede filtrar, y la que no se puede buscar no sirve.

## Lo que el agente puede hacerle a tus servidores

Nada.

- No abre sockets de escucha.
- No modifica archivos ni configuraciones.
- No aplica reglas de firewall.
- Solo ejecuta comandos de una lista blanca de solo lectura
  (`crates/rootcause-agent/src/probe.rs`), con tiempo límite y sin recibir
  entrada no confiable como argumento.
- Si no puede inspeccionar algo, lo declara como brecha en vez de reportar cero.

Puedes comprobar exactamente qué enviaría antes de enrolarlo:

```bash
rootcause-agent --dry-run
```

## Verificación

```bash
# El servidor rechaza a quien no trae token
curl -i http://127.0.0.1:8080/api/v1/status

# Y bloquea a quien insiste
for _ in $(seq 1 12); do
  curl -s -o /dev/null -H 'Authorization: Bearer mal' http://127.0.0.1:8080/api/v1/status
done
curl -i -H "Authorization: Bearer $ROOTCAUSE_API_TOKEN" http://127.0.0.1:8080/api/v1/status
```

La segunda llamada devuelve `429` con `Retry-After` aunque el token sea el
correcto: el bloqueo es por dirección, no por credencial. El panel de amenazas
muestra el conteo de lo que el propio plano de control rechazó.
