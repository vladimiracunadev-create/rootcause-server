# Qué detecta RootCause Server, amenaza por amenaza

Este documento es la lista completa y honesta. No hay una regla que exista aquí
y no en el código: el catálogo lo publica el propio binario
(`rootcause-server rules`, `GET /api/v1/rules`) y CI falla si el número que
aparece en la documentación deja de coincidir con el que compila.

Cada regla se describe por **la pregunta operativa que responde**, no por la
tecnología que usa. Una regla que no responde una pregunta que alguien se hace
a las tres de la mañana no debería existir.

## Cómo leer la severidad

La severidad **no** es una propiedad del servicio: es el producto de lo que el
servicio es por lo lejos que se alcanza.

| Alcance | Qué significa | Efecto |
|---|---|---|
| `loopback` | Solo desde el propio equipo | Nunca genera hallazgo de exposición |
| `private` | Desde la red interna (RFC1918, CGNAT, enlace local, ULA) | Baja un escalón |
| `public` | Desde cualquier interfaz, incluidas las públicas | Severidad plena |

Una dirección que no se puede interpretar se trata como `public`: cuando la
evidencia es ambigua, el producto reporta el **peor** caso y lo dice, en vez de
rebajar el hallazgo en silencio.

El rol declarado del equipo también cambia lo que es normal:

- `--label role=edge` → se espera que publique 80 y 443; no se espera que
  publique SSH.
- `--label role=database` → **cualquier** servicio conocido alcanzable desde
  fuera es crítico.
- `--label role=internal` (por omisión) → nada debería ser público.

---

## Superficie expuesta

### `exposure.service.public`

**¿Hay un servicio escuchando en una dirección que no es loopback?**

El agente enumera los sockets en escucha del equipo y deriva el alcance de la
propia dirección de enlace. La evidencia incluye el proceso y su PID cuando el
sistema los expone.

- Bases de datos e infraestructura (`5432`, `3306`, `27017`, `6379`, `9200`,
  `2375`, `6443`, `10250`, `2379`…) → **crítico**
- Administración remota (`22`, `3389`, `5985`, `5900`, `623`) y compartición de
  archivos (`445`, `2049`, `139`) → **alto**
- Correo y aplicaciones web → **medio**
- Todo lo demás → **bajo**

ATT&CK: `T1190`. Runbook: identificar el proceso, limitar el puerto, reenlazar
el servicio a la interfaz mínima y verificar **desde fuera** que dejó de
responder.

### `exposure.cleartext.protocol`

**¿Se publican credenciales en claro por Telnet, FTP, LDAP o POP3?**

Aquí no hace falta explotar nada: quien observe la red obtiene la credencial.
Severidad **alta** aunque el servicio esté al día.

ATT&CK: `T1040`, `T1190`.

---

## Intrusión

### `intrusion.auth.bruteforce`

**¿Un mismo origen acumula intentos fallidos contra este servidor?**

Un servicio de autenticación expuesto recibe intentos automatizados de forma
permanente. Lo que convierte esto en un incidente es **el volumen y su
persistencia**, no su existencia. Umbral por omisión: 20 intentos (alto), 100
(crítico).

Fuentes: `journalctl _COMM=sshd` o `/var/log/auth.log` en Linux; eventos 4625
del registro de seguridad en Windows. **El agente agrega antes de enviar**: al
servidor viaja `(servicio, origen, usuario, resultado, conteo)`, nunca la línea
del registro.

ATT&CK: `T1110.001`. Runbook: confirmar que el origen no es legítimo →
`ufw deny from …` / `New-NetFirewallRule …`, con su inverso documentado.

### `intrusion.auth.spray`

**¿Un origen prueba muchos nombres de usuario distintos?**

Cinco o más usuarios distintos desde una sola dirección no es alguien que olvidó
su clave: es una lista. La evidencia incluye una muestra de los usuarios
probados, para poder responder la pregunta que de verdad importa —¿alguno de
ellos existe?—.

ATT&CK: `T1110.003`.

### `intrusion.auth.distributed`

**¿Muchos orígenes distintos fallan contra el mismo servidor?**

Diez o más direcciones con intentos fallidos en la misma ventana. Se reporta
aparte porque **cambia la respuesta**: bloquear una por una no contiene una
campaña distribuida.

ATT&CK: `T1110`.

### `intrusion.auth.success_after_burst`

**¿Un origen que fallaba repetidamente consiguió entrar?**

El hallazgo más importante del producto. Cruza dos hechos que ningún registro
guarda juntos: la ráfaga fallida y el acceso concedido después, desde la misma
dirección. Severidad **crítica** siempre. La recomendación no es bloquear: es
revisar sesiones activas, rotar credenciales y buscar persistencia creada
después del acceso.

ATT&CK: `T1110`, `T1078`.

### `intrusion.network.fanin`

**¿Demasiadas direcciones distintas tocan el host a la vez?**

Puede ser un balanceador legítimo o el reconocimiento previo a un intento
dirigido. La diferencia está en si esos orígenes son conocidos, y el hallazgo lo
dice con esas palabras: confianza 0.62, no 0.99.

ATT&CK: `T1046`, `T1595`.

### `intrusion.egress.anomaly`

**¿El tráfico de salida se disparó respecto de su propia línea base?**

La línea base se construye con las muestras previas **del propio host**, no con
un umbral universal. Requiere al menos tres muestras y un piso absoluto, para no
convertir un servidor tranquilo en una alarma. Un respaldo lo explica; una
exfiltración también: por eso la confianza es 0.55 y la primera acción es
identificar proceso y destino, no cortar.

ATT&CK: `T1041`.

---

## Integridad

### `integrity.file.changed`

**¿Cambió un archivo de configuración que sostiene la seguridad del host?**

El agente calcula huellas SHA-256; **nunca envía contenido**. Un digest basta
para probar que algo cambió y es inútil para leer lo que dice — la única
combinación aceptable para `/etc/shadow`.

La primera observación solo establece la línea base: no genera hallazgo. A
partir de ahí, cualquier cambio no anunciado lo genera. Los archivos que
gobiernan el acceso (`sshd_config`, `sudoers`, `passwd`, `authorized_keys`,
`pam.d`, `crontab`, `hosts.allow`) son **altos**; el resto, medios.

ATT&CK: `T1543`, `T1098`.

### `integrity.file.permissions`

**¿Un archivo sensible quedó escribible por cualquier usuario?**

Modo con el bit de escritura para otros activo. Cualquier cuenta local —incluida
la de un servicio comprometido— puede reescribirlo.

ATT&CK: `T1222`.

---

## Higiene

### `hygiene.firewall.disabled`

**¿El servidor depende solo del perímetro para filtrar tráfico?**

Se lee de `ufw`, `firewalld`, `nftables`, el firewall de Windows o el
application firewall de macOS. Un firewall activo que **acepta entrante por
omisión** también cuenta: es medio en vez de alto, pero cuenta.

En Windows se exige que los **tres** perfiles estén activos: uno apagado sigue
siendo un agujero. El lector distingue `DESACTIVADO` de `ACTIVADO` en
instalaciones localizadas — un detalle que decide si el panel miente.

ATT&CK: `T1562.004`. El runbook avisa, antes del comando, de confirmar que la
regla del acceso remoto ya existe: activar el firewall sin ella te deja fuera
del servidor.

### `hygiene.updates.pending`

**¿Hay parches de seguridad publicados y no aplicados?**

Se cuentan desde `apt-get --simulate upgrade` (solo los paquetes del canal de
seguridad) o `dnf check-update --security`. Quince o más → alto.

Si no hay gestor conocido, se reporta como **brecha de recolección**, no como
cero. Un servidor sin inspeccionar y un servidor al día no pueden verse igual.

### `hygiene.clock.skew`

**¿La hora del servidor permite correlacionar sus registros?**

Diferencia entre la marca de la muestra y la hora de recepción por encima de la
tolerancia (120 s por omisión). Con esa deriva, cruzar los registros de este
equipo con los de otro deja de ser fiable justo cuando más hace falta — y un
salto de reloj también es una forma conocida de dificultar el análisis.

ATT&CK: `T1070.006`.

---

## Disponibilidad

### `availability.agent.silence`

**¿El agente calló sin que nadie lo detuviera de forma planificada?**

La única regla que se dispara por **ausencia** de evidencia, y por eso corre en
el servidor: un agente silenciado no puede reportar que lo silenciaron. Se
activa tras cuatro ciclos sin telemetría y escala si el silencio se prolonga.

El hallazgo dice explícitamente lo que no puede saber: un apagado planificado,
una caída de red y un agente detenido a propósito se ven exactamente igual desde
el plano de control. Distinguirlos es trabajo humano.

ATT&CK: `T1562.001`.

---

## Recursos

### `resource.cpu.saturation`

**¿La CPU lleva varias muestras seguidas al límite?**

Un pico aislado **no** genera hallazgo. Se exigen tres muestras consecutivas por
encima del umbral, y la confianza sube cuando la racha se alarga. Reportar cada
pico como saturación es exactamente cómo una consola enseña a sus operadores a
ignorarla.

ATT&CK: `T1496` — sostenido y sin cambio de carga que lo explique, este es el
patrón de un proceso que no debería estar ahí.

### `resource.memory.pressure`

**¿La memoria comprometida puede provocar paginación o terminaciones por OOM?**

### `resource.disk.capacity`

**¿Queda margen de disco para operar y registrar?**

Cuando el disco se agota, el servidor deja de escribir sus propios registros: se
queda ciego justo cuando hace falta ver.

### `resource.disk.runway`

**¿Cuántas horas faltan para quedarse sin disco al ritmo actual?**

Proyección lineal sobre la ventana observada. Se corrige con calma ahora o con
el servicio caído después. Un crecimiento repentino sin cambio de carga también
aparece cuando alguien deja datos en el servidor.

---

## Lo que este build **no** detecta

| No implementado | Por qué importa decirlo |
|---|---|
| Inventario y firma de procesos | Un binario extraño en ejecución no se ve aquí |
| Descubrimiento activo de red | RootCause no escanea: solo ve lo que el agente reporta |
| Contenido de los registros de aplicación | PHP, Nginx y la base de datos siguen siendo su propia fuente |
| Reglas de firewall una por una | Se lee el estado, no la política completa |
| Detección de malware por firma | Es trabajo del antivirus y del EDR; RootCause los complementa |
| Correlación entre equipos distintos | Cada hallazgo pertenece hoy a un activo |

Estas ausencias están en la [hoja de ruta](ROADMAP.md), no en el panel.
