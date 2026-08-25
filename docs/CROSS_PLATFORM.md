# Compatibilidad multiplataforma

CI compila y ejecuta la suite completa en Windows, Linux y macOS, contra la
versión mínima de Rust **y** contra la estable. Lo que sigue es qué cambia entre
sistemas y, sobre todo, **qué se declara como brecha cuando algo no se puede
leer**.

## Componentes

| Componente | Windows | Linux | macOS |
|---|---|---|---|
| Servidor y API | Sí | Sí | Sí |
| Consola embebida | Sí | Sí | Sí |
| SQLite con WAL | Sí | Sí | Sí |
| Agente de recursos | Sí | Sí | Sí |
| Servicio automático | Servicio / Inno Setup | systemd | launchd |
| Firma del binario | Authenticode pendiente | Paquetes pendientes | Notarización pendiente |

## Superficie de seguridad, sistema por sistema

| Superficie | Linux | Windows | macOS |
|---|---|---|---|
| Sockets en escucha | `ss -tunaH`, con respaldo en `/proc/net/*` | `netstat -ano` | `netstat -an` |
| Proceso detrás del puerto | Sí, con privilegios | PID sí, nombre no | No |
| Conexiones establecidas | Sí | Sí | Sí |
| Eventos de autenticación | `journalctl _COMM=sshd`, con respaldo en `auth.log` y `secure` | Eventos 4625 y 4624 vía `wevtutil` | **Brecha declarada** |
| Integridad de archivos | Sí, con permisos POSIX | Sí, sin bits de permiso | Sí |
| Permisos debilitados | Sí | No aplica | Sí |
| Firewall | `ufw`, `firewalld`, `nftables` | `netsh advfirewall` (los tres perfiles) | `socketfilterfw` |
| Parches de seguridad pendientes | `apt-get`, `dnf` | **Brecha declarada** | **Brecha declarada** |

Cada celda que dice «brecha declarada» aparece en la consola con su motivo. No
se reporta cero.

## Diferencias esperadas

- `load_average` no existe en todas las plataformas y puede llegar vacío.
- Los discos son los volúmenes montados **visibles para la cuenta del agente**:
  correr sin privilegios cambia el total, no solo el detalle.
- Los contadores de red son acumulativos y se reinician con la interfaz. Un
  contador que retrocede se interpreta como reinicio, nunca como tráfico
  negativo: por eso una máquina que se reinicia no genera un falso hallazgo de
  exfiltración.
- El nombre del proceso detrás de un puerto requiere privilegios en Linux y no
  está disponible en macOS. La evidencia lo dice: «proceso no identificado por
  el agente».
- Los formatos de salida de las herramientas del sistema **están localizados**.
  Los parsers reconocen `LISTENING`/`ESCUCHANDO` y distinguen `DESACTIVADO` de
  `ACTIVADO` — un detalle que decide si el panel miente en una instalación en
  español.

## Cómo se prueba

Cada formato de salida tiene su parser puro y sus fixtures reales, que corren en
los tres sistemas aunque el formato solo exista en uno. Interpretar texto escrito
por la herramienta de otra persona es la parte frágil, y es la que se verifica en
cada build.

La validación final —privilegios, sandbox, políticas de privacidad de macOS—
requiere equipos reales antes de marcar una versión como estable.
