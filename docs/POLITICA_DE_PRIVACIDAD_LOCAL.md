# Política de privacidad local

RootCause Server es software que corre en tu infraestructura. Esta página
describe qué datos existen, dónde viven y qué sale hacia afuera.

## Qué sale hacia el fabricante

Nada.

No hay telemetría, no hay analítica, no hay comprobación de licencia, no hay
actualizaciones automáticas y no hay informes de fallo remotos. El binario del
servidor no abre ninguna conexión saliente por su cuenta: solo escucha.

Puedes comprobarlo:

```bash
# Levanta el servidor y observa sus conexiones salientes
ss -tnp | grep rootcause-server
```

## Qué se transmite dentro de tu red

El agente habla exclusivamente con la URL que **tú** le das en
`--server-url`. Por esa conexión viaja un sobre JSON por ciclo:

| Campo | Contiene | No contiene |
|---|---|---|
| Identidad | Nombre de equipo, plataforma, versión de sistema, arquitectura, etiquetas | Usuario conectado, dominio, número de serie |
| Recursos | Porcentajes de CPU, memoria y disco, tiempo activo, contadores de red | Nombres de procesos, líneas de comando |
| Sockets | Protocolo, dirección de enlace, puerto, proceso y PID cuando el sistema los expone | Contenido de ninguna conexión |
| Conexiones | Dirección remota, puerto remoto, puerto local, cuántas conexiones | Carga útil, cabeceras, ningún byte del tráfico |
| Autenticación | Servicio, dirección de origen, nombre de usuario **intentado**, resultado y conteo | La línea del registro, contraseñas, hashes, tokens |
| Integridad | Ruta, huella SHA-256, tamaño, fecha, permisos | **El contenido del archivo** |
| Controles | Estado del firewall, número de parches pendientes | Reglas completas, lista de paquetes |
| Brechas | Qué no se pudo inspeccionar y por qué | — |

Puedes ver el sobre exacto, con los datos reales de tu equipo, antes de enrolar
nada:

```bash
rootcause-agent --dry-run
```

### Sobre los nombres de usuario intentados

La detección de barridos necesita saber **cuántos usuarios distintos** probó un
origen, y saber si alguno existe es la pregunta que decide la respuesta. Por eso
el nombre intentado viaja; la credencial nunca.

Si tu marco de cumplimiento no lo admite, `--metrics-only` desactiva por
completo la superficie de seguridad y el agente reporta solo recursos. El
servidor lo declara como brecha, para que nadie confunda «no se recolectó» con
«no hay nada».

### Sobre los archivos vigilados

El agente calcula huellas SHA-256 y envía la huella. Un digest basta para probar
que algo cambió y es inútil para leer lo que dice — la única combinación
aceptable para `/etc/shadow`.

## Dónde vive todo

En un único archivo SQLite en el servidor, en la ruta que tú elijas
(`--database-url`). Contiene activos, telemetría, superficie, incidentes,
presión de autenticación, eventos de defensa y auditoría.

- La telemetría, la presión y los eventos de defensa se borran pasada la
  retención configurada (30 días por omisión).
- Los incidentes y la auditoría se conservan: son la evidencia.
- Nada se cifra en reposo: **protege ese archivo como protegerías un respaldo
  de configuración**.

## Qué guarda el navegador

Solo el token del API, en `sessionStorage`, es decir: se borra al cerrar la
pestaña. No hay cookies, no hay almacenamiento persistente y no hay ninguna
petición a un origen distinto del propio servidor — la política de contenido
que envía el servidor lo prohíbe, y CI comprueba que siga siendo así.

## Qué queda en los registros del servidor

Los registros de `rootcause-server` incluyen la dirección de un cliente cuando
lo bloquea por fallos de autenticación repetidos. No incluyen tokens: la
variable de entorno está marcada para no imprimirse, y los errores del API
devuelven un código estable sin detalle interno.
