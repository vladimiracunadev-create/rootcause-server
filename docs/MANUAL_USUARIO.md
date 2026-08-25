# Manual de operación

Qué es cada cosa, en claro. Si administras servidores pero no vives dentro de
una consola de seguridad, este es el documento por el que empezar.

## La idea en un párrafo

Tus servidores ya escriben registros. El problema no es la falta de datos: es
que cada registro ve su propia parte. RootCause Server pone un **agente de solo
lectura** en cada equipo, recibe lo que ese agente ve, y busca las frases que
solo aparecen al juntar las partes. Cuando encuentra una, la escribe con
evidencia y con el comando exacto para responder — y se detiene ahí.

## Las cinco preguntas del panel

Al abrir `http://127.0.0.1:8080` verás ocho vistas. Estas son las que responden
las preguntas que importan.

### 1. «¿Cómo estamos?» → Panel de defensa

Una puntuación de 0 a 100 con su nota (A a F). Baja con cada hallazgo abierto y
—esto es deliberado— **está limitada por el peor de ellos**: un solo hallazgo
crítico no se diluye entre las otras cinco dimensiones. Un servidor con una base
de datos expuesta no puede sacar una B porque todo lo demás esté en orden.

Bajo la puntuación aparece la lista de **superficies que no se pudieron
inspeccionar**. Léela siempre: una nota alta sobre un equipo del que no se pudo
leer nada no es un certificado de salud.

### 2. «¿Qué se ve desde fuera?» → Superficie expuesta

La tabla de todo lo que tus equipos aceptan desde fuera de sí mismos. Tres
columnas deciden casi todo:

- **Servicio** — qué hay detrás del puerto, con nombre («PostgreSQL», no «5432»).
- **Enlace** — a qué dirección está atado. `127.0.0.1` es rutina; `0.0.0.0` no.
- **Alcance** — «Público» significa: cualquiera que llegue a la red puede tocarlo.

Si algo te sorprende aquí, ese es el trabajo del día.

### 3. «¿Quién está tocando la puerta?» → Amenazas

Direcciones con intentos de autenticación, ordenadas por volumen. Dos columnas
que hay que mirar juntas:

- **Fallidos** — cuántos intentos rechazó el servidor.
- **Concedidos** — cuántos entraron.

Un origen con muchos fallidos es ruido de Internet. **Un origen con muchos
fallidos y al menos uno concedido es una emergencia**: significa que alguien que
estaba adivinando acertó. RootCause lo marca como crítico y te dice qué revisar
antes de bloquear nada.

Más abajo, el panel muestra lo que el propio RootCause rechazó en su perímetro.
Él también es un objetivo.

### 4. «¿Qué hago?» → Incidentes

Cada tarjeta abre un cajón con cuatro bloques:

1. **Causa probable** — una frase, con su nivel de confianza. Si dice 55 %, es
   porque el producto no puede afirmar más con lo que vio.
2. **Evidencia** — la observación concreta que disparó la regla, con su valor y
   su umbral. Esto es lo que le muestras a alguien más.
3. **Qué hacer** — pasos en lenguaje humano, en orden.
4. **Runbook revisado** — el comando exacto, con un botón para copiarlo, la
   plataforma a la que aplica, si necesita privilegios y cómo se revierte.

**RootCause nunca ejecuta esos comandos.** Los escribe y espera. Una prueba del
repositorio impide que un comando destructivo llegue siquiera a esa lista.

Cuando termines, marca el incidente como **reconocido** (lo estás mirando) o
**resuelto** (ya no ocurre). Ambas cosas quedan en la auditoría con tu nombre.

### 5. «¿Qué llega desde Internet?» → Topología

El mapa por zonas. A la izquierda, Internet y el propio plano de control. En el
centro, dos zonas: **superficie expuesta** (equipos con puertos públicos) y
**red interna**. A la derecha, tus equipos, cada uno con cuántos puertos
públicos tiene y cuántos hallazgos abiertos.

Si un equipo que creías interno aparece en la zona expuesta, ya encontraste algo.

## Las tres vistas de contexto

- **Activos** — inventario con la postura de cada equipo.
- **Qué detecta** — el catálogo de reglas, publicado por el propio binario. Si
  una regla no aparece ahí, no está implementada.
- **Sistema** — versión, protocolo, cómo está configurada esta instancia
  (¿exige token?, ¿escucha fuera de loopback?) y la auditoría completa. Desde
  aquí se descarga el paquete de evidencia en NDJSON.

## Enrolar un servidor

```bash
rootcause-agent \
  --server-url https://rootcause.example.cl \
  --api-token "…" \
  --label role=edge \
  --label environment=production
```

El `role` importa: cambia lo que se considera normal.

| Etiqueta | Significa | Efecto |
|---|---|---|
| `role=edge` | Publicado a Internet a propósito | 80 y 443 no generan hallazgo |
| `role=internal` (por omisión) | Solo debería verse desde dentro | Cualquier puerto público es hallazgo |
| `role=database` | Almacén de datos | **Cualquier** servicio público es crítico |

Antes de enrolar nada, mira exactamente qué se enviaría:

```bash
rootcause-agent --dry-run
```

Para vigilar un archivo propio además de los del sistema:

```bash
rootcause-agent --watch-file /srv/app/.env --watch-file /etc/nginx/sites-enabled/app
```

## Preguntas frecuentes

**¿Esto reemplaza a mi antivirus?**
No. RootCause no tiene firmas, no inspecciona memoria y no bloquea procesos. Ve
lo que el antivirus no mira: la superficie, la presión sobre la autenticación y
lo que cambió en la configuración.

**¿Envía algo a Internet?**
El agente habla solo con **tu** servidor RootCause, en la URL que tú le das. El
servidor no habla con nadie. No hay telemetría hacia el fabricante, ni
actualizaciones automáticas, ni analítica. Ver
[`POLITICA_DE_PRIVACIDAD_LOCAL.md`](POLITICA_DE_PRIVACIDAD_LOCAL.md).

**¿Puede el agente romper mi servidor?**
No escribe nada. Solo ejecuta comandos de una lista blanca de solo lectura con
tiempo límite. La lista completa está en `crates/rootcause-agent/src/probe.rs`,
y una prueba impide que crezca sin que alguien lo note.

**Un incidente dejó de aparecer solo. ¿Es un error?**
No. Los hallazgos de superficie e higiene describen un **estado actual**: cuando
la condición deja de observarse, el incidente se cierra solo y el cierre queda
registrado en la auditoría con el motivo. Los de intrusión e integridad no se
cierran solos: alguien tiene que mirarlos.

**¿Por qué un pico de CPU no genera nada?**
Porque un pico no es saturación. Se exigen tres muestras consecutivas. Reportar
cada pico es la forma más rápida de enseñarle a un equipo a ignorar el panel.

**El agente dejó de reportar y salió una alerta.**
Correcto. Un sensor que calla es un hallazgo, no un hueco en el gráfico. Desde
el plano de control, un apagado planificado y un agente detenido a propósito se
ven idénticos: por eso te lo dice en vez de decidir por ti.
