# Modelo de amenazas inicial

## Activos protegidos

- Token y futuras identidades de agentes.
- Integridad de telemetría, evidencias e incidentes.
- Inventario de equipos y metadatos operativos.
- Base de datos y respaldos.
- Capacidad futura de ejecutar playbooks.

## Adversarios y fallas

- Atacante de red que intenta capturar o alterar telemetría.
- Agente falso que inunda el servidor.
- Usuario autenticado que excede su autoridad.
- Endpoint comprometido que entrega señales manipuladas.
- Dependencia vulnerable o paquete sustituido.
- Fallo de disco, base de datos, red o actualización.

## Controles presentes

- Transporte remoto HTTPS exigido por el agente.
- Token no registrado en logs y marcado como secreto en CLI.
- Validación de versión, identidad, rangos, etiquetas y tamaño.
- Consola sin dependencias CDN y con CSP.
- Agente sin acciones correctivas.
- Persistencia con claves, restricciones y migraciones.

## Riesgos aceptados en 0.1

- Token compartido sin revocación individual.
- Sin protección de tasa por identidad.
- Sin firma de mensajes ni mTLS.
- SQLite de nodo único.
- El identificador estable no constituye identidad criptográfica.

Por lo anterior, `0.1` es adecuada para laboratorio y evolución controlada, no
para exponer directamente a Internet ni administrar múltiples organizaciones.
