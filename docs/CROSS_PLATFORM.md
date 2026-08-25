# Compatibilidad multiplataforma

| Componente | Windows | Linux | macOS |
|---|---:|---:|---:|
| Servidor/API | Sí | Sí | Sí |
| Consola embebida | Sí | Sí | Sí |
| SQLite/WAL | Sí | Sí | Sí |
| Agente de recursos | Sí | Sí | Sí |
| Servicio automático | Inno/servicio | systemd | launchd |
| Firma de binarios | Authenticode pendiente | paquetes pendientes | notarización pendiente |

## Diferencias esperadas

- `load_average` puede variar o no estar disponible según el sistema.
- Los discos representan volúmenes montados visibles para la cuenta del agente.
- Los contadores de red son acumulativos y dependen de las interfaces visibles.
- Permisos de servicio, sandbox y privacidad deben validarse en cada plataforma.
- El agente no requiere privilegios administrativos para el conjunto mínimo de
  métricas, pero algunos conectores futuros sí podrían requerir capacidades
  separadas y explícitas.

La CI compila y prueba en los tres sistemas. La validación final requiere
equipos reales antes de marcar una versión como estable.
