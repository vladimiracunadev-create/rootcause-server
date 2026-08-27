# Recursos gráficos

Esta carpeta está reservada para material gráfico de apoyo (capturas de la
consola, esquemas exportados como imagen, logotipos).

**Hoy está vacía a propósito.** Todos los diagramas de este conjunto documental
viven **embebidos en Mermaid** dentro de los propios documentos Markdown, por
tres razones:

1. **Se revisan como código.** Un diagrama en Mermaid aparece en el `diff` de un
   PR; una imagen binaria, no.
2. **No se desincronizan.** Al estar en el mismo archivo que la explicación, un
   cambio en el texto obliga a mirar el diagrama.
3. **Se renderizan solos.** GitHub los dibuja en el navegador, y
   [`scripts/docs_pdf.py`](../../../scripts/docs_pdf.py) los convierte a PNG con
   `mmdc` al generar los PDF, dejando la caché en `docs/system-documentation/pdf/.mermaid-cache/`.

## Diagramas existentes y dónde están

| Diagrama | Documento |
|---|---|
| Flujo general de funcionamiento | [01 · Descripción general](../01-system-overview.md) |
| Mapa mental del sistema | [03 · Arquitectura](../03-architecture.md) |
| Capas y responsabilidades | [03 · Arquitectura](../03-architecture.md) |
| Diagrama de componentes | [03 · Arquitectura](../03-architecture.md) |
| Secuencia: un ciclo de telemetría | [03 · Arquitectura](../03-architecture.md) |
| Secuencia: el sensor que se calló | [03 · Arquitectura](../03-architecture.md) |
| Diagrama de despliegue | [03 · Arquitectura](../03-architecture.md) |
| Modelo de datos (E-R resumido) | [03 · Arquitectura](../03-architecture.md) |
| Modelo de datos (E-R completo) | [07 · Base de datos](../07-database.md) |
| Panorama del flujo de datos | [08 · Flujo de datos](../08-data-flow.md) |
| Orden de decisión del perímetro | [11 · Seguridad](../11-security.md) |

**Si en el futuro se añaden capturas de pantalla**, conviene que no incluyan
nombres de equipo, direcciones IP ni nombres de usuario reales: la consola
muestra exactamente ese tipo de dato.
