# Instalación

## Compilar

```bash
rustup toolchain install 1.95.0
cargo build --release --workspace
```

Los binarios quedan en `target/release/`:

- `rootcause-server` (`rootcause-server.exe` en Windows).
- `rootcause-agent` (`rootcause-agent.exe` en Windows).

La consola está embebida dentro del servidor y no necesita Node.js.

## Windows

1. Copia ambos `.exe` a `C:\Program Files\RootCause\`.
2. Genera el token con `rootcause-server.exe token`.
3. Configura variables de entorno en una cuenta de servicio.
4. Prueba primero desde PowerShell.
5. Usa `packaging/windows/rootcause-server.iss` para producir un instalador.

No incrustes el token dentro del instalador.

## Linux

1. Copia los binarios a `/usr/local/bin/`.
2. Crea `/etc/rootcause/server.env` con permisos `0600`.
3. Instala `packaging/linux/rootcause-server.service`.
4. Ejecuta `systemctl enable --now rootcause-server`.

## macOS

1. Copia los binarios a `/usr/local/bin/` o `/opt/rootcause/bin/`.
2. Firma y notariza los binarios antes de distribuirlos públicamente.
3. Adapta `packaging/macos/com.rootcause.server.plist`.
4. Protege el token mediante permisos del archivo o el mecanismo corporativo de
   secretos.

## Contenedor

El contenedor está pensado para el servidor Linux. Los agentes deben ejecutarse
en los hosts que observan.

```bash
export ROOTCAUSE_API_TOKEN="token-generado"
docker compose up --build
```
