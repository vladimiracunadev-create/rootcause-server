# Instalación multiplataforma

## Desde el código

```bash
git clone https://github.com/vladimiracunadev-create/rootcause-server
cd rootcause-server
cargo build --release --workspace
```

Los binarios quedan en `target/release/`: `rootcause-server` y
`rootcause-agent` (con `.exe` en Windows). `rust-toolchain.toml` fija la versión
del compilador, así que no hace falta elegirla.

## Desde una publicación

Cada versión trae, por plataforma, un `.tar.gz` con los dos binarios, la
documentación, las plantillas de servicio y su suma SHA-256, además de un
inventario CycloneDX de dependencias y una atestación de procedencia firmada por
GitHub.

```bash
sha256sum --check SHA256SUMS.txt
gh attestation verify rootcause-linux-x86_64.tar.gz \
  --repo vladimiracunadev-create/rootcause-server
```

La segunda orden comprueba que ese archivo salió de este repositorio, de ese
commit y de ese workflow. Si no verifica, no lo instales.

## Linux con systemd

```bash
sudo install -m 0755 rootcause-server /usr/local/bin/
sudo install -m 0755 rootcause-agent  /usr/local/bin/
sudo useradd --system --home-dir /var/lib/rootcause --create-home rootcause

sudo install -m 0644 packaging/linux/rootcause-server.service /etc/systemd/system/
sudo install -m 0644 packaging/linux/rootcause-agent.service  /etc/systemd/system/
```

El token va en un archivo de entorno con permisos estrictos, nunca en la línea
de comandos:

```bash
printf 'ROOTCAUSE_API_TOKEN=%s\n' "$(rootcause-server token)" \
  | sudo tee /etc/rootcause/server.env >/dev/null
sudo chmod 0600 /etc/rootcause/server.env
sudo systemctl daemon-reload
sudo systemctl enable --now rootcause-server
```

### Qué necesita el agente para ver todo

El agente funciona sin privilegios, pero con menos visibilidad. Lo que cambia:

| Superficie | Sin privilegios | Con privilegios |
|---|---|---|
| Sockets en escucha | Sí | Sí, **con el proceso y su PID** |
| Eventos de autenticación | Normalmente no | Sí |
| `/etc/shadow`, `authorized_keys` de root | No | Sí |
| Firewall y parches | Depende de la distribución | Sí |

Cada cosa que no pueda leer se reporta como brecha en la consola. Decidir cuánto
privilegio darle es una decisión tuya, y el panel te muestra las consecuencias
de cualquiera de las dos.

## Windows

```powershell
Copy-Item rootcause-server.exe, rootcause-agent.exe 'C:\Program Files\RootCause\'

# El token en el ámbito de la máquina, no en el historial de la consola
[Environment]::SetEnvironmentVariable('ROOTCAUSE_API_TOKEN', $token, 'Machine')

New-Service -Name RootCauseServer `
  -BinaryPathName '"C:\Program Files\RootCause\rootcause-server.exe" serve' `
  -StartupType Automatic
Start-Service RootCauseServer
```

Para leer el registro de seguridad (eventos 4625/4624), el agente necesita
permiso sobre ese registro. Sin él, la superficie de autenticación se declara
como brecha en vez de reportar cero intentos.

`packaging/windows/rootcause-server.iss` contiene el guion de Inno Setup.

## macOS

```bash
sudo install -m 0755 rootcause-server /usr/local/bin/
sudo install -m 0644 packaging/macos/com.rootcause.server.plist /Library/LaunchDaemons/
sudo launchctl load /Library/LaunchDaemons/com.rootcause.server.plist
```

## Contenedor

```bash
docker build -t rootcause-server .
ROOTCAUSE_API_TOKEN="$(openssl rand -hex 32)" docker compose up -d
```

El `compose.yml` del repositorio ya monta el sistema de archivos como solo
lectura, elimina todas las capacidades, prohíbe elevar privilegios y publica el
puerto únicamente en `127.0.0.1`.

## Verificar la instalación

```bash
curl -fsS http://127.0.0.1:8080/healthz
rootcause-server rules | tail -1          # debe listar las reglas publicadas
rootcause-agent --dry-run | head -30      # exactamente lo que se enviaría
```

O de una sola vez, el mismo guion que corre CI:

```bash
bash scripts/smoke.sh
```

## Actualizar

1. Detén el servicio.
2. Reemplaza el binario (las migraciones son aditivas: una base creada por `0.1`
   sigue funcionando).
3. Arranca. El servidor aplica las migraciones pendientes al conectar.

Los agentes `0.1` siguen siendo aceptados por un servidor `0.2`: simplemente no
reportan superficie de seguridad, y el servidor lo dice en cada respuesta en vez
de dejar el panel vacío sin explicación.
