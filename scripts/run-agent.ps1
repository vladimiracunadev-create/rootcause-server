# Ejecuta el sensor contra el plano de control local.
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($env:ROOTCAUSE_API_TOKEN)) {
    throw 'Falta ROOTCAUSE_API_TOKEN. Genera uno con: rootcause-server token'
}

# Sin argumentos, un solo ciclo.
$arguments = if ($args.Count -eq 0) { @('--once') } else { $args }

& rootcause-agent.exe @arguments
