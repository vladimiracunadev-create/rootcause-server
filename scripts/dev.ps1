# Levanta el plano de control para desarrollo. Si no hay token, genera uno y lo
# muestra: pedirle a alguien que "genere un token primero" es una friccion
# gratuita cuando el binario ya sabe hacerlo.
$ErrorActionPreference = 'Stop'

Set-Location (Join-Path $PSScriptRoot '..')

if ([string]::IsNullOrWhiteSpace($env:ROOTCAUSE_API_TOKEN)) {
    $env:ROOTCAUSE_API_TOKEN = (cargo run --quiet -p rootcause-server -- token).Trim()
    Write-Host 'Token generado para esta sesion:'
    Write-Host "  $($env:ROOTCAUSE_API_TOKEN)"
    Write-Host 'Copialo en la consola cuando te lo pida.'
    Write-Host ''
}

cargo run -p rootcause-server -- serve @args
