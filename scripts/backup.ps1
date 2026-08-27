# Respalda la base de datos de RootCause y comprueba que la copia se puede leer.
#
# Los incidentes y la auditoria son lo unico que este sistema no puede
# regenerar: la telemetria vuelve en el ciclo siguiente, la superficie tambien,
# la evidencia no.
#
# Se usa `.backup` y no `Copy-Item` a proposito: con WAL activo, copiar el
# archivo mientras el servidor escribe puede producir una instantanea rota si no
# viajan tambien los ficheros -wal y -shm.
[CmdletBinding()]
param(
    [string] $Source = $(if ($env:ROOTCAUSE_DB_PATH) { $env:ROOTCAUSE_DB_PATH } else { 'rootcause.db' }),
    [string] $DestinationDir = $(if ($env:ROOTCAUSE_BACKUP_DIR) { $env:ROOTCAUSE_BACKUP_DIR } else { './backups' }),
    [int] $Keep = $(if ($env:ROOTCAUSE_BACKUP_KEEP) { [int] $env:ROOTCAUSE_BACKUP_KEEP } else { 14 })
)

$ErrorActionPreference = 'Stop'

function Stop-WithMessage([string] $Message) {
    Write-Error "respaldo: $Message"
    exit 1
}

if (-not (Get-Command sqlite3 -ErrorAction SilentlyContinue)) {
    Stop-WithMessage 'falta sqlite3. Instalalo (winget install SQLite.SQLite) y vuelve a intentarlo.'
}

# Se acepta una URL por comodidad: es lo que ya guarda el archivo de servicio.
if ($Source -like 'sqlite://*') { $Source = $Source.Substring(9) }
elseif ($Source -like 'sqlite:*') { $Source = $Source.Substring(7) }

if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
    Stop-WithMessage "no existe la base de datos $Source"
}

if (-not (Test-Path -LiteralPath $DestinationDir)) {
    New-Item -ItemType Directory -Path $DestinationDir -Force | Out-Null
}

$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$target = Join-Path $DestinationDir "rootcause-$stamp.db"

Write-Host "==> copiando $Source -> $target"
& sqlite3 $Source ".backup '$target'"
if ($LASTEXITCODE -ne 0) { Stop-WithMessage 'sqlite3 no pudo completar la copia' }
if (-not (Test-Path -LiteralPath $target) -or (Get-Item $target).Length -eq 0) {
    Stop-WithMessage 'la copia quedo vacia'
}

Write-Host '==> comprobando la integridad de la copia'
$integrity = (& sqlite3 $target 'PRAGMA integrity_check;') -join ''
if ($integrity -ne 'ok') { Stop-WithMessage "la copia no pasa integrity_check: $integrity" }

function Get-RowCount([string] $Database, [string] $Table) {
    $value = & sqlite3 $Database "SELECT COUNT(*) FROM $Table;"
    if ($LASTEXITCODE -ne 0) { return $null }
    return [int] ($value -join '')
}

foreach ($table in @('incidents', 'audit_log', 'assets')) {
    $origin = Get-RowCount $Source $table
    $copy = Get-RowCount $target $table
    if ($null -eq $copy) { Stop-WithMessage "la copia no puede leer la tabla $table" }
    # El origen puede haber crecido entre la instantanea y esta lectura; lo que
    # nunca debe pasar es que tenga MENOS filas que la copia.
    if ($copy -gt $origin) {
        Stop-WithMessage "la copia de $table tiene mas filas ($copy) que el origen ($origin)"
    }
    Write-Host "    ${table}: $copy filas en la copia ($origin en el origen)"
}

$size = '{0:N1} MiB' -f ((Get-Item $target).Length / 1MB)
Write-Host "==> respaldo verificado: $target ($size)"

if ($Keep -gt 0) {
    $stale = Get-ChildItem -Path $DestinationDir -Filter 'rootcause-*.db' |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -Skip $Keep
    if ($stale) {
        Write-Host "==> conservando los $Keep mas recientes; se retiran $($stale.Count)"
        foreach ($file in $stale) {
            Remove-Item -LiteralPath $file.FullName -Force
            Write-Host "    retirado $($file.FullName)"
        }
    }
}

Write-Host ''
Write-Host 'Para restaurar: detén el servicio, coloca la copia en la ruta de'
Write-Host 'ROOTCAUSE_DATABASE_URL, borra los ficheros -wal y -shm que queden, y arranca.'
Write-Host 'Las migraciones pendientes se aplican solas. Restaurar en un binario anterior'
Write-Host 'al que creó el respaldo no está probado: no hay migraciones descendentes.'
