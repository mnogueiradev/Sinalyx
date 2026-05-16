param(
    [string]$OutputPath = ""
)

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$backupDir = Join-Path $projectRoot "data\backups"

if (-not (Test-Path $backupDir)) {
    New-Item -ItemType Directory -Path $backupDir | Out-Null
}

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $OutputPath = Join-Path $backupDir "sinalyx_postgres_$timestamp.dump"
}

$containerName = $env:SINALYX_POSTGRES_CONTAINER
if ([string]::IsNullOrWhiteSpace($containerName)) {
    $containerName = "sinalyx_postgres"
}

$database = $env:POSTGRES_DB
if ([string]::IsNullOrWhiteSpace($database)) {
    $database = "sinalyx"
}

$user = $env:POSTGRES_USER
if ([string]::IsNullOrWhiteSpace($user)) {
    $user = "sinalyx"
}

$containerDump = "/tmp/sinalyx_postgres_backup.dump"

docker exec $containerName pg_dump -U $user -d $database -Fc -f $containerDump
docker cp "${containerName}:$containerDump" $OutputPath
docker exec $containerName rm -f $containerDump

Write-Host "Backup gerado em: $OutputPath"
