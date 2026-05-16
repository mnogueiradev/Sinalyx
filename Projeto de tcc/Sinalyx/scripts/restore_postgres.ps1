param(
    [Parameter(Mandatory = $true)]
    [string]$BackupPath
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $BackupPath)) {
    throw "Arquivo de backup nao encontrado: $BackupPath"
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

$confirmation = Read-Host "Esta acao substitui dados existentes no banco '$database'. Digite RESTAURAR para continuar"
if ($confirmation -ne "RESTAURAR") {
    Write-Host "Restauracao cancelada."
    exit 0
}

$containerDump = "/tmp/sinalyx_postgres_restore.dump"

docker cp $BackupPath "${containerName}:$containerDump"
docker exec $containerName pg_restore -U $user -d $database --clean --if-exists $containerDump
docker exec $containerName rm -f $containerDump

Write-Host "Backup restaurado com sucesso."
