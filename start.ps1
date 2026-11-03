$ErrorActionPreference = 'Stop'
$relayBinary = Join-Path $PSScriptRoot 'bin\tg-relay.exe'
$relayData = Join-Path $PSScriptRoot 'data'
if (-not (Test-Path -LiteralPath $relayBinary)) {
    throw '缺少 bin\tg-relay.exe，请先按 README 构建程序。'
}
& $relayBinary -listen 127.0.0.1:8765 -data $relayData @args
exit $LASTEXITCODE
