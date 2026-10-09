param(
    [string]$OutputDir = (Join-Path $PSScriptRoot '..\dist\packages\windows-amd64'),
    [string]$Version = '0.1.0'
)

$ErrorActionPreference = 'Stop'
$projectDir = Split-Path -Parent $PSScriptRoot
$outputPath = [System.IO.Path]::GetFullPath($OutputDir)
if (Test-Path -LiteralPath $outputPath -PathType Leaf) {
    throw '发布路径不是目录。'
}
New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
if (Get-ChildItem -LiteralPath $outputPath -Force | Select-Object -First 1) {
    throw '发布目录必须为空，请指定新的输出目录；已有配置和凭据不会被覆盖。'
}
$savedBuildEnv = @{}
foreach ($name in @('GOOS', 'GOARCH', 'CGO_ENABLED')) {
    $savedBuildEnv[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}

Push-Location -LiteralPath $projectDir
try {
    $env:GOOS = 'windows'
    $env:GOARCH = 'amd64'
    $env:CGO_ENABLED = '0'
    $revision = & git rev-parse --short HEAD 2>$null
    if ($LASTEXITCODE -ne 0) { $revision = 'unknown' }
    & go build -trimpath -ldflags "-s -w -X main.version=$Version -X main.revision=$revision" -o (Join-Path $outputPath 'connect.exe') ./cmd/connect
    if ($LASTEXITCODE -ne 0) {
        throw 'Windows build failed.'
    }

    Copy-Item -LiteralPath (Join-Path $projectDir 'server.example.json') -Destination $outputPath -Force
    Copy-Item -LiteralPath (Join-Path $projectDir 'README.md') -Destination $outputPath -Force
    Copy-Item -LiteralPath (Join-Path $projectDir 'LICENSE') -Destination $outputPath -Force
    Copy-Item -LiteralPath (Join-Path $projectDir 'THIRD_PARTY_NOTICES.md') -Destination $outputPath -Force
    Copy-Item -LiteralPath (Join-Path $projectDir 'licenses') -Destination $outputPath -Recurse -Force
    Copy-Item -LiteralPath (Join-Path $projectDir 'docs') -Destination $outputPath -Recurse -Force
    Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'windows') -File | ForEach-Object {
        $text = [System.IO.File]::ReadAllText($_.FullName) -replace '\r?\n', "`r`n"
        [System.IO.File]::WriteAllText((Join-Path $outputPath $_.Name), $text, [System.Text.UTF8Encoding]::new($false))
    }

    Write-Output "Windows package: $outputPath"
} finally {
    foreach ($name in @('GOOS', 'GOARCH', 'CGO_ENABLED')) {
        [Environment]::SetEnvironmentVariable($name, $savedBuildEnv[$name], 'Process')
    }
    Pop-Location
}
