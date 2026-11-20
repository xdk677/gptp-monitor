param(
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$version = (Get-Content (Join-Path $root "VERSION") -Raw).Trim()
$releaseName = "GPTPSyncMonitor-v$version"

function Remove-ProjectPath {
    param([string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    $prefix = $root.TrimEnd('\') + '\'
    if (-not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove path outside project: $full"
    }
    if (Test-Path -LiteralPath $full) {
        Remove-Item -LiteralPath $full -Recurse -Force
    }
}

function Compress-WithRetry {
    param(
        [string[]]$Path,
        [string]$DestinationPath
    )
    for ($attempt = 1; $attempt -le 6; $attempt++) {
        try {
            if (Test-Path -LiteralPath $DestinationPath) {
                Remove-Item -LiteralPath $DestinationPath -Force
            }
            Compress-Archive -Path $Path -DestinationPath $DestinationPath -Force
            return
        }
        catch {
            if ($attempt -eq 6) { throw }
            Start-Sleep -Seconds (2 * $attempt)
        }
    }
}

Push-Location $root
try {
    if (-not $SkipTests) {
        python -m pytest tests -q
        if ($LASTEXITCODE -ne 0) { throw "Tests failed." }
        python -m gptp_monitor.gui --offscreen --smoke-ui
        if ($LASTEXITCODE -ne 0) { throw "GUI smoke failed." }
    }

    Remove-ProjectPath (Join-Path $root "build")
    Remove-ProjectPath (Join-Path $root "dist")
    Remove-ProjectPath (Join-Path $root "release")

    python -m PyInstaller packaging\GPTPSyncMonitor.spec --noconfirm --clean
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed." }

    $releaseRoot = Join-Path $root "release"
    $releaseDir = Join-Path $releaseRoot $releaseName
    New-Item -ItemType Directory -Force -Path $releaseDir | Out-Null

    Copy-Item "dist\GPTPSyncMonitor\*" $releaseDir -Recurse -Force
    Copy-Item README.md, CHANGELOG.md, LICENSE, VERSION $releaseDir -Force
    Copy-Item docs\*.md $releaseDir -Force

    $windowsZip = Join-Path $releaseRoot "$releaseName-windows-x64.zip"
    Compress-WithRetry -Path (Join-Path $releaseDir "*") -DestinationPath $windowsZip

    $sourceZip = Join-Path $releaseRoot "$releaseName-source.zip"
    $sourceStage = Join-Path $root ".source-stage"
    Remove-ProjectPath $sourceStage
    New-Item -ItemType Directory -Force -Path $sourceStage | Out-Null
    $sourceItems = @(
        "src", "tests", "docs", "packaging", "scripts", ".github",
        "pyproject.toml", "requirements.txt", "requirements-dev.txt",
        "README.md", "CHANGELOG.md", "LICENSE", "VERSION", ".gitignore"
    )
    $excludedPattern = '\\(__pycache__|\.pytest_cache|build|dist|release|\.venv|.*\.egg-info)(\\|$)|\.pyc$'
    foreach ($item in $sourceItems) {
        $source = Join-Path $root $item
        if (-not (Test-Path -LiteralPath $source)) { continue }
        if (Test-Path -LiteralPath $source -PathType Leaf) {
            $target = Join-Path $sourceStage $item
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) | Out-Null
            Copy-Item -LiteralPath $source -Destination $target -Force
            continue
        }
        Get-ChildItem -LiteralPath $source -Recurse -File -Force | ForEach-Object {
            $relative = $_.FullName.Substring($root.Length).TrimStart('\')
            if ($relative -notmatch $excludedPattern) {
                $target = Join-Path $sourceStage $relative
                New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) | Out-Null
                Copy-Item -LiteralPath $_.FullName -Destination $target -Force
            }
        }
    }
    Compress-WithRetry -Path (Join-Path $sourceStage "*") -DestinationPath $sourceZip
    Remove-ProjectPath $sourceStage

    $hashLines = @()
    Get-ChildItem -File $releaseDir | Sort-Object Name | ForEach-Object {
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLower()
        $hashLines += "$hash  $($_.Name)"
    }
    $hashLines | Set-Content -Path (Join-Path $releaseDir "SHA256SUMS.txt") -Encoding ascii

    Write-Host "Release directory: $releaseDir"
    Write-Host "Windows ZIP: $windowsZip"
    Write-Host "Source ZIP: $sourceZip"
}
finally {
    Pop-Location
}
