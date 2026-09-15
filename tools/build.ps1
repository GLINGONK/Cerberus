# Distribution build.
#
#   pwsh tools/build.ps1
#
# Equivalent to `cargo tauri build`, with build-machine paths remapped.
#
# Without this, the executable can contain the Cargo registry path and therefore
# the Windows username of the builder. `strip = true` does not remove every
# path embedded in panic messages or dependency source locations.

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $env:USERPROFILE ".cargo" }
$rustup    = if ($env:RUSTUP_HOME) { $env:RUSTUP_HOME } else { Join-Path $env:USERPROFILE ".rustup" }

# Order matters: map the most specific prefixes first.
$remaps = @(
    "--remap-path-prefix=$cargoHome=/cargo",
    "--remap-path-prefix=$rustup=/rustup",
    "--remap-path-prefix=$root=/cerberus",
    "--remap-path-prefix=$env:USERPROFILE=/home"
)

# CARGO_ENCODED_RUSTFLAGS uses 0x1f as its separator, so paths containing spaces
# are not split into separate arguments.
$env:CARGO_ENCODED_RUSTFLAGS = $remaps -join ([char]0x1f)
Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue

Write-Host "Remapped paths:" -ForegroundColor Cyan
$remaps | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
Write-Host ""

Push-Location "app/src-tauri"
try {
    cargo tauri build
    if ($LASTEXITCODE -ne 0) { throw "the build failed" }
} finally {
    Pop-Location
}

# Verify that the binary contains no developer home path.
$exe = "target/release/cerberus-app.exe"
$text = [Text.Encoding]::Latin1.GetString([IO.File]::ReadAllBytes((Resolve-Path $exe)))
$leaked = [regex]::Matches($text, '[A-Z]:\\Users\\[A-Za-z0-9_.-]+\\') |
          ForEach-Object { $_.Value } | Sort-Object -Unique

Write-Host ""
if ($leaked) {
    Write-Host "Developer paths still present in the binary:" -ForegroundColor Red
    $leaked | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    exit 1
}

Write-Host "Clean build: no build-machine path found in the binary." -ForegroundColor Green
Write-Host "  $exe"
Write-Host "  target/release/bundle/nsis/Cerberus_0.1.0_x64-setup.exe"
