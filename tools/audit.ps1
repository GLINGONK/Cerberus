# Security verification suite.
#
#   pwsh tools/audit.ps1
#
# Exits with code 1 when a blocking step fails. See
# docs/SECURITY-TESTING.md for the scope and limitations of each check.

$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$failures = @()

function Step($name, $block, [switch]$Advisory) {
    Write-Host ""
    Write-Host "── $name " -NoNewline -ForegroundColor Cyan
    Write-Host ("─" * [Math]::Max(0, 60 - $name.Length)) -ForegroundColor DarkGray
    & $block
    if ($LASTEXITCODE -ne 0) {
        if ($Advisory) {
            Write-Host "  (non-blocking)" -ForegroundColor Yellow
        } else {
            $script:failures += $name
            Write-Host "  FAILED" -ForegroundColor Red
        }
    }
}

Step "Strict compilation (clippy -D warnings)" {
    cargo clippy --workspace --all-targets -- -D warnings 2>&1 |
        Select-String -Pattern "^error|^warning:|Finished" | Select-Object -First 10
}

Step "Test suite" {
    cargo test --workspace 2>&1 | Select-String -Pattern "test result:|FAILED"
}

Step "Measured unlock-attempt cost" {
    cargo test -p cerberus-core --release --test properties -- --ignored --nocapture 2>&1 |
        Select-String -Pattern "costs|test result"
}

Step "Dependency vulnerabilities (cargo audit)" {
    cargo audit 2>&1 | Select-String -Pattern "Crate:|Title:|vulnerabilities|error"
}

Step "Licences, sources and advisories (cargo deny)" {
    cargo deny check 2>&1 | Select-String -Pattern "^error" | Select-Object -First 10
}

Step "No networking crate in the core" {
    $hits = Select-String -Path "core/Cargo.toml" `
        -Pattern "reqwest|hyper|ureq|curl|tokio|rustls|native-tls|openssl"
    if ($hits) {
        Write-Host "  Networking crate found:" -ForegroundColor Red
        $hits | ForEach-Object { Write-Host "    $_" }
        $global:LASTEXITCODE = 1
    } else {
        Write-Host "  none" -ForegroundColor Green
        $global:LASTEXITCODE = 0
    }
}

Step "No npm dependency in the frontend" {
    if ((Test-Path "app/package.json") -or (Test-Path "app/node_modules")) {
        Write-Host "  The frontend has acquired npm dependencies" -ForegroundColor Red
        $global:LASTEXITCODE = 1
    } else {
        Write-Host "  none (plain HTML/CSS/JS)" -ForegroundColor Green
        $global:LASTEXITCODE = 0
    }
}

Step "Binary contains no developer paths" -Advisory {
    $exe = "target/release/cerberus-app.exe"
    if (-not (Test-Path $exe)) {
        Write-Host "  binary missing; run cargo tauri build first" -ForegroundColor Yellow
        $global:LASTEXITCODE = 0
        return
    }
    # Latin-1 maps each byte to one character without loss, allowing a reliable
    # search for readable paths inside the binary.
    $bytes = [IO.File]::ReadAllBytes((Resolve-Path $exe))
    $text = [Text.Encoding]::Latin1.GetString($bytes)
    $found = [regex]::Matches($text, '[A-Z]:\\Users\\[A-Za-z0-9_.-]+\\') |
             ForEach-Object { $_.Value } | Sort-Object -Unique

    if ($found) {
        Write-Host "  Developer paths found in the binary:" -ForegroundColor Yellow
        $found | Select-Object -First 5 | ForEach-Object { Write-Host "    $_" }
        $global:LASTEXITCODE = 1
    } else {
        Write-Host "  none" -ForegroundColor Green
        $global:LASTEXITCODE = 0
    }
}

Step "A synthetic vault leaves no plaintext" {
    $probe = Join-Path $env:TEMP "cerberus-audit-$(Get-Random)"
    New-Item -ItemType Directory -Force $probe | Out-Null
    $out = cargo run --release --quiet -p cerberus-core --example leak_probe -- $probe 2>&1
    Write-Host ($out | Out-String).Trim()
    Remove-Item -Recurse -Force $probe -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host ("═" * 64) -ForegroundColor DarkGray
if ($failures.Count -eq 0) {
    Write-Host "All blocking checks passed." -ForegroundColor Green
    Write-Host ""
    Write-Host "These checks verify expected behaviour; they do not replace an external review." -ForegroundColor DarkGray
    Write-Host "See docs/SECURITY-TESTING.md." -ForegroundColor DarkGray
    exit 0
} else {
    Write-Host "Failures:" -ForegroundColor Red
    $failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 1
}
