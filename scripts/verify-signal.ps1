$ErrorActionPreference = "Stop"
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$script:stepResults = [System.Collections.Generic.List[string]]::new()
$script:failureMessage = $null
$originalLocation = Get-Location
$originalTemp = $env:TEMP
$originalUvCache = $env:UV_CACHE_DIR
$venvPython = Join-Path $repoRoot ".venv\Scripts\python.exe"
Set-Location $repoRoot

function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $Executable $($Arguments -join ' ')"
    }
}

function Invoke-Step {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Action
    )
    Write-Host "`n== $Name =="
    try {
        & $Action
        $script:stepResults.Add("PASS $Name")
        Write-Host "PASS $Name" -ForegroundColor Green
    }
    catch {
        $script:failureMessage = $_.Exception.Message
        $script:stepResults.Add("FAIL $Name")
        Write-Host "FAIL $Name`n$script:failureMessage" -ForegroundColor Red
        throw
    }
}

try {
    Invoke-Step "1. Select Python 3.12 and temporary cache paths" {
        if (-not (Test-Path -LiteralPath "C:\t" -PathType Container)) {
            throw "Required temporary directory does not exist: C:\t"
        }
        $env:TEMP = "C:\t"
        $env:UV_CACHE_DIR = "C:\t\uv-cache"
        if (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
            throw "Required virtual environment interpreter is missing: $venvPython"
        }
        $version = & $venvPython -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
        if ($LASTEXITCODE -ne 0 -or $version.Trim() -ne "3.12") {
            throw "The virtual environment interpreter must be Python 3.12; $venvPython reported: $version"
        }
        Write-Host "Python=$version TEMP=$env:TEMP UV_CACHE_DIR=$env:UV_CACHE_DIR"
    }

    Invoke-Step "2. Ruff on touched Python files" {
        Invoke-Native $venvPython @(
            "-m", "ruff", "check",
            "chinescan/core/capabilities.py",
            "chinescan/core/logging/redaction.py",
            "chinescan/malware_analysis/analyzer.py",
            "chinescan/core/models/investigation.py",
            "chinescan/core/orchestration/code_rules.py",
            "chinescan/core/orchestration/code_scan.py",
            "chinescan/core/reporting.py",
            "chinescan/web/app.py",
            "tests/unit/test_code_rules_behavior.py",
            "tests/unit/test_code_scan.py",
            "tests/unit/test_malware_analysis.py",
            "tests/unit/test_reporting.py",
            "tests/unit/test_redaction.py",
            "tests/unit/test_redaction_parity.py",
            "tests/unit/test_web_api.py"
        )
    }

    Invoke-Step "2b. Build local Rust redaction extension" {
        Push-Location (Join-Path $repoRoot "engine")
        try { Invoke-Native $venvPython @("-m", "maturin", "develop") }
        finally { Pop-Location }
    }

    Invoke-Step "3. Focused Python tests" {
        Invoke-Native $venvPython @(
            "-m", "pytest", "-q",
            "tests/unit/test_redaction.py",
            "tests/unit/test_redaction_parity.py",
            "tests/unit/test_code_rules_behavior.py",
            "tests/unit/test_code_scan.py",
            "tests/unit/test_malware_analysis.py",
            "tests/unit/test_reporting.py",
            "tests/unit/test_web_api.py"
        )
    }

    $rustChanges = @(git diff --name-only feature/rust-engine -- engine/src)
    if ($rustChanges.Count -gt 0) {
        Invoke-Step "4a. Rust formatting check" {
            Push-Location (Join-Path $repoRoot "engine")
            try { Invoke-Native "cargo" @("fmt", "--check") }
            finally { Pop-Location }
        }
        Invoke-Step "4b. Rust Clippy" {
            Push-Location (Join-Path $repoRoot "engine")
            try { Invoke-Native "cargo" @("clippy", "--all-targets", "--", "-D", "warnings") }
            finally { Pop-Location }
        }
        Invoke-Step "4c. Rust tests" {
            Push-Location (Join-Path $repoRoot "engine")
            try { Invoke-Native "cargo" @("test") }
            finally { Pop-Location }
        }
    }

    Invoke-Step "5. Frontend unit tests for touched UI" {
        Push-Location (Join-Path $repoRoot "frontend")
        try { Invoke-Native "npm" @("test", "--", "--run", "src/ui/App.test.tsx") }
        finally { Pop-Location }
    }
    Invoke-Step "6. Frontend build" {
        Push-Location (Join-Path $repoRoot "frontend")
        try { Invoke-Native "npm" @("run", "build") }
        finally { Pop-Location }
    }
    Invoke-Step "7. Frontend lint (when configured)" {
        Push-Location (Join-Path $repoRoot "frontend")
        try { Invoke-Native "npm" @("run", "lint", "--if-present") }
        finally { Pop-Location }
    }
    Invoke-Step "8. Frontend typecheck" {
        Push-Location (Join-Path $repoRoot "frontend")
        try { Invoke-Native "npm" @("run", "typecheck") }
        finally { Pop-Location }
    }
}
catch {
    if (-not $script:failureMessage) {
        $script:failureMessage = $_.Exception.Message
    }
}
finally {
    if ($null -eq $originalTemp) { Remove-Item Env:TEMP -ErrorAction SilentlyContinue }
    else { $env:TEMP = $originalTemp }
    if ($null -eq $originalUvCache) { Remove-Item Env:UV_CACHE_DIR -ErrorAction SilentlyContinue }
    else { $env:UV_CACHE_DIR = $originalUvCache }
    Set-Location $originalLocation
    Write-Host "`n========== SIGNAL QUALITY VERIFICATION SUMMARY =========="
    Write-Host "Repository: $repoRoot"
    foreach ($result in $script:stepResults) { Write-Host $result }
    if ($script:failureMessage) {
        Write-Host "Overall: FAIL"
        Write-Host "Failure: $script:failureMessage"
    }
    else {
        Write-Host "Overall: PASS"
    }
    Write-Host "========================================================="
}

if ($script:failureMessage) { exit 1 }
