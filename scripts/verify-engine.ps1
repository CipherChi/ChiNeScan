$ErrorActionPreference = "Stop"
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$python312 = "C:\Users\CipherChi\AppData\Local\Programs\Python\Python312\python.exe"
$venvPath = "C:\t\engine-verify"
$script:stepResults = [System.Collections.Generic.List[string]]::new()
$script:failureMessage = $null
$script:installMode = "not reached"
$script:originalEngineMode = $env:CHINESCAN_ENGINE
$script:originalPythonPath = $env:PYTHONPATH
$script:originalEnvironment = @{
    PYO3_PYTHON = $env:PYO3_PYTHON
    TEMP = $env:TEMP
    PIP_CACHE_DIR = $env:PIP_CACHE_DIR
    CARGO_HOME = $env:CARGO_HOME
}
$originalLocation = Get-Location
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
    Invoke-Step "1. Select Python 3.12 and temporary directory" {
        if (-not (Test-Path -LiteralPath $python312 -PathType Leaf)) {
            throw "Python 3.12 executable not found: $python312"
        }
        if (-not (Test-Path -LiteralPath "C:\t" -PathType Container)) {
            throw "Required temporary directory does not exist: C:\t"
        }
        $tempItem = Get-Item -LiteralPath "C:\t" -Force
        if (($tempItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Refusing to use a reparse-point temp directory: C:\t"
        }
        $env:PYO3_PYTHON = $python312
        $env:TEMP = "C:\t"
        $env:PIP_CACHE_DIR = "C:\t\pip-cache"
        $env:CARGO_HOME = "C:\t\cargo-home"
        Write-Host "PYO3_PYTHON=$env:PYO3_PYTHON"
        Write-Host "TEMP=$env:TEMP"
    }

    Invoke-Step "2a. Apply rustfmt" {
        Push-Location (Join-Path $repoRoot "engine")
        try { Invoke-Native "cargo" @("fmt") }
        finally { Pop-Location }
    }
    Invoke-Step "2b. Check rustfmt" {
        Push-Location (Join-Path $repoRoot "engine")
        try { Invoke-Native "cargo" @("fmt", "--check") }
        finally { Pop-Location }
    }
    Invoke-Step "2c. Run Clippy" {
        Push-Location (Join-Path $repoRoot "engine")
        try { Invoke-Native "cargo" @("clippy", "--all-targets", "--", "-D", "warnings") }
        finally { Pop-Location }
    }
    Invoke-Step "2d. Run Rust tests" {
        Push-Location (Join-Path $repoRoot "engine")
        try { Invoke-Native "cargo" @("test") }
        finally { Pop-Location }
    }

    Invoke-Step "3. Build the release wheel" {
        $engineRoot = [System.IO.Path]::GetFullPath((Join-Path $repoRoot "engine"))
        $targetRoot = [System.IO.Path]::GetFullPath((Join-Path $engineRoot "target"))
        $wheelDirectory = [System.IO.Path]::GetFullPath((Join-Path $targetRoot "wheels"))
        $targetPrefix = $targetRoot + [System.IO.Path]::DirectorySeparatorChar
        if (-not $wheelDirectory.StartsWith(
                $targetPrefix,
                [System.StringComparison]::OrdinalIgnoreCase
            )) {
            throw "Refusing unexpected wheel directory: $wheelDirectory"
        }
        foreach ($directory in @($engineRoot, $targetRoot, $wheelDirectory)) {
            if (Test-Path -LiteralPath $directory -PathType Container) {
                $directoryItem = Get-Item -LiteralPath $directory -Force
                if (
                    ($directoryItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
                ) {
                    throw "Refusing wheel cleanup through a reparse point: $directory"
                }
            }
        }
        if (Test-Path -LiteralPath $wheelDirectory -PathType Container) {
            Get-ChildItem -LiteralPath $wheelDirectory -Filter "*.whl" -File |
                ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force }
        }
        Push-Location (Join-Path $repoRoot "engine")
        try {
            Invoke-Native "py" @(
                "-3.12", "-m", "maturin", "build", "--release", "-i", $env:PYO3_PYTHON
            )
        }
        finally { Pop-Location }
    }

    Invoke-Step "4. Create an isolated venv and install the engine/project test dependencies" {
        $expectedVenv = [System.IO.Path]::GetFullPath("C:\t\engine-verify")
        $resolvedVenv = [System.IO.Path]::GetFullPath($venvPath)
        if ($resolvedVenv -ne $expectedVenv) {
            throw "Refusing unexpected venv path: $resolvedVenv"
        }
        if (Test-Path -LiteralPath $resolvedVenv) {
            $venvItem = Get-Item -LiteralPath $resolvedVenv -Force
            if (($venvItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Refusing to recursively remove a reparse-point venv: $resolvedVenv"
            }
            Remove-Item -LiteralPath $resolvedVenv -Recurse -Force
        }
        Invoke-Native "py" @("-3.12", "-m", "venv", $resolvedVenv)
        $venvPython = Join-Path $resolvedVenv "Scripts\python.exe"
        $wheelPath = Join-Path $repoRoot "engine\target\wheels"
        $wheels = @(
            Get-ChildItem -LiteralPath $wheelPath -Filter "chinescan_engine-*.whl" -File
        )
        if ($wheels.Count -ne 1) {
            throw "Expected exactly one chinescan_engine wheel; found $($wheels.Count)."
        }
        Invoke-Native $venvPython @("-m", "pip", "install", $wheels[0].FullName)
        try {
            Push-Location $repoRoot
            try { Invoke-Native $venvPython @("-m", "pip", "install", "-e", ".[dev]") }
            finally { Pop-Location }
            $script:installMode = "editable project install plus Rust wheel"
        }
        catch {
            Write-Host (
                "Editable project install failed; using PYTHONPATH=$repoRoot and installing " +
                "pytest for the focused suite."
            )
            $env:PYTHONPATH = $repoRoot
            Invoke-Native $venvPython @("-m", "pip", "install", "pytest")
            $script:installMode = "PYTHONPATH fallback plus pytest and Rust wheel"
        }
        Write-Host "Install mode: $script:installMode"
    }

    $venvPython = Join-Path $venvPath "Scripts\python.exe"
    Invoke-Step "5. Import chinescan_engine and print engine_info" {
        $env:CHINESCAN_ENGINE = "rust"
        Invoke-Native $venvPython @(
            "-c", "import chinescan_engine; print(chinescan_engine.engine_info())"
        )
    }

    Invoke-Step "6a. Run Python redaction tests with Rust required" {
        $env:CHINESCAN_ENGINE = "rust"
        Invoke-Native $venvPython @(
            "-m", "pytest", "tests/unit/test_redaction.py", "tests/unit/test_redaction_parity.py",
            "-q", "-rs"
        )
    }
    Invoke-Step "6b. Run Python redaction tests with Python forced" {
        $env:CHINESCAN_ENGINE = "python"
        Invoke-Native $venvPython @(
            "-m", "pytest", "tests/unit/test_redaction.py", "tests/unit/test_redaction_parity.py",
            "-q", "-rs"
        )
    }

    Invoke-Step "7. Benchmark deterministic 50 MiB corpus" {
        $env:CHINESCAN_ENGINE = "rust"
        Invoke-Native $venvPython @("scripts/bench_redaction.py")
    }
}
catch {
    if (-not $script:failureMessage) {
        $script:failureMessage = $_.Exception.Message
    }
}
finally {
    if ($null -eq $script:originalEngineMode) {
        Remove-Item Env:CHINESCAN_ENGINE -ErrorAction SilentlyContinue
    }
    else {
        $env:CHINESCAN_ENGINE = $script:originalEngineMode
    }
    if ($null -eq $script:originalPythonPath) {
        Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
    }
    else {
        $env:PYTHONPATH = $script:originalPythonPath
    }
    foreach ($name in @("PYO3_PYTHON", "TEMP", "PIP_CACHE_DIR", "CARGO_HOME")) {
        $oldValue = $script:originalEnvironment[$name]
        if ($null -eq $oldValue) {
            Remove-Item "Env:$name" -ErrorAction SilentlyContinue
        }
        else {
            Set-Item "Env:$name" $oldValue
        }
    }
    Set-Location $originalLocation
    Write-Host "`n========== ENGINE VERIFICATION SUMMARY =========="
    Write-Host "Repository: $repoRoot"
    Write-Host "Install mode: $script:installMode"
    foreach ($result in $script:stepResults) { Write-Host $result }
    if ($script:failureMessage) {
        Write-Host "Overall: FAIL"
        Write-Host "Failure: $script:failureMessage"
    }
    else {
        Write-Host "Overall: PASS"
        Write-Host (
            "Review the test counts and benchmark table above before pasting this summary back."
        )
    }
    Write-Host "=================================================="
}

if ($script:failureMessage) { exit 1 }
