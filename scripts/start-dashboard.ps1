param(
    [int]$BackendPort = 8765,
    [int]$FrontendPort = 5173
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$frontendRoot = Join-Path $repositoryRoot 'frontend'

if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    throw 'Python launcher "py" was not found. Install Python 3.12 and try again.'
}
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    throw 'npm was not found. Install Node.js, reopen PowerShell, and try again.'
}
if (-not (Test-Path -LiteralPath (Join-Path $frontendRoot 'node_modules\vite\bin\vite.js'))) {
    throw "Frontend dependencies are missing. Run 'npm ci' once from $frontendRoot, then retry."
}

$backendArguments = @('-3.12', '-m', 'chinescan', 'web', 'serve', '--port', "$BackendPort")
$backend = Start-Process `
    -FilePath 'py' `
    -ArgumentList $backendArguments `
    -WorkingDirectory $repositoryRoot `
    -PassThru

$frontendCommand = "Set-Location -LiteralPath '$frontendRoot'; npm run dev -- --port $FrontendPort"
$frontend = Start-Process `
    -FilePath 'powershell.exe' `
    -ArgumentList @('-NoExit', '-Command', $frontendCommand) `
    -WorkingDirectory $frontendRoot `
    -PassThru

Write-Host "Backend console started (PID $($backend.Id)): http://127.0.0.1:$BackendPort"
Write-Host "Frontend console started (PID $($frontend.Id)): http://127.0.0.1:$FrontendPort"
Write-Host 'Close either service window to stop that service.'
