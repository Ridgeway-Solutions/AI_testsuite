<#
.SYNOPSIS
    Installer for llm-testsuite on Windows.

.DESCRIPTION
    Checks everything the suite needs, installs what is missing, and then
    proves the result actually works before claiming it did.

    PowerShell blocks unsigned scripts by default. Either run it as:

        powershell -ExecutionPolicy Bypass -File .\install.ps1

    or allow scripts for this session only:

        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
        .\install.ps1

.PARAMETER Venv
    Directory for the virtual environment. Default: .venv

.PARAMETER NoVenv
    Install into the interpreter you are already using instead of a venv.

.PARAMETER Dev
    Also install the test dependencies.

.PARAMETER Check
    Report what is missing and change nothing.

.PARAMETER Python
    Path to a specific interpreter to use.

.EXAMPLE
    .\install.ps1
.EXAMPLE
    .\install.ps1 -Check
.EXAMPLE
    .\install.ps1 -Dev
#>

[CmdletBinding()]
param(
    [string] $Venv = '.venv',
    [switch] $NoVenv,
    [switch] $Dev,
    [switch] $Check,
    [string] $Python
)

$ErrorActionPreference = 'Stop'
$MinVersion = [Version]'3.10'

function Write-Ok    { param($m) Write-Host "  [ok] $m"   -ForegroundColor Green }
function Write-Warn  { param($m) Write-Host "  [!]  $m"   -ForegroundColor Yellow }
function Write-Bad   { param($m) Write-Host "  [x] $m"    -ForegroundColor Red }
function Write-Step  { param($m) Write-Host "`n$m"        -ForegroundColor White }
function Write-Note  { param($m) Write-Host "    $m"      -ForegroundColor DarkGray }

function Stop-With {
    param([string] $Message, [string[]] $Detail = @())
    Write-Host ''
    Write-Host "error: $Message" -ForegroundColor Red
    foreach ($line in $Detail) { Write-Host "  $line" }
    exit 1
}

# Run from the repository root whatever directory the user invoked us from.
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

Write-Host 'llm-testsuite installer' -ForegroundColor White
if ($Check) { Write-Note 'check only - nothing will be installed' }

# ------------------------------------------------------------------- the repo

Write-Step 'Repository'
$pyproject = Join-Path $Root 'pyproject.toml'
if (-not (Test-Path $pyproject) -or
    -not (Select-String -Path $pyproject -Pattern 'name = "llm-testsuite"' -Quiet)) {
    Stop-With 'this script must live in the llm-testsuite checkout' @(
        "expected $pyproject to be llm-testsuite's",
        '',
        '  git clone https://github.com/Ridgeway-Solutions/AI_testsuite',
        '  cd AI_testsuite',
        '  .\install.ps1'
    )
}
Write-Ok "llm-testsuite checkout at $Root"

# -------------------------------------------------------------------- python

Write-Step "Python $MinVersion or newer"

function Get-PyVersion {
    param([string] $Exe, [string[]] $Prefix = @())
    try {
        $argv = $Prefix + @('-c', 'import sys; print("%d.%d.%d" % sys.version_info[:3])')
        $out = & $Exe @argv 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $out) { return $null }
        return [Version](($out | Select-Object -First 1).Trim())
    } catch { return $null }
}

# Each candidate is an executable plus any launcher arguments. The `py` launcher
# is the reliable way to reach a specific Python on Windows; a bare `python` may
# be the Microsoft Store stub that only opens the Store.
$candidates = @()
if ($Python) {
    $candidates += ,@($Python, @())
} else {
    foreach ($v in '3.14', '3.13', '3.12', '3.11', '3.10') {
        $candidates += ,@('py', @("-$v"))
    }
    $candidates += ,@('py', @('-3'))
    $candidates += ,@('python', @())
    $candidates += ,@('python3', @())
}

$PyExe = $null; $PyArgs = @(); $PyVersion = $null; $TooOld = $null
foreach ($candidate in $candidates) {
    $exe, $prefix = $candidate
    if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) { continue }
    $version = Get-PyVersion -Exe $exe -Prefix $prefix
    if (-not $version) { continue }
    if ($version -ge $MinVersion) {
        $PyExe = $exe; $PyArgs = $prefix; $PyVersion = $version
        break
    }
    if (-not $TooOld) { $TooOld = "$exe $($prefix -join ' ') ($version)" }
}

if (-not $PyExe) {
    if ($TooOld) { Write-Bad "found $TooOld - too old" }
    else { Write-Bad 'no python interpreter found' }
    Stop-With "Python $MinVersion+ is required and cannot be installed safely from here" @(
        'Install it, then re-run this script:',
        '',
        '  winget install Python.Python.3.12',
        '  or  https://www.python.org/downloads/',
        '',
        'Tick "Add python.exe to PATH" in the installer.'
    )
}
Write-Ok "$PyExe $($PyArgs -join ' ') ($PyVersion)"

function Invoke-Py {
    param([string[]] $Arguments)
    & $PyExe @($PyArgs + $Arguments)
}

function Test-PyModule {
    param([string] $Module)
    Invoke-Py @('-c', "import $Module") 2>$null | Out-Null
    return $LASTEXITCODE -eq 0
}

# ---------------------------------------------------------------- preflight

Write-Step 'Installer prerequisites'
if (-not $NoVenv) {
    if (Test-PyModule 'venv') { Write-Ok 'venv module' }
    else { Stop-With 'the venv module is missing' @('Reinstall Python from python.org, which includes it.') }
}
Invoke-Py @('-m', 'pip', '--version') 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Ok 'pip'
} else {
    Stop-With 'pip is missing' @(
        'Try:  ' + $PyExe + ' ' + ($PyArgs -join ' ') + ' -m ensurepip --upgrade'
    )
}

# curses is not in the Windows standard library; windows-curses supplies it.
# Only the terminal UI needs it - `llmtest run` works without.
$HasCurses = Test-PyModule 'curses'
if ($HasCurses) { Write-Ok 'curses (terminal UI available)' }
else { Write-Warn 'curses missing - will install windows-curses for the terminal UI' }

# --------------------------------------------------------------- check mode

if ($Check) {
    Write-Step 'Already installed?'
    if (Test-PyModule 'llmtest') { Write-Ok 'llmtest importable' } else { Write-Warn 'llmtest not installed' }
    if (Test-PyModule 'yaml')    { Write-Ok 'PyYAML' }             else { Write-Warn 'PyYAML not installed (pip will fetch it)' }
    Write-Host ''
    Write-Note 'Everything above is a report only - nothing was changed.'
    Write-Host 'Run .\install.ps1 to install.'
    exit 0
}

# --------------------------------------------------------------- environment

if (-not $NoVenv) {
    Write-Step 'Virtual environment'
    $VenvPy = Join-Path $Venv 'Scripts\python.exe'
    if (Test-Path $VenvPy) {
        Write-Ok "reusing $Venv"
    } else {
        # A half-built venv from an interrupted run is worse than none: it has
        # the layout but no interpreter, and later steps fail obscurely.
        # Only ever delete something provably a venv - pyvenv.cfg is the
        # marker - so a mistyped -Venv cannot turn this into a recursive
        # delete of someone's home directory.
        if (Test-Path $Venv) {
            if (Test-Path (Join-Path $Venv 'pyvenv.cfg')) {
                Remove-Item -Recurse -Force $Venv
                Write-Note "removed an incomplete $Venv"
            } elseif (Get-ChildItem -Force $Venv | Select-Object -First 1) {
                Stop-With "$Venv already exists and is not a virtual environment" @(
                    'Refusing to delete it. Pick another location:',
                    '  .\install.ps1 -Venv some-other-dir'
                )
            }
        }
        Invoke-Py @('-m', 'venv', $Venv)
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $VenvPy)) {
            Stop-With "could not create a virtual environment in $Venv"
        }
        Write-Ok "created $Venv"
    }
    Write-Note 'a venv keeps this off your system Python and makes it trivial to remove'
} else {
    $VenvPy = $PyExe
    Write-Step 'Target environment'
    Write-Warn 'installing into your current interpreter directly (-NoVenv)'
}

function Invoke-VenvPy {
    param([string[]] $Arguments)
    if ($NoVenv) { Invoke-Py $Arguments } else { & $VenvPy @Arguments }
}

# ------------------------------------------------------------------ install

Write-Step 'Dependencies'
Write-Note 'pip installs only what is missing or outdated; this is safe to re-run'

Invoke-VenvPy @('-m', 'pip', 'install', '--quiet', '--upgrade', 'pip') 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) { Write-Ok 'pip up to date' }
else { Write-Warn 'could not upgrade pip - continuing with the version present' }

$target = if ($Dev) { '.[dev]' } else { '.' }
Invoke-VenvPy @('-m', 'pip', 'install', '--editable', $target)
if ($LASTEXITCODE -ne 0) {
    Stop-With 'pip could not install llm-testsuite' @(
        'If the error mentions a network or TLS failure, pip needs to reach',
        'PyPI to fetch PyYAML.'
    )
}
Write-Ok 'llm-testsuite installed (editable - your edits take effect immediately)'
if ($Dev) { Write-Ok 'test dependencies installed' }

Invoke-VenvPy @('-c', 'import curses') 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) {
    Invoke-VenvPy @('-m', 'pip', 'install', '--quiet', 'windows-curses') 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Ok 'windows-curses installed (terminal UI available)'
        $HasCurses = $true
    } else {
        Write-Warn "windows-curses failed to install - 'llmtest tui' will be unavailable"
        $HasCurses = $false
    }
} else {
    $HasCurses = $true
}

# ------------------------------------------------------------------- verify

Write-Step 'Verifying'

Invoke-VenvPy @('-c', 'import yaml') 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) { Write-Ok 'PyYAML importable' } else { Stop-With 'PyYAML did not install' }

$version = Invoke-VenvPy @('-m', 'llmtest', '--version') 2>&1
if ($LASTEXITCODE -ne 0) { Stop-With 'the llmtest command did not run' @("output: $version") }
Write-Ok "$version"

if ($HasCurses) { Write-Ok "curses importable - 'llmtest tui' will work" }
else { Write-Warn "no curses - use 'llmtest run'; the terminal UI needs it" }

# The real proof: load the plugin registry, build a target and plan a suite.
# `plan` sends nothing, so this is safe and offline.
Invoke-VenvPy @('-m', 'llmtest', 'plan', 'suites/quick.yaml') 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) {
    Stop-With 'llmtest installed but could not plan the bundled suite' @(
        'Run this to see why:',
        "  $VenvPy -m llmtest plan suites/quick.yaml"
    )
}
Write-Ok 'end-to-end check passed (registry, target and suite all load)'

# --------------------------------------------------------------- next steps

Write-Host "`nDone.`n" -ForegroundColor Green

if (-not $NoVenv) {
    Write-Host 'Activate the environment:'
    Write-Host "`n    .\$Venv\Scripts\Activate.ps1`n" -ForegroundColor White
    Write-Host 'Then start it:'
} else {
    Write-Host 'Start it:'
}
Write-Host ''
if ($HasCurses) {
    Write-Host '    llmtest tui suites/quick.yaml' -ForegroundColor White -NoNewline
    Write-Host '   the terminal UI, offline mock'
}
Write-Host '    llmtest run suites/quick.yaml' -ForegroundColor White -NoNewline
Write-Host '   the plain CLI, offline mock'
Write-Host '    llmtest --help'
Write-Host ''
Write-Note 'Both commands run against a built-in offline mock: no credentials, no'
Write-Note 'network, no spend. Only run against a real system you own or have'
Write-Note 'written permission to test - see docs\ETHICS.md.'
