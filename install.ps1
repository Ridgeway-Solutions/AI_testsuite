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

.PARAMETER Yes
    Answer yes to every prompt. Needed for unattended and CI runs.

.PARAMETER NoInstallDeps
    Never install anything system-wide; report what is missing instead.

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
    [string] $Python,
    [switch] $Yes,
    [switch] $NoInstallDeps
)

$ErrorActionPreference = 'Stop'
$MinVersion = [Version]'3.10'

# This is a Windows installer, but PowerShell runs everywhere — and a script
# that cannot run outside Windows cannot be tested outside Windows, which is
# exactly how a bug shipped here before. Deriving the few platform-specific
# bits lets CI exercise the whole thing under pwsh on Linux.
# $IsWindows does not exist in Windows PowerShell 5.1, which only runs on
# Windows, so its absence means Windows.
$OnWindows = (-not (Test-Path variable:IsWindows)) -or $IsWindows
$VenvBin = if ($OnWindows) { 'Scripts' } else { 'bin' }
$ExeSuffix = if ($OnWindows) { '.exe' } else { '' }

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

# Ask before installing anything system-wide. Fails closed: with no console to
# ask on (CI, a non-interactive host) this returns $false rather than assuming
# consent, unless -Yes was given.
$script:CouldNotAsk = $false
function Confirm-Action {
    param([string] $Question)
    $script:CouldNotAsk = $false
    if ($Yes) {
        Write-Note '(-Yes given)'
        return $true
    }
    if ([Console]::IsInputRedirected -or -not $Host.UI.RawUI) {
        $script:CouldNotAsk = $true
        return $false
    }
    try {
        $reply = Read-Host "`n  $Question [y/N]"
    } catch {
        $script:CouldNotAsk = $true
        return $false
    }
    return $reply -match '^(y|yes)$'
}

# Shows the exact command, asks, then runs that same string. Building the
# displayed and executed commands separately would let the prompt describe
# something other than what runs.
function Install-WithConsent {
    param([string] $What, [string] $Command)
    if ($NoInstallDeps) {
        Write-Note "-NoInstallDeps given, so not offering to install $What"
        return $false
    }
    Write-Host "`n  $What can be installed with:`n"
    Write-Host "      $Command" -ForegroundColor White
    if (-not (Confirm-Action 'Run it now?')) {
        if ($script:CouldNotAsk) {
            Write-Warn 'no console to ask on - nothing was installed'
            Write-Note 're-run with -Yes to install without being asked'
        } else {
            Write-Warn 'declined - nothing was installed'
        }
        return $false
    }
    Write-Host ''
    # Route the command's output to the host, not to the pipeline.
    #
    # A PowerShell function returns everything left on its output stream, so a
    # bare `& cmd /c $Command` makes this function return [winget's output
    # lines..., $false]. A non-empty array is truthy, so `if
    # (Install-WithConsent ...)` then took the success branch even when the
    # install had failed — and the output the user needed in order to see why
    # was swallowed as the return value instead of printed.
    & cmd /c $Command 2>&1 | ForEach-Object { Write-Host "  $_" }
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        Write-Warn "that command failed (exit code $code)"
        return $false
    }
    return $true
}

# Where Windows actually puts Python. Get-Command only ever looks at PATH, and
# a shell opened before the install has none of the new entries — so after
# installing we look on disk rather than telling the user to open a new window
# and hoping.
# Every python.org installer records itself in the registry under PEP 514,
# whether it was run directly or by winget, and for either scope. That is the
# authoritative answer to "where is Python", so ask it before guessing at
# directories.
function Get-PythonFromRegistry {
    $found = @()
    foreach ($hive in 'HKCU:\SOFTWARE\Python', 'HKLM:\SOFTWARE\Python',
                      'HKLM:\SOFTWARE\WOW6432Node\Python') {
        $companies = Get-ChildItem $hive -ErrorAction SilentlyContinue
        foreach ($company in $companies) {
            foreach ($tag in (Get-ChildItem $company.PSPath -ErrorAction SilentlyContinue)) {
                $key = Get-ItemProperty "$($tag.PSPath)\InstallPath" -ErrorAction SilentlyContinue
                if (-not $key) { continue }
                # The executable is named by ExecutablePath, or sits under the
                # default value of the InstallPath key.
                if ($key.ExecutablePath -and (Test-Path $key.ExecutablePath)) {
                    $found += $key.ExecutablePath
                } elseif ($key.'(default)') {
                    $exe = Join-Path $key.'(default)' 'python.exe'
                    if (Test-Path $exe) { $found += $exe }
                }
            }
        }
    }
    return $found
}

# The paths the registry CLAIMS, whether or not they still exist. A winget
# record can outlive the files it points at, and "recorded but missing" is a
# completely different problem from "never installed" — the diagnostic has to
# tell those apart.
function Get-PythonRegistryPaths {
    $found = @()
    foreach ($hive in 'HKCU:\SOFTWARE\Python', 'HKLM:\SOFTWARE\Python',
                      'HKLM:\SOFTWARE\WOW6432Node\Python') {
        foreach ($company in (Get-ChildItem $hive -ErrorAction SilentlyContinue)) {
            foreach ($tag in (Get-ChildItem $company.PSPath -ErrorAction SilentlyContinue)) {
                $key = Get-ItemProperty "$($tag.PSPath)\InstallPath" -ErrorAction SilentlyContinue
                if (-not $key) { continue }
                if ($key.ExecutablePath) { $found += $key.ExecutablePath }
                elseif ($key.'(default)') { $found += (Join-Path $key.'(default)' 'python.exe') }
            }
        }
    }
    return $found | Sort-Object -Unique
}

# Where the installers put Python when the registry has nothing to say.
function Get-PythonFromDisk {
    $patterns = @()
    foreach ($root in $env:LOCALAPPDATA, $env:ProgramFiles, ${env:ProgramFiles(x86)},
                      $env:ProgramW6432) {
        if (-not $root) { continue }
        $patterns += (Join-Path $root 'Programs\Python\Python3*\python.exe')
        $patterns += (Join-Path $root 'Python3*\python.exe')
    }
    if ($env:LOCALAPPDATA) {
        $patterns += (Join-Path $env:LOCALAPPDATA 'Programs\Python\Launcher\py.exe')
    }
    if ($env:WINDIR) { $patterns += (Join-Path $env:WINDIR 'py.exe') }

    $found = @()
    foreach ($pattern in $patterns) {
        foreach ($item in (Get-Item -Path $pattern -ErrorAction SilentlyContinue)) {
            $found += $item.FullName
        }
    }
    return $found
}

function Find-PythonOnDisk {
    # Newest first, so a box with several gets the highest version.
    return @(Get-PythonFromRegistry) + @(Get-PythonFromDisk) |
        Where-Object { $_ } | Sort-Object -Descending -Unique
}

# Try every interpreter we can find that is not on PATH. Returns the first
# usable one as @(exe, version), or $null.
function Resolve-PythonOffPath {
    foreach ($path in Find-PythonOnDisk) {
        $version = Get-PyVersion -Exe $path
        if ($version -and $version -ge $MinVersion) { return @($path, $version) }
    }
    return $null
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
    # An explicitly named interpreter is a claim to check, not a candidate to
    # try and quietly skip. Falling through to the winget branch here told the
    # reporter "no python interpreter found" straight after they had named one,
    # which hid the actual problem (the path did not exist). install.sh has
    # always failed loudly on --python; this now matches it.
    if (-not (Test-Path -LiteralPath $Python)) {
        Write-Bad "no such interpreter: $Python"
        Stop-With "-Python points at a path that does not exist" @(
            'Nothing was searched, because you named an interpreter explicitly.',
            '',
            'Find the real one with:',
            '  Get-ChildItem $env:LOCALAPPDATA\Programs\Python,$env:ProgramFiles -Filter python.exe -Recurse -Depth 3 -ErrorAction SilentlyContinue | % FullName',
            '',
            'Or drop -Python and let this script search for you.'
        )
    }
    $explicit = Get-PyVersion -Exe $Python
    if (-not $explicit) {
        Write-Bad "$Python exists but did not report a version"
        Stop-With "-Python is not a usable interpreter" @(
            'It may be the Microsoft Store stub, or a broken install. Try:',
            "  & '$Python' --version"
        )
    }
    if ($explicit -lt $MinVersion) {
        Write-Bad "$Python is $explicit"
        Stop-With "-Python is $explicit, but $MinVersion or newer is required"
    }
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

    if (Get-Command winget -ErrorAction SilentlyContinue) {
        # The two --accept flags matter: without them winget stops on its
        # source and package agreements, which is a common way for this to
        # fail with no useful message.
        $wingetCmd = 'winget install -e --id Python.Python.3.12 ' +
                     '--accept-package-agreements --accept-source-agreements'
        if (-not (Install-WithConsent 'Python 3.12' $wingetCmd)) {
            # A non-zero exit does NOT mean Python is absent. When the package
            # is already installed, winget reports "No applicable upgrade" and
            # exits 0x8A15002B (-1978335189) — a failure to upgrade, not a
            # failure to have Python. So look for an interpreter regardless,
            # the same way install.sh trusts the re-check over the package
            # manager's exit code.
            Write-Note 'looking for Python anyway - "already installed" also exits non-zero'
        }
    } else {
        Write-Note 'winget is not available to install it automatically'
    }

    # One discovery pass, whatever happened above: PATH first, then the
    # registry and the usual install directories. PATH in this process
    # predates any install, and Get-Command only ever consults PATH.
    foreach ($candidate in $candidates) {
        $exe, $prefix = $candidate
        if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) { continue }
        $version = Get-PyVersion -Exe $exe -Prefix $prefix
        if ($version -and $version -ge $MinVersion) {
            $PyExe = $exe; $PyArgs = $prefix; $PyVersion = $version
            break
        }
    }
    if (-not $PyExe) {
        $offPath = Resolve-PythonOffPath
        if ($offPath) {
            $PyExe = $offPath[0]; $PyArgs = @(); $PyVersion = $offPath[1]
            Write-Note "found it at $PyExe (not on this shell's PATH)"
        }
    }

    # Still nothing: say where we looked, so the next report is diagnosable
    # rather than another round trip.
    if (-not $PyExe) {
        $registered = @(Get-PythonRegistryPaths)
        if ($registered) {
            Write-Note 'the registry names these, but they could not be used:'
            foreach ($entry in $registered) {
                $state = if (Test-Path -LiteralPath $entry) { 'exists but did not run' }
                         else { 'RECORDED BUT MISSING FROM DISK' }
                Write-Note "  $entry  ($state)"
            }
            Write-Note 'a missing file usually means it was uninstalled outside winget'
        } else {
            Write-Note 'no Python is recorded in the PEP 514 registry keys at all'
        }
        Write-Note 'searched PATH, the registry, and:'
        foreach ($root in $env:LOCALAPPDATA, $env:ProgramFiles, ${env:ProgramFiles(x86)}) {
            if ($root) { Write-Note "  $root\**\Python3*\python.exe" }
        }
    }
}

if (-not $PyExe) {
    Stop-With "Python $MinVersion+ is required" @(
        'Install it, then re-run this script:',
        '',
        '  winget install Python.Python.3.12',
        '  or  https://www.python.org/downloads/',
        '',
        'Tick "Add python.exe to PATH" in the installer.',
        '',
        'If Python IS installed and this still cannot see it, find it with:',
        '  Get-ChildItem $env:LOCALAPPDATA\Programs\Python,$env:ProgramFiles -Filter python.exe -Recurse -Depth 3 -ErrorAction SilentlyContinue | % FullName',
        'then point this script straight at it:',
        '  .\install.ps1 -Python "C:\path\to\python.exe"'
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
elseif ($OnWindows) { Write-Warn 'curses missing - will install windows-curses for the terminal UI' }
else { Write-Warn "curses missing - 'llmtest tui' unavailable, 'llmtest run' still works" }

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
    $VenvPy = Join-Path $Venv (Join-Path $VenvBin "python$ExeSuffix")
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
if ($LASTEXITCODE -ne 0 -and $OnWindows) {
    Invoke-VenvPy @('-m', 'pip', 'install', '--quiet', 'windows-curses') 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Ok 'windows-curses installed (terminal UI available)'
        $HasCurses = $true
    } else {
        Write-Warn "windows-curses failed to install - 'llmtest tui' will be unavailable"
        $HasCurses = $false
    }
} elseif ($LASTEXITCODE -ne 0) {
    Write-Warn "no curses - use 'llmtest run'; the terminal UI needs it"
    $HasCurses = $false
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
    $activate = if ($OnWindows) { ".\$Venv\Scripts\Activate.ps1" }
                else { "./$Venv/bin/Activate.ps1" }
    Write-Host "`n    $activate`n" -ForegroundColor White
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
Write-Note "written permission to test - see $(if ($OnWindows) {'docs\ETHICS.md'} else {'docs/ETHICS.md'})."
