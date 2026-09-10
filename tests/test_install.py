"""The installer scripts.

Only the paths that change nothing are exercised here — `--help`, `--check`,
and the refusals. A test that actually installed would need a network and would
rewrite the developer's own environment, so the real install is proved by
running it, not by pytest.

The point of these is that install.sh is the first thing a new user runs, and
nothing else in the suite would notice if it rotted.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
INSTALL_SH = ROOT / "install.sh"
INSTALL_PS1 = ROOT / "install.ps1"

SH = shutil.which("sh")
posix_only = pytest.mark.skipif(
    sys.platform == "win32" or SH is None,
    reason="needs a POSIX shell",
)


def run(*args, cwd=None, env=None):
    return subprocess.run(
        [SH, str(INSTALL_SH), *args],
        cwd=cwd or ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


# -- install.sh --------------------------------------------------------------


def test_the_installer_is_present_and_executable():
    assert INSTALL_SH.is_file()
    if sys.platform != "win32":
        assert os.access(INSTALL_SH, os.X_OK), "install.sh must be chmod +x"


@posix_only
def test_it_is_valid_posix_shell():
    # It declares #!/bin/sh, so it must not rely on bash. `sh -n` parses
    # without executing.
    assert INSTALL_SH.read_text().startswith("#!/bin/sh")
    result = subprocess.run([SH, "-n", str(INSTALL_SH)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


@posix_only
def test_help_explains_the_options():
    result = run("--help")
    assert result.returncode == 0
    for flag in ("--dev", "--check", "--no-venv", "--python", "--venv"):
        assert flag in result.stdout
    # The help is extracted from the header comment; if that extraction breaks
    # it tends to spill shell source into the output.
    assert "set -eu" not in result.stdout


@posix_only
def test_check_reports_without_installing(tmp_path):
    marker = ROOT / ".venv-should-not-appear"
    result = run("--check", "--venv", str(tmp_path / "unused"))
    assert result.returncode == 0, result.stderr
    assert "nothing was changed" in result.stdout
    assert "Python" in result.stdout
    assert not (tmp_path / "unused").exists()
    assert not marker.exists()


@posix_only
def test_an_unknown_option_fails_loudly():
    result = run("--definitely-not-an-option")
    assert result.returncode != 0
    assert "unknown option" in result.stderr


@posix_only
def test_it_refuses_to_run_outside_the_checkout(tmp_path):
    # Copied somewhere with no pyproject.toml, it must say so rather than
    # building a venv that can never work.
    stray = tmp_path / "install.sh"
    shutil.copy(INSTALL_SH, stray)
    result = subprocess.run(
        [SH, str(stray), "--check"], capture_output=True, text=True, timeout=60
    )
    assert result.returncode != 0
    assert "llm-testsuite checkout" in result.stderr


@posix_only
def test_it_rejects_an_interpreter_that_does_not_exist():
    result = run("--python", "/nonexistent/python", "--check")
    assert result.returncode != 0
    assert "no such interpreter" in result.stderr


@posix_only
def test_it_rejects_an_interpreter_that_is_too_old(tmp_path):
    fake = tmp_path / "python3.9"
    fake.write_text(
        "#!/bin/sh\n"
        'case "$2" in\n'
        '  *"sys.exit"*) exit 1 ;;\n'
        '  *"print"*) echo "3.9.18"; exit 0 ;;\n'
        "esac\nexit 0\n"
    )
    fake.chmod(0o755)
    result = run("--python", str(fake), "--check")
    assert result.returncode != 0
    assert "3.9.18" in result.stderr
    assert "3.10 or newer is required" in result.stderr


@posix_only
def test_it_will_not_delete_a_directory_that_is_not_a_venv(tmp_path):
    # --venv takes a path, so this guard is the difference between removing a
    # half-built environment and removing whatever the user mistyped.
    precious = tmp_path / "not-a-venv"
    precious.mkdir()
    (precious / "important.txt").write_text("keep me")

    result = run("--venv", str(precious))
    assert result.returncode != 0
    assert "not a virtual environment" in result.stderr
    assert (precious / "important.txt").read_text() == "keep me"


@posix_only
def test_an_empty_directory_is_fine_to_use(tmp_path):
    # Refusing every existing directory would break `mkdir venv && install`.
    # Only a non-empty non-venv is a refusal.
    empty = tmp_path / "empty"
    empty.mkdir()
    result = run("--check", "--venv", str(empty))
    assert result.returncode == 0


# -- installing missing system dependencies ----------------------------------
#
# These drive install.sh against a fake interpreter whose venv module appears
# only once a fake package manager has "installed" it. Nothing real is touched:
# the whole environment is a temp directory on PATH.

FAKE_PYTHON = """#!/bin/sh
case "$2" in
  "import venv"|"import ensurepip")
      [ -f "$FAKE_STATE/installed" ] && exit 0 || exit 1 ;;
  "import curses") exit 0 ;;
  *"sys.exit"*) exit 0 ;;
  *"print"*) echo "3.11.9"; exit 0 ;;
esac
exit 0
"""

FAKE_APT = """#!/bin/sh
echo "apt-get $*" >> "$FAKE_STATE/log"
case "$1" in install) touch "$FAKE_STATE/installed" ;; esac
exit 0
"""

# Fails the version-specific package the way apt does when it does not exist.
FAKE_APT_NO_VERSIONED = """#!/bin/sh
echo "apt-get $*" >> "$FAKE_STATE/log"
case "$*" in
  *python3.11-venv*) echo "E: Unable to locate package" >&2; exit 100 ;;
  *install*) touch "$FAKE_STATE/installed" ;;
esac
exit 0
"""

TOOLS = ("dirname", "grep", "awk", "sed", "uname", "rm", "mkdir", "cut", "tput",
         "cat", "head", "tail", "id", "sh", "touch")


@pytest.fixture
def fake_env(tmp_path):
    """An isolated PATH: real coreutils, a fake python, a fake apt-get."""
    bin_dir = tmp_path / "bin"
    state = tmp_path / "state"
    bin_dir.mkdir()
    state.mkdir()
    for tool in TOOLS:
        found = shutil.which(tool)
        if found:
            (bin_dir / tool).symlink_to(found)

    def write(name, body):
        path = bin_dir / name
        path.write_text(body)
        path.chmod(0o755)

    write("python3", FAKE_PYTHON)
    write("apt-get", FAKE_APT)
    # This environment is not root, so the installer correctly wants sudo.
    # A fake one that logs and then execs keeps the privilege path exercised
    # without anything actually gaining privilege.
    write("sudo", '#!/bin/sh\necho "sudo $*" >> "$FAKE_STATE/log"\nexec "$@"\n')

    env = dict(os.environ)
    env["PATH"] = str(bin_dir)
    env["FAKE_STATE"] = str(state)
    env["NO_COLOR"] = "1"
    return type("FakeEnv", (), {"env": env, "state": state, "bin": bin_dir,
                                "write": staticmethod(write)})()


def ran(fake_env):
    log = fake_env.state / "log"
    return log.read_text() if log.exists() else ""


@posix_only
def test_a_missing_dependency_is_offered_not_just_reported(fake_env):
    # Without a terminal it must still SHOW the exact command it would run.
    result = run("--check", env=fake_env.env)
    assert "apt-get install -y python3.11-venv" in result.stdout


@posix_only
def test_nothing_is_installed_without_an_answer(fake_env):
    # No terminal to ask on, and no --yes: it must not install, and must not
    # hang waiting for input that can never arrive.
    result = run("--check", env=fake_env.env)
    assert ran(fake_env) == ""
    assert "no terminal to ask on" in result.stdout
    assert result.returncode != 0


@posix_only
def test_yes_installs_the_dependency_and_continues(fake_env):
    result = run("--check", "--yes", env=fake_env.env)
    log = ran(fake_env)
    assert "apt-get install -y python3.11-venv python3-pip" in log
    # Refreshing the index first is what stops a correct install failing as
    # though the package did not exist.
    assert "apt-get update" in log
    assert "resolved" in result.stdout
    assert result.returncode == 0


@posix_only
def test_no_install_deps_reports_instead(fake_env):
    result = run("--check", "--yes", "--no-install-deps", env=fake_env.env)
    assert ran(fake_env) == ""
    assert result.returncode != 0
    assert "sudo apt install" in result.stderr  # the old advice, as a fallback


@posix_only
def test_the_displayed_command_is_the_command_that_runs(fake_env):
    # A consent prompt that describes something other than what executes is
    # worse than no prompt at all.
    result = run("--check", "--yes", env=fake_env.env)
    shown = [line.strip() for line in result.stdout.splitlines()
             if "apt-get install" in line]
    assert shown, result.stdout
    executed = [line.strip() for line in ran(fake_env).splitlines()]
    for piece in shown[0].split(" && "):
        assert piece.strip() in executed


@posix_only
def test_it_falls_back_when_the_versioned_package_does_not_exist(fake_env):
    fake_env.write("apt-get", FAKE_APT_NO_VERSIONED)
    result = run("--check", "--yes", env=fake_env.env)
    log = ran(fake_env)
    assert "python3.11-venv" in log        # tried the specific name first
    assert "python3-venv python3-pip" in log  # then the metapackage
    assert result.returncode == 0


@posix_only
def test_a_declined_offer_is_not_re_asked_under_another_name(fake_env):
    # Saying no once must not produce a second prompt for the fallback package.
    fake_env.write("apt-get", FAKE_APT_NO_VERSIONED)
    result = run("--check", env=fake_env.env)  # no tty, so "cannot ask"
    assert result.stdout.count("can be installed with") == 1
    assert ran(fake_env) == ""


@posix_only
def test_it_verifies_the_module_rather_than_trusting_the_exit_code(fake_env):
    # On Debian the wrong -venv package installs cleanly and changes nothing,
    # so a zero exit from the package manager proves nothing.
    fake_env.write("apt-get", '#!/bin/sh\necho "apt-get $*" >> "$FAKE_STATE/log"\nexit 0\n')
    result = run("--check", "--yes", env=fake_env.env)
    assert result.returncode != 0
    assert "still missing after installing" in result.stderr


@posix_only
def test_it_refuses_when_root_is_needed_but_sudo_is_absent(fake_env):
    # sudo_prefix runs inside the command substitution that builds the install
    # command. If it returns non-zero there, `set -e` aborts the substitution
    # and yields an empty string — and `sh -c ""` exits 0, reporting an install
    # that never happened. This asserts the refusal, not a false success.
    (fake_env.bin / "sudo").unlink()
    assert shutil.which("sudo", path=str(fake_env.bin)) is None

    result = run("--check", "--yes", env=fake_env.env)
    assert ran(fake_env) == ""
    assert "sudo is not available" in result.stdout
    assert "installed" not in result.stdout.split("sudo is not available")[-1]
    assert result.returncode != 0


@posix_only
def test_sudo_is_used_when_not_root(fake_env):
    result = run("--check", "--yes", env=fake_env.env)
    assert "sudo apt-get install" in result.stdout
    assert "sudo apt-get install" in ran(fake_env)
    assert result.returncode == 0


# -- install.ps1 -------------------------------------------------------------


def test_the_windows_installer_is_present():
    assert INSTALL_PS1.is_file()


def test_the_windows_installer_covers_the_same_ground():
    text = INSTALL_PS1.read_text()
    for flag in ("$NoVenv", "$Dev", "$Check", "$Python", "$Venv", "$Yes",
                 "$NoInstallDeps"):
        assert flag in text
    # curses is the one dependency Windows needs that other platforms do not.
    assert "windows-curses" in text
    # The same guard as install.sh: never delete a directory that is not a venv.
    assert "pyvenv.cfg" in text
    # Execution policy blocks unsigned scripts and is the first thing a Windows
    # user hits; the header has to say so.
    assert "ExecutionPolicy" in text


def test_the_windows_installer_does_not_leak_command_output_into_its_return():
    # The bug this guards against: a PowerShell function returns everything
    # left on its output stream, so a bare `& cmd /c $Command` made
    # Install-WithConsent return [winget's output..., $false]. A non-empty
    # array is truthy, so `if (Install-WithConsent ...)` took the success
    # branch after a FAILED install and told the user to reopen their shell to
    # find a Python that had never been installed.
    text = INSTALL_PS1.read_text()
    assert "& cmd /c $Command 2>&1 | ForEach-Object { Write-Host" in text, (
        "cmd output must go to the host, not the pipeline"
    )
    # Nothing may invoke cmd without redirecting its output.
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("& cmd /c"):
            assert "|" in stripped, f"unpiped cmd invocation: {stripped}"


def test_the_windows_installer_does_not_trust_wingets_exit_code():
    # Reported from a real Windows run: winget said "Found an existing package
    # already installed / No available upgrade found" and exited 0x8A15002B
    # (-1978335189). That is a failure to UPGRADE, not a failure to have
    # Python — but the script stopped there and declared Python missing.
    # Discovery must run whatever winget's exit code was, the same way
    # install.sh re-checks the module rather than trusting apt.
    text = INSTALL_PS1.read_text()
    assert "looking for Python anyway" in text
    # PEP 514 is the authoritative record of an installed Python, whoever ran
    # the installer and whichever scope it used.
    assert "Get-PythonFromRegistry" in text
    assert "HKCU:\\SOFTWARE\\Python" in text and "HKLM:\\SOFTWARE\\Python" in text
    # And when it still finds nothing, it must say where it looked.
    assert "searched PATH, the registry, and:" in text


def test_the_windows_installer_offers_a_way_out_when_it_cannot_find_python():
    # The last-resort message has to be actionable, not just "install Python".
    text = INSTALL_PS1.read_text()
    assert "-Python " in text
    assert "Get-ChildItem" in text


def test_the_windows_installer_fails_loudly_on_an_explicit_python():
    # Reported: the user passed -Python with a path, and the script answered
    # "no python interpreter found" and started installing — because the
    # candidate loop uses Get-Command, which simply skips a path that does not
    # exist. An interpreter the user named explicitly is a claim to check, not
    # a candidate to silently drop. install.sh has always died here.
    text = INSTALL_PS1.read_text()
    assert "-Python points at a path that does not exist" in text
    assert "Nothing was searched, because you named an interpreter explicitly" in text
    # And the two other ways an explicit path can be wrong.
    assert "-Python is not a usable interpreter" in text
    assert "or newer is required" in text


def test_the_windows_installer_distinguishes_missing_from_never_installed():
    # A winget record can outlive the files it points at. "recorded but
    # missing from disk" and "never installed" need different fixes, so the
    # diagnostic has to tell them apart.
    text = INSTALL_PS1.read_text()
    assert "Get-PythonRegistryPaths" in text
    assert "RECORDED BUT MISSING FROM DISK" in text
    assert "no Python is recorded in the PEP 514 registry keys at all" in text


PWSH = shutil.which("pwsh") or shutil.which("powershell")
powershell_only = pytest.mark.skipif(PWSH is None, reason="needs PowerShell")


@powershell_only
def test_the_windows_installer_parses():
    # A syntax error would only ever surface on a user's machine otherwise.
    script = (
        "$errs = $null; "
        f"[System.Management.Automation.Language.Parser]::ParseFile('{INSTALL_PS1}', "
        "[ref]$null, [ref]$errs) | Out-Null; "
        "if ($errs) { $errs | ForEach-Object { $_.Message }; exit 1 }; exit 0"
    )
    result = subprocess.run([PWSH, "-NoProfile", "-Command", script],
                            capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr


@powershell_only
def test_the_windows_installer_check_mode_changes_nothing(tmp_path):
    result = subprocess.run(
        [PWSH, "-NoProfile", "-File", str(INSTALL_PS1), "-Check",
         "-Venv", str(tmp_path / "unused")],
        cwd=ROOT, capture_output=True, text=True, timeout=300,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "nothing was changed" in result.stdout
    assert not (tmp_path / "unused").exists()


@powershell_only
def test_the_windows_installer_will_not_delete_a_non_venv(tmp_path):
    precious = tmp_path / "not-a-venv"
    precious.mkdir()
    (precious / "important.txt").write_text("keep me")

    result = subprocess.run(
        [PWSH, "-NoProfile", "-File", str(INSTALL_PS1), "-Venv", str(precious)],
        cwd=ROOT, capture_output=True, text=True, timeout=300,
    )
    assert result.returncode != 0
    assert "not a virtual environment" in result.stdout
    assert (precious / "important.txt").read_text() == "keep me"


@powershell_only
def test_the_windows_installer_rejects_a_nonexistent_explicit_python(tmp_path):
    missing = tmp_path / "Matthew James" / "Python312" / "python.exe"
    result = subprocess.run(
        [PWSH, "-NoProfile", "-File", str(INSTALL_PS1), "-Check",
         "-Python", str(missing)],
        cwd=ROOT, capture_output=True, text=True, timeout=300,
    )
    assert result.returncode != 0
    assert "no such interpreter" in result.stdout
    # It must NOT have gone off looking, or offered to install anything.
    assert "no python interpreter found" not in result.stdout
    assert "can be installed with" not in result.stdout


@powershell_only
def test_a_spaced_explicit_python_path_is_found_not_mangled(tmp_path):
    # Windows home directories routinely contain a space — the reporter's was
    # "C:\Users\Matthew James\..." — so a space must not break the path
    # handling in Test-Path -LiteralPath and `& $Exe`.
    #
    # This deliberately does not require the copied file to RUN. A lone
    # python.exe on Windows has neither its DLLs nor its stdlib beside it, so
    # it cannot start; asserting a successful run here only tested that the
    # copy happened to work on Linux. What matters is that the path was
    # resolved: reaching the version check at all proves the space survived.
    spaced = tmp_path / "Matthew James" / "Python312"
    spaced.mkdir(parents=True)
    exe = spaced / ("python.exe" if sys.platform == "win32" else "python")
    shutil.copy(sys.executable, exe)

    result = subprocess.run(
        [PWSH, "-NoProfile", "-File", str(INSTALL_PS1), "-Check",
         "-Python", str(exe), "-Venv", str(tmp_path / "unused")],
        cwd=ROOT, capture_output=True, text=True, timeout=300,
    )
    output = result.stdout + result.stderr
    # The file was located despite the space: not confused with a missing one.
    assert "no such interpreter" not in output, output
    assert "does not exist" not in output, output
    assert str(exe) in output, output
    # And an explicit -Python never wanders off into the search or winget.
    assert "no python interpreter found" not in output, output
    assert "can be installed with" not in output, output
