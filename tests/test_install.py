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


# -- install.ps1 -------------------------------------------------------------


def test_the_windows_installer_is_present():
    assert INSTALL_PS1.is_file()


def test_the_windows_installer_covers_the_same_ground():
    text = INSTALL_PS1.read_text()
    for flag in ("$NoVenv", "$Dev", "$Check", "$Python", "$Venv"):
        assert flag in text
    # curses is the one dependency Windows needs that other platforms do not.
    assert "windows-curses" in text
    # The same guard as install.sh: never delete a directory that is not a venv.
    assert "pyvenv.cfg" in text
    # Execution policy blocks unsigned scripts and is the first thing a Windows
    # user hits; the header has to say so.
    assert "ExecutionPolicy" in text
