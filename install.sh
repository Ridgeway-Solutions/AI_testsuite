#!/bin/sh
# Installer for llm-testsuite (macOS, Linux, and Git Bash / MSYS on Windows).
#
# Checks everything the suite needs, installs what is missing, and then proves
# the result actually works before claiming it did.
#
#   ./install.sh                # into ./.venv  (recommended)
#   ./install.sh --dev          # also the test dependencies
#   ./install.sh --check        # report what is missing, change nothing
#   ./install.sh --no-venv      # into the interpreter you are already using
#   ./install.sh --venv DIR     # somewhere other than ./.venv
#   ./install.sh --python /path/to/python3.12
#   ./install.sh --yes          # answer yes to every prompt (for CI)
#   ./install.sh --no-install-deps   # never touch system packages, just report
#
# Where a system package is missing it shows you the exact command, asks, and
# runs it only if you say yes. It never installs anything without an answer:
# with no terminal to ask on (a pipe, CI) it prints the command and stops
# unless --yes was given.

set -eu

VENV_DIR=.venv
USE_VENV=1
DEV=0
CHECK_ONLY=0
ASSUME_YES=0
INSTALL_DEPS=1
PY=""
MIN_MAJOR=3
MIN_MINOR=10

# ---------------------------------------------------------------- presentation

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    RED=$(printf '\033[31m')
    GREEN=$(printf '\033[32m')
    YELLOW=$(printf '\033[33m')
    DIM=$(printf '\033[2m')
    BOLD=$(printf '\033[1m')
    OFF=$(printf '\033[0m')
else
    RED='' GREEN='' YELLOW='' DIM='' BOLD='' OFF=''
fi

ok()   { printf '  %s✓%s %s\n' "$GREEN" "$OFF" "$1"; }
warn() { printf '  %s!%s %s\n' "$YELLOW" "$OFF" "$1"; }
bad()  { printf '  %s✗%s %s\n' "$RED" "$OFF" "$1"; }
step() { printf '\n%s%s%s\n' "$BOLD" "$1" "$OFF"; }
note() { printf '    %s%s%s\n' "$DIM" "$1" "$OFF"; }

die() {
    printf '\n%serror:%s %s\n' "$RED" "$OFF" "$1" >&2
    shift
    for line in "$@"; do printf '  %s\n' "$line" >&2; done
    exit 1
}

usage() {
    # The header comment is the help text. Read until the first non-comment
    # line rather than a fixed range, so editing the header cannot desync it.
    awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"
    exit 0
}

# ------------------------------------------------------ system package manager

# Everything below only ever runs a package manager after showing the exact
# command and getting a yes. `confirm` fails closed: no terminal means no
# consent, so a piped or CI run reports instead of installing.

# 0 = yes, 1 = said no, 2 = could not ask.
confirm() {
    if [ "$ASSUME_YES" -eq 1 ]; then
        printf '    %s(--yes given)%s\n' "$DIM" "$OFF"
        return 0
    fi
    # Actually opening /dev/tty is the only reliable test: the device node can
    # exist and pass -r while there is no controlling terminal behind it, which
    # is exactly the case in CI and under `curl | sh`.
    #
    # The probe runs in a subshell deliberately. POSIX says a non-interactive
    # shell exits when a redirection on `exec` fails, so probing with `exec` in
    # this shell would abort the whole installer on precisely the machines that
    # have no terminal. A subshell absorbs that.
    if ! (: < /dev/tty) 2>/dev/null; then
        return 2
    fi
    printf '\n  %s%s%s [y/N] ' "$BOLD" "$1" "$OFF"
    read -r reply < /dev/tty || return 2
    case "$reply" in
        [Yy] | [Yy][Ee][Ss]) return 0 ;;
        *) return 1 ;;
    esac
}

detect_package_manager() {
    for manager in apt-get dnf yum pacman zypper apk brew; do
        if command -v "$manager" >/dev/null 2>&1; then
            printf '%s' "$manager"
            return 0
        fi
    done
    return 1
}

# Homebrew refuses to run as root and breaks itself if forced; everything else
# needs root when we are not already it.
needs_root() {
    [ "$1" = "brew" ] && return 1
    [ "$(id -u 2>/dev/null || echo 0)" = "0" ] && return 1
    return 0
}

# Prints the privilege prefix, or nothing. MUST always return 0: this runs
# inside the command substitution that builds the install command, and under
# `set -e` a non-zero return here aborts that substitution, yielding an empty
# command that then "succeeds".
sudo_prefix() {
    if needs_root "$1" && command -v sudo >/dev/null 2>&1; then
        printf 'sudo '
    fi
    return 0
}

# The packages that carry `venv`, `ensurepip` and `pip` for a given manager.
# On Debian the venv module ships in a version-specific package keyed to the
# interpreter we actually picked, so python3.12-venv is tried before the
# python3-venv metapackage, which tracks the *system* python and may be a
# different one entirely.
venv_packages() {
    case "$1" in
        apt-get) printf 'python%s-venv python3-pip' "$(printf '%s' "$PY_VERSION" | cut -d. -f1,2)" ;;
        dnf|yum)  printf 'python3-pip' ;;
        pacman)   printf 'python-pip' ;;
        zypper)   printf 'python3-pip' ;;
        apk)      printf 'py3-pip' ;;
        brew)     printf 'python@%s' "$(printf '%s' "$PY_VERSION" | cut -d. -f1,2)" ;;
    esac
}

python_packages() {
    case "$1" in
        apt-get) printf 'python3 python3-venv python3-pip' ;;
        dnf|yum)  printf 'python3 python3-pip' ;;
        pacman)   printf 'python python-pip' ;;
        zypper)   printf 'python3 python3-pip' ;;
        apk)      printf 'python3 py3-pip' ;;
        brew)     printf 'python@3.12' ;;
    esac
}

# One string, shown to the user and then executed verbatim. Building the
# displayed command and the executed command separately would mean the consent
# prompt could describe something other than what runs.
install_command() {
    manager=$1
    shift
    prefix=$(sudo_prefix "$manager")
    case "$manager" in
        # A stale index is the usual reason an otherwise-correct apt install
        # fails, and it fails as though the package does not exist.
        apt-get) printf '%sapt-get update && %sapt-get install -y %s' "$prefix" "$prefix" "$*" ;;
        dnf)     printf '%sdnf install -y %s' "$prefix" "$*" ;;
        yum)     printf '%syum install -y %s' "$prefix" "$*" ;;
        pacman)  printf '%spacman -S --noconfirm %s' "$prefix" "$*" ;;
        zypper)  printf '%szypper install -y %s' "$prefix" "$*" ;;
        apk)     printf '%sapk add %s' "$prefix" "$*" ;;
        brew)    printf 'brew install %s' "$*" ;;
    esac
}

# Ask, then install.
#   0  installed
#   1  the command ran and failed — a caller may try a different package name
#   2  nothing was attempted (declined, no terminal, --no-install-deps, or no
#      package manager) — a caller must NOT ask again with another name
offer_install() {
    what=$1
    packages=$2

    if [ "$INSTALL_DEPS" -eq 0 ]; then
        note "--no-install-deps given, so not offering to install $what"
        return 2
    fi

    manager=$(detect_package_manager) || {
        warn "no supported package manager found (looked for apt-get, dnf, yum, pacman, zypper, apk, brew)"
        return 2
    }

    if needs_root "$manager" && ! command -v sudo >/dev/null 2>&1; then
        warn "installing $what needs root, but sudo is not available here"
        note "run this script as root, or install $packages yourself"
        return 2
    fi

    # shellcheck disable=SC2086 -- splitting $packages into words is intended
    cmd=$(install_command "$manager" $packages)
    if [ -z "$cmd" ]; then
        # Belt and braces: an empty string handed to `sh -c` exits 0, which
        # would report a successful install that never happened.
        warn "could not work out an install command for $manager"
        return 2
    fi
    printf '\n  %s can be installed with:\n\n      %s%s%s\n' \
        "$what" "$BOLD" "$cmd" "$OFF"
    case "$cmd" in
        sudo*) note "this needs root, so sudo will prompt for your password" ;;
    esac

    confirm "Run it now?" && answer=0 || answer=$?
    if [ "$answer" -eq 2 ]; then
        warn "no terminal to ask on — nothing was installed"
        note "re-run with --yes to install without being asked"
        return 2
    fi
    if [ "$answer" -ne 0 ]; then
        warn "declined — nothing was installed"
        return 2
    fi

    printf '\n'
    if ! sh -c "$cmd"; then
        warn "that command failed"
        return 1
    fi
    ok "installed $packages"
    return 0
}

# ----------------------------------------------------------------- arguments

while [ $# -gt 0 ]; do
    case "$1" in
        --venv)     VENV_DIR="${2:?--venv needs a directory}"; shift 2 ;;
        --no-venv)  USE_VENV=0; shift ;;
        --dev)      DEV=1; shift ;;
        --check)    CHECK_ONLY=1; shift ;;
        -y|--yes)   ASSUME_YES=1; shift ;;
        --no-install-deps) INSTALL_DEPS=0; shift ;;
        --python)   PY="${2:?--python needs a path}"; shift 2 ;;
        -h|--help)  usage ;;
        *)          die "unknown option: $1" "run ./install.sh --help" ;;
    esac
done

# Run from the repository root whatever directory the user invoked us from.
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR"

case "$(uname -s 2>/dev/null || echo unknown)" in
    MINGW*|MSYS*|CYGWIN*) BIN=Scripts; WINDOWS=1 ;;
    *)                    BIN=bin;     WINDOWS=0 ;;
esac

printf '%sllm-testsuite installer%s\n' "$BOLD" "$OFF"
[ "$CHECK_ONLY" -eq 1 ] && note "check only — nothing will be installed"

# ------------------------------------------------------------------- the repo

step "Repository"
if [ ! -f pyproject.toml ] || ! grep -q 'name = "llm-testsuite"' pyproject.toml; then
    die "this script must live in the llm-testsuite checkout" \
        "expected $SCRIPT_DIR/pyproject.toml to be llm-testsuite's" \
        "" \
        "  git clone https://github.com/Ridgeway-Solutions/AI_testsuite" \
        "  cd AI_testsuite && ./install.sh"
fi
ok "llm-testsuite checkout at $SCRIPT_DIR"

# ------------------------------------------------------------------- python

step "Python $MIN_MAJOR.$MIN_MINOR or newer"

version_ok() {
    "$1" -c "import sys; sys.exit(0 if sys.version_info >= ($MIN_MAJOR, $MIN_MINOR) else 1)" \
        >/dev/null 2>&1
}

describe() { "$1" -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])' 2>/dev/null; }

if [ -n "$PY" ]; then
    command -v "$PY" >/dev/null 2>&1 || die "no such interpreter: $PY"
    version_ok "$PY" || die \
        "$PY is $(describe "$PY"), but $MIN_MAJOR.$MIN_MINOR or newer is required"
else
    # Newest first: a box with both 3.9 and 3.12 should get 3.12, and `python3`
    # alone is not enough to tell.
    for candidate in python3.14 python3.13 python3.12 python3.11 python3.10 python3 python; do
        command -v "$candidate" >/dev/null 2>&1 || continue
        if version_ok "$candidate"; then PY="$candidate"; break; fi
        [ -z "${FOUND_OLD:-}" ] && FOUND_OLD="$candidate $(describe "$candidate")"
    done
fi

if [ -z "$PY" ]; then
    if [ -n "${FOUND_OLD:-}" ]; then
        bad "found $FOUND_OLD — too old"
    else
        bad "no python interpreter found"
    fi
    manager=$(detect_package_manager 2>/dev/null || true)
    if [ -n "$manager" ] && offer_install "Python $MIN_MAJOR.$MIN_MINOR+" "$(python_packages "$manager")"; then
        # Re-run the same search rather than assuming a name for what landed.
        for candidate in python3.14 python3.13 python3.12 python3.11 python3.10 python3 python; do
            command -v "$candidate" >/dev/null 2>&1 || continue
            if version_ok "$candidate"; then PY="$candidate"; break; fi
        done
    fi
fi

if [ -z "$PY" ]; then
    die "Python $MIN_MAJOR.$MIN_MINOR+ is required" \
        "Install it, then re-run this script:" \
        "" \
        "  macOS          brew install python@3.12" \
        "  Debian/Ubuntu  sudo apt install python3 python3-venv python3-pip" \
        "  Fedora/RHEL    sudo dnf install python3 python3-pip" \
        "  Arch           sudo pacman -S python python-pip" \
        "  anywhere       https://www.python.org/downloads/"
fi
PY_VERSION=$(describe "$PY")
ok "$PY ($PY_VERSION) at $(command -v "$PY")"

# ------------------------------------------------------- venv and pip modules

step "Installer prerequisites"

MISSING=""
if [ "$USE_VENV" -eq 1 ]; then
    if "$PY" -c 'import venv' >/dev/null 2>&1; then
        ok "venv module"
    else
        bad "venv module (python3-venv is packaged separately on Debian/Ubuntu)"
        MISSING="$MISSING venv"
    fi
    # Debian ships venv without ensurepip, so `python -m venv` fails only at
    # the point it tries to seed pip — catch it here with a usable message.
    if "$PY" -c 'import ensurepip' >/dev/null 2>&1; then
        ok "ensurepip"
    else
        bad "ensurepip (same Debian/Ubuntu package)"
        MISSING="$MISSING ensurepip"
    fi
else
    if "$PY" -m pip --version >/dev/null 2>&1; then
        ok "pip ($("$PY" -m pip --version 2>/dev/null | cut -d' ' -f2))"
    else
        bad "pip"
        MISSING="$MISSING pip"
    fi
fi

if [ -n "$MISSING" ]; then
    manager=$(detect_package_manager 2>/dev/null || true)
    packages=$(venv_packages "$manager")
    installed=0
    if [ -n "$packages" ]; then
        offer_install "The missing module(s)$MISSING" "$packages" && outcome=0 || outcome=$?
        if [ "$outcome" -eq 0 ]; then
            installed=1
        elif [ "$outcome" -eq 1 ] && [ "$manager" = "apt-get" ]; then
            # The version-specific name does not exist for every interpreter
            # (a pyenv or deadsnakes build). Only worth a second ask when the
            # first command actually ran and failed — never when the user
            # already said no, or there was nobody to ask.
            note "trying the python3-venv metapackage instead"
            offer_install "The missing module(s)$MISSING" "python3-venv python3-pip" && installed=1
        fi
    fi

    if [ "$installed" -eq 1 ]; then
        # Trust the re-check, not the package manager's exit code: on Debian
        # the wrong -venv package installs cleanly and changes nothing.
        STILL=""
        if [ "$USE_VENV" -eq 1 ]; then
            "$PY" -c 'import venv' >/dev/null 2>&1 || STILL="$STILL venv"
            "$PY" -c 'import ensurepip' >/dev/null 2>&1 || STILL="$STILL ensurepip"
        else
            "$PY" -m pip --version >/dev/null 2>&1 || STILL="$STILL pip"
        fi
        if [ -n "$STILL" ]; then
            die "still missing after installing:$STILL" \
                "The package installed but $PY still cannot import it, which" \
                "usually means this interpreter came from somewhere the system" \
                "packages do not cover (pyenv, deadsnakes, a manual build)." \
                "Try another interpreter:  ./install.sh --python python3"
        fi
        ok "resolved:$MISSING"
        MISSING=""
    else
        die "missing:$MISSING" \
            "Install the package that provides it, then re-run ./install.sh:" \
            "" \
            "  Debian/Ubuntu  sudo apt install python3-venv python3-pip" \
            "  Fedora/RHEL    sudo dnf install python3-pip" \
            "  Arch           sudo pacman -S python-pip" \
            "  Alpine         sudo apk add py3-pip"
    fi
fi

# curses is stdlib everywhere except Windows, where it is a pip package. Only
# the terminal UI needs it; `llmtest run` works fine without.
if "$PY" -c 'import curses' >/dev/null 2>&1; then
    ok "curses (terminal UI available)"
    CURSES=1
else
    CURSES=0
    if [ "$WINDOWS" -eq 1 ]; then
        warn "curses missing — will install windows-curses for the terminal UI"
    else
        warn "curses missing — 'llmtest tui' will be unavailable, 'llmtest run' still works"
    fi
fi

# ------------------------------------------------------------------ check mode

if [ "$CHECK_ONLY" -eq 1 ]; then
    step "Already installed?"
    if "$PY" -c 'import llmtest' >/dev/null 2>&1; then
        ok "llmtest importable by $PY"
    else
        warn "llmtest not installed for $PY"
    fi
    if "$PY" -c 'import yaml' >/dev/null 2>&1; then
        ok "PyYAML"
    else
        warn "PyYAML not installed (pip will fetch it)"
    fi
    printf '\n%sEverything above is a report only — nothing was changed.%s\n' "$DIM" "$OFF"
    printf 'Run %s./install.sh%s to install.\n' "$BOLD" "$OFF"
    exit 0
fi

# ------------------------------------------------------------------ the venv

if [ "$USE_VENV" -eq 1 ]; then
    step "Virtual environment"
    if [ -d "$VENV_DIR" ] && [ -x "$VENV_DIR/$BIN/python" ]; then
        ok "reusing $VENV_DIR"
    else
        # A half-built venv from an interrupted run is worse than none: it has
        # the layout but no interpreter, and every later step fails obscurely.
        # Only ever delete something that is provably a venv — pyvenv.cfg is
        # the marker — so a mistyped --venv cannot turn this into an rm -rf of
        # someone's home directory.
        if [ -d "$VENV_DIR" ]; then
            if [ -f "$VENV_DIR/pyvenv.cfg" ]; then
                rm -rf "$VENV_DIR"
                note "removed an incomplete $VENV_DIR"
            elif [ -n "$(ls -A "$VENV_DIR" 2>/dev/null)" ]; then
                die "$VENV_DIR already exists and is not a virtual environment" \
                    "Refusing to delete it. Pick another location:" \
                    "  ./install.sh --venv some-other-dir"
            fi
        fi
        "$PY" -m venv "$VENV_DIR" || die \
            "could not create a virtual environment in $VENV_DIR" \
            "Try: sudo apt install python3-venv   (Debian/Ubuntu)"
        ok "created $VENV_DIR"
    fi
    VPY="$VENV_DIR/$BIN/python"
    note "a venv keeps this off your system Python, which is also what avoids"
    note "the 'externally-managed-environment' error on newer distros and macOS"
else
    VPY="$PY"
    step "Target environment"
    warn "installing into $(command -v "$PY") directly (--no-venv)"
    note "if this fails with 'externally-managed-environment', drop --no-venv"
fi

# ------------------------------------------------------------------ install

step "Dependencies"
note "pip installs only what is missing or outdated; this is safe to re-run"

"$VPY" -m pip install --quiet --upgrade pip >/dev/null 2>&1 \
    && ok "pip up to date" \
    || warn "could not upgrade pip — continuing with the version present"

TARGET="."
[ "$DEV" -eq 1 ] && TARGET=".[dev]"

if ! "$VPY" -m pip install --editable "$TARGET"; then
    die "pip could not install llm-testsuite" \
        "If the error mentions 'externally-managed-environment', re-run without" \
        "--no-venv so the install goes into $VENV_DIR instead." \
        "If it mentions a network or TLS failure, pip needs to reach PyPI to" \
        "fetch PyYAML."
fi
ok "llm-testsuite installed (editable — your edits take effect immediately)"
[ "$DEV" -eq 1 ] && ok "test dependencies installed"

if [ "$WINDOWS" -eq 1 ] && [ "$CURSES" -eq 0 ]; then
    if "$VPY" -m pip install --quiet windows-curses; then
        ok "windows-curses installed (terminal UI available)"
        CURSES=1
    else
        warn "windows-curses failed to install — 'llmtest tui' will be unavailable"
    fi
fi

# ------------------------------------------------------------------ verify

step "Verifying"
LLMTEST="$VENV_DIR/$BIN/llmtest"
[ "$USE_VENV" -eq 1 ] || LLMTEST=$(command -v llmtest 2>/dev/null || echo "$VPY -m llmtest")

"$VPY" -c 'import yaml' >/dev/null 2>&1 && ok "PyYAML importable" \
    || die "PyYAML did not install"

VERSION=$("$VPY" -m llmtest --version 2>&1) || die \
    "the llmtest command did not run" "output: $VERSION"
ok "$VERSION"

if "$VPY" -c 'import curses' >/dev/null 2>&1; then
    ok "curses importable — 'llmtest tui' will work"
else
    warn "no curses — use 'llmtest run'; the terminal UI needs it"
fi

# The real proof: load the plugin registry, build a target and plan a suite.
# `plan` sends nothing, so this is safe and offline.
if "$VPY" -m llmtest plan suites/quick.yaml >/dev/null 2>&1; then
    ok "end-to-end check passed (registry, target and suite all load)"
else
    die "llmtest installed but could not plan the bundled suite" \
        "Run this to see why:" "  $VPY -m llmtest plan suites/quick.yaml"
fi

# ------------------------------------------------------------------ next steps

printf '\n%sDone.%s\n\n' "$GREEN$BOLD" "$OFF"

if [ "$USE_VENV" -eq 1 ]; then
    if [ "$WINDOWS" -eq 1 ]; then
        ACTIVATE="$VENV_DIR/Scripts/activate"
    else
        ACTIVATE=". $VENV_DIR/bin/activate"
    fi
    printf 'Activate the environment:\n\n    %s%s%s\n\n' "$BOLD" "$ACTIVATE" "$OFF"
    printf 'Then start it:\n\n'
else
    printf 'Start it:\n\n'
fi

if [ "$CURSES" -eq 1 ]; then
    printf '    %sllmtest tui%s\n\n' "$BOLD" "$OFF"
    printf 'then point it at your own endpoint from inside it:\n\n'
    printf '    %s:target https://your-app.example/api/chat%s\n' "$BOLD" "$OFF"
    printf '    %s:response-path data.reply%s   where the reply sits in the JSON\n' "$BOLD" "$OFF"
    printf '    %s:test%s                       one benign request, to prove it answers\n' "$BOLD" "$OFF"
    printf '    %s:run%s                        %s:help lists the rest%s\n\n' \
        "$BOLD" "$OFF" "$DIM" "$OFF"
    printf 'Or without activating anything:  %s%s tui%s\n\n' "$DIM" "$LLMTEST" "$OFF"
else
    printf '    %sllmtest run --target-type http --url https://your-app.example/api/chat%s\n' \
        "$BOLD" "$OFF"
    printf '    %sllmtest --help%s\n\n' "$BOLD" "$OFF"
fi
printf '%sThe shipped suites (suites/quick.yaml and friends) aim at a built-in\n' "$DIM"
printf 'offline mock: they prove this works and nothing about your system.\n'
printf 'Only run against a real system you own or have written permission to\n'
printf 'test — see docs/ETHICS.md.%s\n' "$OFF"
