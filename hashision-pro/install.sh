#!/usr/bin/env bash
#
# Hashision Pro - installer for Kali Linux / Debian
#
# Usage:
#   chmod +x install.sh
#   ./install.sh
#
# The tool uses only the Python 3 standard library, so this script mainly
# checks the environment, creates the working directories, makes the entry
# point executable and runs the test suite.

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
MIN_MINOR=8

green() { printf '\033[32m%s\033[0m\n' "$1"; }
yellow() { printf '\033[33m%s\033[0m\n' "$1"; }
red() { printf '\033[31m%s\033[0m\n' "$1"; }
step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }

step "Hashision Pro - installation"
echo "Project directory: ${PROJECT_DIR}"

# --------------------------------------------------------------------------
# 1. Check Python 3
# --------------------------------------------------------------------------
step "Checking for Python 3"
if ! command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
    red "python3 was not found."
    echo "Install it with:"
    echo "  sudo apt update && sudo apt install python3 -y"
    exit 1
fi

PY_VERSION="$("${PYTHON_BIN}" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
PY_MAJOR="${PY_VERSION%%.*}"
PY_MINOR="${PY_VERSION##*.}"

if [ "${PY_MAJOR}" -lt 3 ] || { [ "${PY_MAJOR}" -eq 3 ] && [ "${PY_MINOR}" -lt "${MIN_MINOR}" ]; }; then
    red "Python 3.${MIN_MINOR}+ is required, found ${PY_VERSION}."
    exit 1
fi
green "Found Python ${PY_VERSION} ($(command -v "${PYTHON_BIN}"))"

# --------------------------------------------------------------------------
# 2. Dependencies
# --------------------------------------------------------------------------
step "Checking dependencies"
echo "This tool uses the Python 3 standard library only:"
echo "  hashlib, argparse, dataclasses, statistics, csv, json, random, time"
if [ -f "${PROJECT_DIR}/requirements.txt" ]; then
    if grep -qvE '^\s*(#|$)' "${PROJECT_DIR}/requirements.txt"; then
        yellow "requirements.txt lists packages - installing them."
        "${PYTHON_BIN}" -m pip install -r "${PROJECT_DIR}/requirements.txt"
    else
        green "No third-party packages required."
    fi
fi

# --------------------------------------------------------------------------
# 3. Directories
# --------------------------------------------------------------------------
step "Creating working directories"
mkdir -p "${PROJECT_DIR}/reports" "${PROJECT_DIR}/samples"
green "reports/ and samples/ are ready."

# --------------------------------------------------------------------------
# 4. Sample files
# --------------------------------------------------------------------------
step "Creating sample files"
if [ ! -f "${PROJECT_DIR}/samples/sample1.txt" ]; then
    printf 'hello' > "${PROJECT_DIR}/samples/sample1.txt"
fi
if [ ! -f "${PROJECT_DIR}/samples/sample2.txt" ]; then
    printf 'world' > "${PROJECT_DIR}/samples/sample2.txt"
fi
if [ ! -f "${PROJECT_DIR}/samples/sample1_copy.txt" ]; then
    printf 'hello' > "${PROJECT_DIR}/samples/sample1_copy.txt"
fi
green "samples/sample1.txt, samples/sample2.txt, samples/sample1_copy.txt"

# --------------------------------------------------------------------------
# 5. Permissions
# --------------------------------------------------------------------------
step "Setting permissions"
chmod +x "${PROJECT_DIR}/collision_analyzer.py"
green "collision_analyzer.py is executable."

# --------------------------------------------------------------------------
# 6. Tests
# --------------------------------------------------------------------------
step "Running the test suite"
if (cd "${PROJECT_DIR}" && "${PYTHON_BIN}" -m unittest discover -s tests -q); then
    green "All tests passed."
else
    red "Tests failed. The tool may still run, but please review the output above."
    exit 1
fi

# --------------------------------------------------------------------------
# 7. Optional: a launcher on PATH
# --------------------------------------------------------------------------
step "Optional launcher"
echo "To call the tool from anywhere, add an alias to ~/.bashrc or ~/.zshrc:"
echo "  alias hashision='${PYTHON_BIN} ${PROJECT_DIR}/collision_analyzer.py'"

step "Installation complete"
cat <<EOF
Try it now:

  ${PYTHON_BIN} collision_analyzer.py --help
  ${PYTHON_BIN} collision_analyzer.py algorithms
  ${PYTHON_BIN} collision_analyzer.py hash-text "hello" --algorithm md5
  ${PYTHON_BIN} collision_analyzer.py collision-demo --algorithm sha256 --bits 16
  ${PYTHON_BIN} collision_analyzer.py interactive

Reminder: collision experiments use deliberately TRUNCATED digests.
Full MD5/SHA-1/SHA-256/SHA-512 hashes are never broken by this tool.
EOF
