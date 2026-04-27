#!/bin/bash
# Common test script for all OpenAEV collectors.
# Usage:
#   ./run_test.sh <collector_dir>          Run tests for a single collector
#   ./run_test.sh <dir1> <dir2> ...        Run tests for multiple collectors
#   ./run_test.sh                           Auto-discover and run all collector tests
#
# Environment variables:
#   RELEASE_REF       Base branch for git diff (default: main)
#   GITHUB_REF_NAME   Current branch name (GitHub Actions)
#   CIRCLE_BRANCH     Current branch name (CircleCI)

set -e

RELEASE_REF="${RELEASE_REF:-main}"
BRANCH="${CIRCLE_BRANCH:-${GITHUB_REF_NAME:-$RELEASE_REF}}"
REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"

# Determine pyoaev git branch
if [ "$BRANCH" = "main" ]; then
  PYOAEV_BRANCH="main"
else
  PYOAEV_BRANCH="release/current"
fi

# Discover collectors with test directories
discover_collectors() {
  find "$REPO_ROOT" -maxdepth 2 \( -name "test" -o -name "tests" \) -type d \
    | sed "s|^$REPO_ROOT/||; s|/test.*||" \
    | sort -u
}

# Detect install arguments for a collector's pyproject.toml
get_install_args() {
  local pyproject="$1/pyproject.toml"
  local args="--extras prod"

  if grep -q '\[tool\.poetry\.group\.test' "$pyproject" 2>/dev/null; then
    args="$args --with test"
  elif grep -q '\[tool\.poetry\.group\.dev' "$pyproject" 2>/dev/null; then
    # microsoft-defender has pytest in dev group
    if sed -n '/\[tool\.poetry\.group\.dev/,/\[/p' "$pyproject" | grep -q 'pytest'; then
      args="$args --with dev"
    fi
  fi

  echo "$args"
}

# Detect whether the collector uses pytest or unittest
uses_pytest() {
  local collector_dir="$1"
  local pyproject="$collector_dir/pyproject.toml"

  # Check for pytest configuration in pyproject.toml
  if grep -q '\[tool\.pytest' "$pyproject" 2>/dev/null; then
    return 0
  fi

  # Check for conftest.py (pytest convention)
  if [ -f "$collector_dir/tests/conftest.py" ] || [ -f "$collector_dir/test/conftest.py" ]; then
    return 0
  fi

  # Check if pytest is in any dependency group
  if grep -q 'pytest' "$pyproject" 2>/dev/null; then
    return 0
  fi

  return 1
}

# Run tests for a single collector
run_collector_tests() {
  local collector="$1"
  local collector_dir="$REPO_ROOT/$collector"

  echo "==========================================="
  echo "Processing: $collector"
  echo "==========================================="

  echo "🔄 Running tests for $collector"

  cd "$collector_dir"

  # Ensure Poetry is available
  command -v poetry >/dev/null 2>&1 || pip install -q poetry==2.1.3
  poetry config installer.re-resolve false 2>/dev/null || true

  # Install collector dependencies
  local install_args
  install_args=$(get_install_args "$collector_dir")
  echo "→ poetry install $install_args"
  poetry install $install_args

  # Force-reinstall pyoaev from git (correct branch)
  echo "→ Installing pyoaev from branch $PYOAEV_BRANCH"
  poetry run pip install --force-reinstall -q \
    "git+https://github.com/OpenAEV-Platform/client-python.git@$PYOAEV_BRANCH"

  # Install coverage tooling
  poetry run pip install -q coverage

  # Detect test directory
  local test_dir=""
  if [ -d "test" ]; then
    test_dir="test"
  elif [ -d "tests" ]; then
    test_dir="tests"
  fi

  # Run tests with the appropriate framework, capturing exit code explicitly
  # (set -e is disabled inside `if !` so we must not rely on it here)
  local test_rc=0
  if uses_pytest "$collector_dir"; then
    echo "→ Running pytest"
    poetry run python -m coverage run -m pytest -q -rA || test_rc=$?
  else
    echo "→ Running unittest"
    poetry run python -m coverage run -m unittest discover -s "$test_dir" -v || test_rc=$?
  fi

  # Generate coverage report even on failure (partial coverage is still useful)
  poetry run python -m coverage xml -o coverage.xml || true

  cd "$REPO_ROOT"
  return $test_rc
}

# --- Main ---

if [ $# -gt 0 ]; then
  collectors="$*"
else
  collectors=$(discover_collectors)
fi

exit_code=0
for collector in $collectors; do
  if run_collector_tests "$collector"; then
    echo "✅ $collector tests passed"
  else
    echo "❌ $collector tests FAILED"
    exit_code=1
  fi
done

exit $exit_code
