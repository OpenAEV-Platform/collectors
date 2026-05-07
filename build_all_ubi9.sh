#!/bin/sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

PUSH=false
while [ $# -gt 0 ]; do
    case "$1" in
        --push) PUSH=true; shift ;;
        -*) echo "Unknown option: $1" >&2; echo "Usage: $0 [--push] <version>" >&2; exit 1 ;;
        *) break ;;
    esac
done

VERSION="${1:?Usage: $0 [--push] <version>}"

BUILD_ARGS=""
if [ "${PUSH}" = true ]; then
    BUILD_ARGS="--push"
fi

COLLECTORS="
    atomic-red-team
    crowdstrike
    microsoft-defender
    mitre-attack
    openaev
    splunk-es
"

FAILED=""
for collector in ${COLLECTORS}; do
    echo "=========================================="
    echo "Building ${collector}..."
    echo "=========================================="
    if "${SCRIPT_DIR}/build_ubi9.sh" ${BUILD_ARGS} "${collector}" "${VERSION}"; then
        echo "OK: ${collector}"
    else
        echo "FAILED: ${collector}"
        FAILED="${FAILED} ${collector}"
    fi
    echo ""
done

if [ -n "${FAILED}" ]; then
    echo "=========================================="
    echo "The following builds failed:"
    for f in ${FAILED}; do
        echo "  - ${f}"
    done
    echo "=========================================="
    exit 1
fi

echo "All UBI9 builds succeeded."

