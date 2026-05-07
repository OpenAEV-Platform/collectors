#!/bin/sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

usage() {
    echo "Usage: $0 [--push] <collector-dir> <version>" >&2
    echo "  --push         Push the image after building" >&2
    echo "  collector-dir  Path to the collector (e.g. mitre-attack)" >&2
    echo "  version        Image version tag" >&2
    exit 1
}

PUSH=false
if [ "$1" = "--push" ]; then
    PUSH=true
    shift
fi

COLLECTOR_DIR="${1:?$(usage)}"
VERSION="${2:?$(usage)}"

# Resolve and validate
COLLECTOR_DIR="${COLLECTOR_DIR%/}"
if [ ! -d "${COLLECTOR_DIR}" ]; then
    echo "Error: collector directory '${COLLECTOR_DIR}' does not exist." >&2
    exit 1
fi

# Auto-compute COLLECTOR_CMD from directory name
MODULE_NAME=$(echo "${COLLECTOR_DIR}" | tr '-' '_')
COLLECTOR_CMD="${MODULE_NAME}.openaev_${MODULE_NAME}"

IMAGE="openaev/collector-${COLLECTOR_DIR}:${VERSION}-ubi9"
ENV_FILE="${COLLECTOR_DIR}/.build.env"

# Collector-specific overrides from env file (e.g. COLLECTOR_CMD)
if [ -f "${ENV_FILE}" ]; then
    . "${ENV_FILE}"
fi

# Build argument list
set -- -f "${SCRIPT_DIR}/Dockerfile_ubi9"
set -- "$@" --build-arg "COLLECTOR_CMD=${COLLECTOR_CMD}"

# Append remaining collector-specific overrides from env file as --build-arg flags
if [ -f "${ENV_FILE}" ]; then
    eval set -- '"$@"' $(sed '/^$/d; /^#/d; /^COLLECTOR_CMD=/d; s/^/--build-arg /' "${ENV_FILE}")
fi

set -- "$@" -t "${IMAGE}"
set -- "$@" "${COLLECTOR_DIR}"

if command -v podman >/dev/null 2>&1; then
    RUNTIME=podman
else
    RUNTIME=docker
fi

${RUNTIME} build "$@"

if [ "${PUSH}" = true ]; then
    echo "Pushing ${IMAGE}..."
    ${RUNTIME} push "${IMAGE}"
fi
