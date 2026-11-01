# Common base stage for shared environment configuration.
FROM python:3.14-alpine AS base

# brotli-libs: the system Brotli that Pillow's FreeType loads (see the builder stage).
RUN apk --no-cache upgrade && \
    apk add --no-cache brotli-libs

# Python runtime and Poetry build configuration.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/collector/.venv/bin:$PATH"

WORKDIR /collector

# Builder stage for installing dependencies and creating the application environment.
FROM base AS builder

ENV POETRY_VERSION=2.3.2 \
    POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_CREATE=true \
    POETRY_VIRTUALENVS_IN_PROJECT=true

# Allows overriding the client-python source version.
ARG PYOAEV_GIT_REF_OVERRIDE=""

# Build dependencies required.
RUN apk add --no-cache --virtual .build-deps \
    build-base \
    libffi-dev \
    openssl-dev \
    git

# Poetry is required only during build and is intentionally excluded from the runtime image.
RUN pip install --no-cache-dir "poetry==$POETRY_VERSION"

# Copy only dependency metadata first.
COPY pyproject.toml ./

# Cache package downloads to speed up subsequent builds.
# Install production dependencies into the virtual environment.
RUN --mount=type=cache,target=/root/.cache \
    poetry install  \
    --only main  \
    --no-root

# Optional override of the client-python dependency.
# Useful for testing a specific branch or tag.
# Example: --build-arg PYOAEV_GIT_REF_OVERRIDE=2.260703.0
RUN if [ "$PYOAEV_GIT_REF_OVERRIDE" ]; then \
      echo "Forcing specific version ($PYOAEV_GIT_REF_OVERRIDE) of client-python" && \
      pip install --no-cache-dir --force-reinstall \
      "git+https://github.com/OpenAEV-Platform/client-python.git@$PYOAEV_GIT_REF_OVERRIDE"; \
    fi

# The Pillow wheels bundle Brotli 1.2.0 (CVE-2026-111497) for FreeType: replace
# the bundled libbrotlidec with a link to the system one (brotli-libs, fixed) and
# remove the bundled libbrotlicommon, which only it loads (#643). The link keeps
# the bundled name (libbrotlidec-<hash>.so.1.2.0), the one FreeType loads, but
# resolves to the system version.
RUN cd /collector/.venv/lib/python3*/site-packages/pillow.libs && \
    rm libbrotlicommon-* && \
    ln -sf /usr/lib/libbrotlidec.so.1 libbrotlidec-*

# Runtime stage containing only the application environment required for execution.
FROM base AS runner

# Run the application as a non-root user for better container security.
# Using explicit UIDs/GIDs ensures deterministic ownership during rebuilds (Docker recommendation).
RUN addgroup -g 10001 -S nonroot && \
    adduser -S -D -H -u 10001 -G nonroot nonroot

COPY --chown=nonroot:nonroot README.md ./

# Copy only runtime artifacts from the builder.
# Set file ownership during copy to avoid an additional chown layer.
COPY --from=builder --chown=nonroot:nonroot \
    /collector/.venv /collector/.venv

# Copy application sources after dependencies are installed to maximize build cache reuse.
COPY --chown=nonroot:nonroot ./src /collector/src

USER nonroot

# Run using the isolated Poetry virtual environment.
CMD ["python", "-m", "src"]

