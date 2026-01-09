# GitHub Copilot Instructions for OpenAEV Collectors

## Repository Overview

This repository contains **OpenAEV collectors** - Python-based integrations that interface with security tools (EDR, XDR, SIEM, etc.) to collect security data and alerts for the OpenAEV platform. The repository is a **monorepo** containing 15 individual collectors, each with its own Python package.

**Key Facts:**
- **Language**: Python 3.11+ (CI uses Python 3.13)
- **Package Manager**: Poetry 2.1.3+
- **Size**: Medium-sized monorepo with 15 collectors
- **CI/CD**: CircleCI (`.circleci/config.yml`)
- **License**: Apache 2.0

**Collectors in this repository:**
- atomic-red-team, aws-resources, crowdstrike, google-workspace, microsoft-azure, microsoft-defender, microsoft-entra, microsoft-intune, microsoft-sentinel, mitre-attack, nvd-nist-cve, openaev, sentinelone, splunk-es, tanium-threat-response

## Critical Build Requirements

### Poetry and Dependency Management

**IMPORTANT**: This repository uses **"mutually exclusive extra markers"** for the `pyoaev` dependency. Read the [Poetry documentation on exclusive extras](https://python-poetry.org/docs/dependency-specification/#exclusive-extras) before making dependency changes.

**Two installation modes:**
1. **Production mode**: Uses `pyoaev` from PyPI
   ```bash
   poetry install --extras prod
   ```

2. **Development mode**: Uses local `pyoaev` from `../client-python` directory
   ```bash
   poetry install --extras dev
   ```

**Expected directory structure for development:**
```
/home/runner/work/
├── client-python/       # pyoaev library (must be cloned separately)
└── collectors/          # This repository
    ├── crowdstrike/
    ├── mitre-attack/
    └── ...
```

**NEVER** try to install both `dev` and `prod` extras simultaneously - they are mutually exclusive.

### Installing Dependencies

**For the entire repository** (all collectors at once):
```bash
cd /path/to/collectors
poetry install --extras dev  # For development with local pyoaev
```

**For a single collector**:
```bash
cd /path/to/collectors/crowdstrike
poetry install --extras prod  # Uses PyPI version
```

**Common installation issue**: If you see `Path /home/runner/work/collectors/client-python for pyoaev does not exist`, you are in dev mode but `client-python` is not cloned at the expected location. Either:
- Clone `client-python` to the correct location, OR
- Use `--extras prod` instead

## Code Quality and Linting

### Pre-commit Checks

The CI runs three quality checks that **MUST pass**:

1. **isort** - Import sorting (with black profile)
2. **black** - Code formatting  
3. **flake8** - Linting (with specific ignore rules)

### Running Linters Locally

**ALWAYS run these commands before committing:**

```bash
# Install linting tools
pip install black isort flake8

# Run isort check
isort --profile black --check .

# Run black check  
black --check .

# Run flake8
flake8 --ignore=E,W .
```

**To auto-fix formatting issues:**
```bash
isort --profile black .
black .
```

### Linter Configuration

- **black**: No custom config, uses defaults
- **isort**: Must use `--profile black` to match black's style
- **flake8**: Config in `.flake8`:
  - Ignores: E203, E266, E501, W503, F403, F401
  - Max line length: 120
  - Selects: B,C,E,F,W,T4,B9 (enables specific checker categories)

**IMPORTANT**: The CircleCI `linter` job ignores all E and W errors with `--ignore=E,W`. Do NOT change this without testing on CI.

## Testing

### Test Structure

Not all collectors have tests. Collectors with tests:
- **crowdstrike**: `test/` directory, uses unittest
- **sentinelone**: `tests/` directory  
- **splunk-es**: `tests/` directory
- **nvd-nist-cve**: `tests/` directory

### Running Tests

**For crowdstrike collector (example from CI)**:
```bash
cd crowdstrike
poetry install --extras prod
poetry run pip install --force-reinstall git+https://github.com/OpenAEV-Platform/client-python.git@main
poetry run python -m unittest
```

**Key points:**
- Tests use Python's built-in `unittest` framework
- CI overrides the pyoaev dependency with the latest from git after installation
- Tests expect pyoaev to be available in the environment

## CI/CD Pipeline (CircleCI)

### Workflow Jobs

The CI pipeline runs the following jobs **in order**:

1. **ensure_formatting** - Checks code formatting with black and isort
2. **linter** - Runs flake8 
3. **test** - Runs tests for crowdstrike collector (only collector with CI tests currently)
4. **build_docker_images** - Builds Docker images for all collectors
5. **publish_images** - Publishes images to Docker Hub (on main/release/tags)

**All three quality checks (formatting, isort, linter) MUST pass before builds run.**

### Docker Builds

Each collector has a `Dockerfile` that:
- Uses `python:3.13-alpine` base image
- Installs Poetry 2.1.3
- Builds the collector as a wheel
- Installs the wheel with `[prod]` extras
- Optionally overrides pyoaev version with `PYOAEV_GIT_BRANCH_OVERRIDE` build arg

**Build command pattern**:
```bash
cd <collector-directory>
docker build -t openaev/collector-<name>:tag .
```

### Branch Strategy

- **main**: Development branch, publishes "rolling" Docker tag
- **release/current**: Pre-release branch, publishes "prerelease" Docker tag  
- **tags (vX.Y.Z)**: Release tags, publishes version tag

## Collector Architecture

### Standard Collector Structure

Each collector directory contains:
```
collector-name/
├── collector_name/          # Python package
│   ├── __init__.py
│   ├── openaev_<name>.py   # Main entry point
│   └── ...
├── test/ or tests/          # Tests (if present)
├── Dockerfile              # Docker build
├── docker-compose.yml      # Local deployment
├── .env.sample            # Environment variable template
├── pyproject.toml         # Poetry config
└── README.md              # Collector documentation
```

### Running a Collector

**Via Poetry**:
```bash
cd <collector-name>
poetry install --extras prod
poetry run python -m <collector_name>.openaev_<collector_name>
```

**Via Docker**:
```bash
cd <collector-name>
docker build -t collector .
docker compose up -d
```

## Common Configuration

All collectors share these environment variables:
- `OPENAEV_URL` - OpenAEV platform URL
- `OPENAEV_TOKEN` - Platform authentication token
- `COLLECTOR_ID` - Unique UUID for the collector instance
- `COLLECTOR_NAME` - Human-readable name
- `COLLECTOR_PERIOD` - Collection interval in seconds (default: 60)
- `COLLECTOR_LOG_LEVEL` - Logging verbosity (debug/info/warn/error)
- `COLLECTOR_PLATFORM` - Security platform type (EDR/XDR/SIEM/SOAR/NDR/ISPM)

Each collector also has its own specific configuration variables (API keys, URLs, etc.).

## Making Changes

### Modifying a Collector

1. Make code changes in the collector's package directory
2. **ALWAYS run linters**: `black .`, `isort --profile black .`, `flake8 --ignore=E,W .`
3. If tests exist, run them: `poetry run python -m unittest`
4. Test the collector locally if possible
5. Commit with clear messages

### Adding a New Collector

Use Poetry to create the skeleton:
```bash
poetry new new_collector
cd new_collector
# Edit pyproject.toml to add pyoaev dependency with mutually exclusive markers
```

See README.md "Creating a new collector" section for the exact `pyproject.toml` format.

### Updating Dependencies

**For security updates**: Use `renovate.json` configuration (automated via Renovate bot)

**Manual updates**:
```bash
cd <collector-directory>
poetry update <package-name>
```

**NEVER modify the pyoaev dependency structure** (the mutually exclusive extras) without consulting the team.

## Troubleshooting

### "Path for pyoaev does not exist"
- You're in dev mode but `client-python` is not at `../client-python`
- Solution: Clone `client-python` or use `--extras prod`

### Import errors when running tests
- pyoaev is not installed
- Solution: Run `poetry install --extras prod` first

### Black/isort conflicts
- Solution: Always use `isort --profile black` to match black's style

### Docker build fails on "pip3 install"
- Check that Poetry 2.1.3 is used in the Dockerfile
- Verify `poetry build` succeeds before pip install

### CI formatting check fails
- Run `black --check .` and `isort --profile black --check .` locally
- Fix with `black .` and `isort --profile black .`

## Key Files Reference

### Repository Root
- `pyproject.toml` - Root Poetry config, installs all collectors
- `.circleci/config.yml` - CI/CD pipeline definition
- `.pre-commit-config.yaml` - Pre-commit hooks (black, flake8, isort)
- `.flake8` - Flake8 configuration
- `scripts/release.py` - Release automation script
- `renovate.json` - Automated dependency updates

### Per-Collector Files
- `pyproject.toml` - Collector dependencies and metadata
- `Dockerfile` - Docker build instructions
- `docker-compose.yml` - Local deployment config
- `.env.sample` - Required environment variables
- `README.md` - Collector-specific documentation

## Best Practices

1. **ALWAYS run linters before committing** - CI will fail otherwise
2. **Use the correct poetry extras** - dev for local development with client-python, prod otherwise
3. **Test locally when possible** - Run collectors against test instances
4. **Follow existing patterns** - Look at similar collectors for examples
5. **Document configuration** - Update READMEs when adding new config options
6. **Use semantic versions** - Follow existing version patterns (X.Y.Z)
7. **Keep dependencies up to date** - Review Renovate PRs promptly

## Instructions Priority

**TRUST THESE INSTRUCTIONS**. Only search for additional information if:
- The instructions are incomplete for your specific task
- You encounter an error not documented here
- You need to understand implementation details not covered here

These instructions are comprehensive and tested. Following them will minimize build failures and CI rejections.
