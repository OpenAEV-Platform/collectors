# GitHub Copilot Instructions for OpenAEV Collectors

## Repository Overview

**OpenAEV collectors** - Python integrations for security tools (EDR, XDR, SIEM, etc.) to collect data for OpenAEV platform. Monorepo with 15 collectors.

**Key Facts:**
- **Language**: Python 3.11+ (CI: Python 3.13)
- **Package Manager**: Poetry 2.1.3+
- **CI/CD**: CircleCI
- **Collectors**: 8 in root pyproject.toml (atomic-red-team, crowdstrike, microsoft-defender, microsoft-entra, microsoft-sentinel, mitre-attack, nvd-nist-cve, tanium-threat-response), 7 standalone (aws-resources, google-workspace, microsoft-azure, microsoft-intune, openaev, sentinelone, splunk-es)

## Critical Build Requirements

### Poetry and Dependency Management

**IMPORTANT**: Uses **mutually exclusive extra markers** for `pyoaev` dependency. Different sources based on extras.

**Installation modes:**
- **Production**: `poetry install --extras prod` (PyPI)
- **Development**: `poetry install --extras dev` (local `../client-python`)

**Expected dev structure:**
```
/home/runner/work/
├── client-python/       # pyoaev library
└── collectors/          # This repo
```

**NEVER** use both `dev` and `prod` extras simultaneously.

**Common issue**: `Path for pyoaev does not exist` - clone `client-python` or use `--extras prod`.

## Code Quality and Linting

**CI requires three checks:**
1. **isort** - Import sorting (with black profile)
2. **black** - Code formatting  
3. **flake8** - Linting

**Run before committing:**
```bash
pip install black isort flake8
isort --profile black --check .
black --check .
flake8 --ignore=E,W .  # Match CI behavior
```

**Auto-fix:** `isort --profile black .` and `black .`

**Config notes:**
- **isort**: Must use `--profile black`
- **flake8**: CI uses `--ignore=E,W` (overrides `.flake8` file)

## Testing

**Collectors with tests:** crowdstrike, sentinelone, splunk-es, nvd-nist-cve

**Run tests (crowdstrike example):**
```bash
cd crowdstrike
poetry install --extras prod
poetry run pip install --force-reinstall git+https://github.com/OpenAEV-Platform/client-python.git@main
poetry run python -m unittest
```

## CI/CD Pipeline (CircleCI)

**Job order:**
1. **ensure_formatting** - black and isort checks
2. **linter** - flake8
3. **test** - crowdstrike collector tests (unittest)
4. **build_docker_images** - All collectors (python:3.13-alpine, Poetry 2.1.3)
5. **publish_images** - Docker Hub (main/release/tags)

**Branch strategy:**
- **main**: Rolling tag
- **release/current**: Prerelease tag
- **tags (vX.Y.Z)**: Version tag

## Collector Architecture

**Standard structure:**
```
collector-name/
├── collector_name/          # Python package
│   └── openaev_<name>.py   # Entry point
├── test/ or tests/          # Tests (unittest)
├── Dockerfile              # python:3.13-alpine, Poetry 2.1.3
├── pyproject.toml         # Dependencies with mutually exclusive extras
└── README.md
```

**Run collector:**
- Poetry: `cd <collector> && poetry install --extras prod && poetry run python -m <collector_name>.openaev_<collector_name>`
- Docker: `cd <collector> && docker build -t collector . && docker compose up -d`

**Common env vars:** `OPENAEV_URL`, `OPENAEV_TOKEN`, `COLLECTOR_ID`, `COLLECTOR_NAME`, `COLLECTOR_PERIOD`, `COLLECTOR_LOG_LEVEL`, `COLLECTOR_PLATFORM`

## Making Changes

**Modify collector:**
1. Make changes in collector's package directory
2. **ALWAYS run linters:** `black .`, `isort --profile black .`, `flake8 --ignore=E,W .`
3. Run tests if they exist: `poetry run python -m unittest`
4. Test locally if possible

**Add new collector:** Use `poetry new new_collector` then edit pyproject.toml for pyoaev with mutually exclusive markers (see README.md)

**Update dependencies:** Use Renovate bot (automated) or `poetry update <package>`. **NEVER modify pyoaev structure** without team approval.

## Troubleshooting

- **"Path for pyoaev does not exist"**: Clone `client-python` or use `--extras prod`
- **Import errors**: Run `poetry install --extras prod`
- **Black/isort conflicts**: Use `isort --profile black`
- **Docker build fails**: Check Poetry 2.1.3 in Dockerfile
- **CI formatting fails**: Run `black .` and `isort --profile black .` locally

## Key Files

**Root:** `pyproject.toml`, `.circleci/config.yml`, `.pre-commit-config.yaml`, `.flake8`, `scripts/release.py`, `renovate.json`

**Per-collector:** `pyproject.toml`, `Dockerfile`, `docker-compose.yml`, `.env.sample`, `README.md`

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
