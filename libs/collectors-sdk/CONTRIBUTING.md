# Contributing to collectors-sdk

collectors-sdk runs on the
[xtm-oaev-sdk contributing guide](https://github.com/OpenAEV-Platform/client-python/blob/main/libs/xtm-oaev-sdk/CONTRIBUTING.md)
for the layering, seams, tests and TDRs, and on the repository's
[CONTRIBUTING.md](../../CONTRIBUTING.md) for commits and pull requests. This page only
covers where it differs.

## Set up

On Python 3.12 or later, with `client-python` checked out right next to this repository:

```bash
cd libs/collectors-sdk
pip install -e ../../../client-python/libs/xtm-oaev-sdk -e .
```

No local `client-python`? Pull `xtm-oaev-sdk` straight from git:

```bash
pip install "xtm-oaev-sdk @ git+https://github.com/OpenAEV-Platform/client-python.git@<ref>#subdirectory=libs/xtm-oaev-sdk"
```

## Run the checks

```bash
python -m pytest test            # from libs/collectors-sdk
pre-commit run --files <files>   # from the repository root: black, flake8, isort (black profile), check-yaml
```

The repository CI does not run the collectors-sdk tests yet. That job is yours: run
them before every change.

## What is specific here

- collectors-sdk reaches xtm-oaev-sdk through its package root only, and never imports
  `pyoaev`, `pika` or `requests`. `test/test_boundaries.py` keeps it honest
  ([collectors-sdk-builds-on-xtm-oaev-sdk-public-api-only](docs/tdr/collectors-sdk-builds-on-xtm-oaev-sdk-public-api-only.tdr.md)).
- Need something new in xtm-oaev-sdk? That change starts in `client-python`, not here:
  collectors-sdk depends on `xtm-oaev-sdk (>=0.1.0,<0.2.0)`.
- Seam changes bump the capability's `SEAM_VERSION` (`daemons`, `detection`,
  `expectations`) and land in [CHANGELOG.md](CHANGELOG.md).
- Commits carry the `collectors-sdk` scope:
  `:recycle: refactor(collectors-sdk): enhancing port-adapter public boundaries`.
- The decisions that belong to this SDK alone are in [docs/tdr/TDR_ToC.md](docs/tdr/TDR_ToC.md).
