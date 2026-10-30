# collectors-sdk: agent instructions

Applies to work under `libs/collectors-sdk/`. Paths below are relative to that directory,
except in the commands, which run from the repository root.

collectors-sdk is the collector runtime (`CollectorDaemon`, `OpenAEVDetectionHelper`,
the expectation models). It builds on xtm-oaev-sdk, which lives in the `client-python`
repository, and `pyoaev` serves its names to legacy connectors through deprecation shims.

## Hard rules

1. Use xtm-oaev-sdk through its package root only (`from xtm_oaev_sdk import X`). NEVER
   import `xtm_oaev_sdk._core`, `xtm_oaev_sdk.seam` or `xtm_oaev_sdk.public`.
2. NEVER import `pyoaev`, `injectors_sdk`, `pika` or `requests`. The API client is
   injected (`api_client=`).
3. Respect the layering of `daemons`, `detection` and `expectations`: `seam/` imports
   neither `public/` nor `_core/`, `_core/` NEVER imports `public/`, and `public/` imports
   `_core/` only to assign module-level defaults typed by their port. Every piece of
   behaviour goes through a seam port, one-liners included.
4. NEVER rename or remove a public name, constructor argument, attribute or overridable
   hook. Why: `pyoaev` serves these exact objects to legacy collectors, which subclass
   them and patch them in their tests (`CollectorDaemon._setup`, for one).
5. Keep dispatch through `self`: `Expectation` and `OpenAEVDetectionHelper` pass their
   matching methods to the core as callables, and `CollectorDaemon` stays a subclass of
   `xtm_oaev_sdk.BaseDaemon` customised only through its hooks.
6. A seam change bumps that capability's `SEAM_VERSION` and gets an entry in `CHANGELOG.md`.
   Then regenerate the seam golden in the same change:
   `(cd libs/collectors-sdk && python test/seam/generate_seam_golden.py)`. NEVER
   regenerate it to make a failing `test/seam/test_seam_golden.py` pass without a
   deliberate seam change.

## Scope

Only make the changes directly requested. Do not add capabilities, abstractions, files,
dependencies or refactors beyond the task. A change that needs something new in
xtm-oaev-sdk belongs to `client-python`: stop and say so instead of working around it here.

## Stop and ask before

- changing a seam contract or a `SEAM_VERSION`;
- renaming or removing any public name;
- adding or changing a dependency in `pyproject.toml`;
- editing the seam golden `test/seam/fixtures/seam_golden.json`;
- deleting any file.

## Done when

Run from the repository root, and report the real output:

```bash
(cd libs/collectors-sdk && python -m pytest test)
black --check libs/collectors-sdk
isort --profile black --check libs/collectors-sdk
flake8 --ignore=E,W libs/collectors-sdk
```

All four pass. NEVER run the linters from inside `libs/collectors-sdk/`: from there,
isort classifies `collectors_sdk` as first-party and reorders imports the repository
keeps as they are. The repository CI does not run these tests, so this run is the only
check. NEVER report a check as passing without running it.

## Conventions

- Tests live in `test/`, exercise behaviour through the public API, and are written as
  `_given_*` / `_when_*` / `_then_*` helpers with a one-line `"""It ..."""` docstring.
- Recording a decision: add `docs/tdr/<slug>.tdr.md` with the header of an existing
  record and `status: draft`, plus a row in `docs/tdr/TDR_ToC.md`.
- Commit messages, when asked for: gitmoji + Conventional Commits with the
  `collectors-sdk` scope.

## Read when relevant

- `CONTRIBUTING.md`: setup, checks, and what differs from xtm-oaev-sdk.
- `docs/tdr/TDR_ToC.md`: the decisions behind the rules above.
- The xtm-oaev-sdk layering guide, `libs/xtm-oaev-sdk/docs/seam_strategy.md` in `client-python`.
