# OpenAEV collectors: agent instructions

Applies to the collectors in this repository (every directory except `libs/`). Work
under `libs/collectors-sdk/` follows `libs/collectors-sdk/CLAUDE.md` instead.

Build, lint and test commands, the `pyoaev` dependency setup and repository conventions are in
`.github/copilot-instructions.md` and `CONTRIBUTING.md`. Follow them. This file adds the
rules about `pyoaev` and the SDKs, and wins over them on that topic.

## Context: the SDK split

The shared runtime of `pyoaev` is moving into SDKs: `collectors-sdk` (`libs/` in this
repository) and `xtm-oaev-sdk` (in `client-python`). `pyoaev` keeps the OpenAEV API
client and serves the former names through deprecation shims. The `pyoaev` releases the
collectors pin today do NOT ship the SDKs.

## Hard rules

1. Keep the `pyoaev` imports a collector already uses (`pyoaev.daemons.CollectorDaemon`,
   `pyoaev.helpers.OpenAEVDetectionHelper`, `pyoaev.apis.inject_expectation.model`…) as
   long as its pinned `pyoaev` does not depend on the SDKs. NEVER import `collectors_sdk`
   or `xtm_oaev_sdk` in such a collector. Why: the install takes the pinned
   `pyoaev` from PyPI, where the SDK packages do not exist, so the collector would fail
   at runtime.
2. To check, run `pip show pyoaev` in the collector's environment: the SDKs are usable
   only if `collectors-sdk` appears under `Requires`.
3. NEVER change a `pyoaev` version pin, or add an SDK dependency
   without explicit approval.
4. NEVER edit `libs/collectors-sdk/` as a side effect of a collector task.

## Migrating a collector to the SDKs

Only when asked, and only once rule 2 passes:

- replace each legacy import with the one named by its `DeprecationWarning`, always
  from the package root (`from collectors_sdk import CollectorDaemon`), never from
  `public`, `seam` or `_core`;
- build the client yourself and pass it: `CollectorDaemon(..., api_client=OpenAEV(...))`;
- keep `pyoaev` for `OpenAEV` and the `pyoaev.apis` managers.

The full import table and before/after examples are in the
[migration guide](https://github.com/OpenAEV-Platform/client-python/blob/main/libs/xtm-oaev-sdk/docs/migration_guide.md).

## Stop and ask before

- changing any dependency declaration (`pyproject.toml`, requirements files);
- migrating a collector's imports to the SDKs;
- continuing when installing a local `client-python` fails to resolve `xtm-oaev-sdk`,
  `collectors-sdk` or `injectors-sdk`. Report the error instead of working around it.

## Done when

The linters and the collector's tests from `.github/copilot-instructions.md` pass. Report
the real output, and NEVER report a check as passing without running it.
