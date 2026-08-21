# AGENTS.md

Instructions for AI agents (and humans) working in this repository: how to
write issues and pull requests, how to test collectors end-to-end with
Mimikyu + ofapi, and how to handle CI and commit attribution.

## 1. Writing issues

- Title format follows Conventional Commits, **without** an issue reference
  (the issue *is* the reference): `type(scope?)!?: description`.
  - Example: `fix(microsoft-defender): asyncio.get_event_loop() raises RuntimeError on Python 3.14`
  - `description` starts lowercase, no trailing period, preserve acronyms
    (OpenAEV, STIX, EDR, XDR, SIEM, UBI9, etc.).
  - `scope` is the collector name when the issue is collector-specific, e.g.
    `microsoft-defender`, `crowdstrike`.
- Use the repo's bug report template (`.github/ISSUE_TEMPLATE/1-bug_report.md`)
  structure: **Description / Environment / Reproducible steps / Expected
  output / Actual output / Additional information / Suggested fix**.
- Labels: exactly one primary type label matching the title prefix
  (`fix:` → `bug`, `feat:` → `feature`, `docs:` → `documentation`), plus
  `needs triage`, plus an optional area/scope label such as
  `collector: <name>` if one exists (check `gh label list` — not every
  collector has a dedicated label; don't invent one).
- If two issues describe the same root cause in different collectors,
  cross-reference each issue's body with the other issue's number.
- Create with `gh issue create --repo OpenAEV-Platform/collectors --title "..." --body-file ... --label "bug,needs triage[,collector: <name>]"`.

## 2. Writing pull requests

- Title format: Conventional Commits **with** a required issue reference
  suffix: `type(scope?)!?: description (#issue)`.
  - Example: `fix(microsoft-defender,microsoft-entra): use asyncio.run instead of get_event_loop for Python 3.14 compatibility (#572)`.
  - Every PR must be linked to an issue — reference it in the title suffix
    and/or with `Fixes #123` / `Fixes #124` in the body for multiple issues.
- PR labels are restricted to a small allowed set — **never** add type or
  area/scope labels to a PR:
  - exactly one ownership label: `filigran team` (Filigran employee) or
    `community` (external contributor),
  - optionally `vibe-coded` for AI-assisted changes reviewed by the author,
  - language/`dependencies` labels are applied automatically — don't add
    them manually.
- Base branch: target `main` unless the fix only makes sense on top of an
  unmerged feature branch (e.g. a bug only introduced by that branch).
- Body should cover: **Description** of the problem, **Fix** explanation,
  **Testing** performed (commands run, results), and `Fixes #issue` lines.
- Full title/label taxonomy source of truth: `.github/LABELS.md`.

## 3. Commit and attribution rules

- **Never sign commits with the agent's name or add a Copilot/AI
  co-author trailer.** Every commit must be attributed solely to the
  human user (`git config user.name` / `user.email` already set to the
  repo owner's identity — verify with `git log -1 --format='%an <%ae>'`
  before pushing, don't add `Co-authored-by:` lines for the agent).
- Sign commits per repo convention (see `.github/copilot-instructions.md`).
- Follow Conventional Commits for the commit message subject too, even
  though only the PR title strictly requires the `(#issue)` suffix.

## 4. Checking CI after every PR

After opening or pushing to a PR, **always** verify CI before considering
the work done:

```bash
gh pr checks <pr-number> --repo OpenAEV-Platform/collectors
```

- Wait for checks to settle (poll with a short sleep, e.g. 60-90s, then
  re-check) rather than assuming success right after push.
- Pay special attention to `codecov/patch` (diff coverage must hit the
  target threshold, e.g. 80%) and `codecov/project`. If a patch fails
  coverage, the changed lines need dedicated tests — don't just lower
  the bar or ignore it.
- Confirm the relevant `Test <collector>` job(s), `check-signed-commits`,
  `Validate PR Title`, and `ci/circleci: ensure_formatting` /
  `linter` / `test` all pass.
- Only report/declare a task complete once `gh pr checks` shows no
  failing checks (pending checks for unrelated collectors/jobs are fine).

## 5. Testing collectors end-to-end with Mimikyu + ofapi

Two sibling repos in the parent GitHub folder simulate the full stack so a
collector can be exercised offline, without real vendor credentials:

- **Mimikyu** (`../Mimikyu`) — a Flask app that fakes the **OpenAEV
  platform** itself: collector/injector registration, RabbitMQ-based
  messaging, expectations, and traces.
- **ofapi** (`../ofapi`) — a FastAPI app that fakes third-party **vendor
  APIs** (CrowdStrike, Tanium, Elastic, LogRhythm, NetWitness, QRadar,
  Splunk ES, Palo Alto Cortex XDR/XSOAR, SentinelOne, Shodan, Censys,
  Slack, Microsoft Graph, Gmail, OpenAI, etc.).

### Setup

```bash
# Start Mimikyu (OpenAEV platform fake) — default port 5001->5000, includes RabbitMQ
cd ../Mimikyu && docker-compose up -d --build

# Start ofapi (vendor API fakes) — default port 8000
cd ../ofapi && docker-compose up -d --build
```

From inside a collector's container, reach both via `host.docker.internal`:
`http://host.docker.internal:5001` (Mimikyu) and
`http://host.docker.internal:8000` (ofapi).

### Running a collector against them

Point the collector's `OPENAEV_URL` at Mimikyu and its vendor base-URL
config at ofapi, e.g.:

```bash
OPENAEV_URL=http://host.docker.internal:5001 \
OPENAEV_TOKEN=<any-value-mimikyu-accepts> \
COLLECTOR_ID=<uuid> \
COLLECTOR_PERIOD=PT1M \
CROWDSTRIKE_API_BASE_URL=http://host.docker.internal:8000/crowdstrike \
poetry run python -m crowdstrike.openaev_crowdstrike
```

- `COLLECTOR_PERIOD` must be an **ISO-8601 duration** (e.g. `PT1M`), not a
  bare integer of seconds.
- See `../ofapi/README.md#openaev-collectors` for the full table of
  per-collector vendor base-URL env vars.
- A healthy run: the collector registers with Mimikyu, polls ofapi (or a
  public data source for collectors like `nvd-nist-cve`/`mitre-attack`),
  and settles into its polling loop with no unhandled exceptions.

### Known limitations (not bugs in this repo)

Per `../ofapi/README.md#known-limitations`, some collectors cannot be
fully exercised offline because they hardcode real vendor auth endpoints:
`microsoft-azure`, `microsoft-defender`, `microsoft-defender-o365`,
`microsoft-entra`, `microsoft-intune`, `google-workspace`. These progress
past registration into a real (expected-to-fail) auth call
(`AADSTS90002` / `invalid_grant` / `InvalidClientTokenId`) — that failure
is expected and does not indicate a regression. `aws-resources` registers
fine but talks to real AWS. `palo-alto-cortex-xdr` requires ofapi to be
served over TLS (its client hardcodes `https://{fqdn}`); see the ofapi
README for generating a self-signed cert.

### Cleanup

Always tear down test infrastructure when done:

```bash
cd ../Mimikyu && docker-compose down
cd ../ofapi && docker-compose down
# remove any collector test containers/images and git worktrees you created
```
