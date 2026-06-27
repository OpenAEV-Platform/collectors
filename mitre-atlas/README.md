# OpenAEV MITRE ATLAS Collector

The MITRE ATLAS collector imports the [MITRE ATLAS](https://atlas.mitre.org/)
(Adversarial Threat Landscape for AI Systems) knowledge base into OpenAEV as a
dedicated `mitre-atlas` kill chain. It is the AI counterpart of the
`mitre-attack` collector: ATLAS tactics become kill chain phases and ATLAS
techniques / sub-techniques (`AML.Txxxx`) become attack patterns, so AI
adversarial actions can be mapped and the ATLAS coverage matrix can be rendered.

## How it works

1. Fetches the MITRE ATLAS STIX 2.1 bundle (ATT&CK-compatible: `x-mitre-tactic`
   objects, `attack-pattern` objects with `kill_chain_phases`, and
   `subtechnique-of` relationships).
2. Upserts ATLAS tactics as kill chain phases via `POST /api/kill_chain_phases/upsert`
   with `phase_kill_chain_name = "mitre-atlas"` and the canonical ATLAS matrix
   ordering (`phase_order`).
3. Upserts ATLAS techniques and sub-techniques as attack patterns via
   `POST /api/attack_patterns/upsert`, resolving sub-technique parents by STIX id.

## Configuration

| Parameter            | Env var               | Default                                                                                          | Description                                              |
| -------------------- | --------------------- | ------------------------------------------------------------------------------------------------ | -------------------------------------------------------- |
| OpenAEV URL          | `OPENAEV_URL`         | -                                                                                                | Base URL of the OpenAEV platform                         |
| OpenAEV token        | `OPENAEV_TOKEN`       | -                                                                                                | Admin API token                                          |
| OpenAEV tenant id    | `OPENAEV_TENANT_ID`   | -                                                                                                | Optional tenant id (multi-tenant deployments)            |
| Collector id         | `COLLECTOR_ID`        | `openaev_mitre_atlas`                                                                             | Unique collector id (UUIDv4 recommended)                 |
| Collector name       | `COLLECTOR_NAME`      | `MITRE ATLAS`                                                                                     | Display name                                             |
| Collector period     | `COLLECTOR_PERIOD`    | `P7D`                                                                                             | ISO-8601 duration between runs                            |
| ATLAS STIX URL       | `COLLECTOR_STIX_URL`  | `https://raw.githubusercontent.com/mitre-atlas/atlas-navigator-data/main/dist/stix-atlas.json`   | Override the ATLAS STIX bundle location (air-gapped use) |

## Run

```bash
# configure config.yml (see config.yml.sample) or environment variables, then:
poetry install --extras prod
poetry run python -m mitre_atlas.openaev_atlas
```

> For simultaneous development on `pyoaev` and this collector, clone
> [client-python](https://github.com/OpenAEV-Platform/client-python) alongside this
> repository and run `poetry install --extras dev` instead.

> Note: as with the other connectors in this repository, the collector icon
> (`mitre_atlas/img/icon-mitre-atlas.png`) is provided at build/deploy time.
