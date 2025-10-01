# OpenAEV collectors

[![Website](https://img.shields.io/badge/website-openaev.io-blue.svg)](https://openaev.io)
[![CircleCI](https://circleci.com/gh/OpenAEV-Platform/collectors.svg?style=shield)](https://circleci.com/gh/OpenAEV-Platform/collectors/tree/main)
[![Slack Status](https://img.shields.io/badge/slack-3K%2B%20members-4A154B)](https://community.filigran.io)

The following repository is used to store the OpenAEV collectors for the platform integration with other tools and
applications. To know how to enable collectors on OpenAEV, please read the [dedicated documentation](https://docs.openaev.io/latest/deployment/ecosystem/collectors).

## Collectors list and statuses

This repository is used to host collectors that are supported by the core development team of OpenAEV.
Nevertheless, the community is also developing a lot of collectors, third-parties modules directly linked to OpenAEV.
You can find the list of all available collectors and plugins in the [OpenAEV ecosystem dedicated space](https://filigran.notion.site/OpenAEV-Ecosystem-30d8eb73d7d04611843e758ddef8941b).

## Contributing

If you want to help use improve or develop new collector, please check out the
**[development documentation for new collectors](https://docs.openaev.io/latest/development/collectors)**. If you want to make your collectors available to the community,
**please create a Pull Request on this repository**, then we will integrate it to the CI and in
the [OpenAEV ecosystem](https://filigran.notion.site/OpenAEV-Ecosystem-30d8eb73d7d04611843e758ddef8941b).

## Development
This step installs all collectors within the repository inside a single poetry environment. If you do not wish
to work with all collectors at once, it is possible to install each collector within its own poetry environment. Refer
to each collector's individual README for instructions.

In this repository, you need to have `python >= 3.11` and `poetry >= 2.1`. Install the development environment with:
> [!IMPORTANT]
> This repository uses "mutually exclusive extra markers" to manage the source of the pyoaev dependency. Make sure to
> follow the steps to set up poetry correctly to handle this case:
> https://python-poetry.org/docs/dependency-specification/#exclusive-extras

> [!NOTE]
> For Windows hosts: as of writing, the [msgraph-python-sdk has the following note](https://github.com/microsoftgraph/msgraph-sdk-python/blob/65d88850202e9ea75477583e76e75dfbf6d75859/README.md#1-installation):
> > * The Microsoft Graph SDK for Python is a fairly large package. It may take a few minutes for the initial installation to complete.
> > * Enable long paths in your environment if you receive a Could not install packages due to an OSError. For details, see [Enable Long Paths in Windows 10, Version 1607, and Later](https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation?tabs=powershell#enable-long-paths-in-windows-10-version-1607-and-later).
> 
> Follow these instructions if not already enabled on your system.

```shell
poetry install --extras dev
```

### Creating a new collector

#### Project setup
Assuming a new collector by the name of `new_collector`, create a skeleton directory with:
```shell
poetry new new_collector
```

#### `pyoaev` dependency
We wish to retain the possibility to develop simultaneously on `pyoaev` and collectors. We rely on PEP 508 environment
markers to alternatively install a local path `pyoaev` dependency or a released version from PyPI; specifically the `extra`
marker.

Navigate to the new directory and edit `pyproject.toml`.
```shell
vim new_collector/pyproject.toml
```
(or open the file in your favourite editor).

Here's the expression for the pyoaev dependency, including the `extra` definition:
```toml
[tool.poetry.dependencies]
pyoaev = [
    { markers = "extra == 'prod' and extra != 'dev'", version = "<latest pyoaev release on PyPI>", source = "pypi"  },
    { markers = "extra == 'dev' and extra != 'prod'", path = "../../client-python", develop = true },
]

[tool.poetry.extras]
prod = []
dev = []
```

### Simultaneous development on pyoaev and a collector
The collectors repository is set to assume that in the event of a simultaneous development work on both `pyoaev`
and collectors, the `pyoaev` repository is cloned in a directory at the same level as the collectors root directory,
and is named strictly `client-python`.

Here's an example layout:
```
.
├── client-python       <= mandatory dir name
│   ├── docs
│   ├── pyoaev
│   ├── scripts
│   └── test
└── collectors          <= this repo root dir
    ├── atomic-red-team
    ├── crowdstrike
    ├── microsoft-azure
    ├── microsoft-defender
    ├── microsoft-entra
    ├── microsoft-intune
    ├── microsoft-sentinel
    ├── mitre-attack
    ├── openaev
    ├── scripts
    └── tanium-threat-response
```

## License

**Unless specified otherwise**, collectors are released under the [Apache 2.0](https://github.com/OpenAEV-Platform/collectors/blob/master/LICENSE). If a collector is released by its
author under a different license, the subfolder corresponding to it will contain a *LICENSE* file.

## About

OpenAEV is a product designed and developed by the company [Filigran](https://filigran.io).

<a href="https://filigran.io" alt="Filigran"><img src="https://github.com/OpenAEV-Platform/openaev/raw/master/.github/img/logo_filigran.png" width="300" /></a>