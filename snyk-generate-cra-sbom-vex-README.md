# Snyk CRA SBOM/VEX Generator

Generates an aggregate, EU CRA-aligned Software Bill of Materials (SBOM) and a
companion Vulnerability Exploitability eXchange (VEX) document from Snyk Open
Source and Container project data, across any combination of Snyk
organizations, targets, assets, projects, groups, and tags.

See `snyk-cra-sbom-vex-requirements.md.pdf` for the full requirements this
implements.

## Requirements

- Python 3.9 or later
- No third-party packages required (standard library only)
- A Snyk API token with access to the orgs/projects you want to include

## Setup

Provide your Snyk API token either as an environment variable or a flag
(`--token` takes precedence if both are set):

```bash
export SNYK_TOKEN=<your-snyk-api-token>
```

## Running it

Run all commands from the repository root. The entry point is the top-level
script:

```bash
python3 snyk-generate-cra-sbom-vex.py --org <org-id>
```

At least one source flag is required. All six are repeatable and freely
combinable in a single run:

```bash
python3 snyk-generate-cra-sbom-vex.py \
  --org acme-platform \
  --target 3f9c... --target 7a21... \
  --project 55e0... \
  --group ee19... \
  --tag team=platform-security
```

Run `python3 snyk-generate-cra-sbom-vex.py --help` for the full flag
reference. The most commonly used ones:

| Flag | Purpose |
| --- | --- |
| `--org`, `--target`, `--asset`, `--project`, `--group`, `--tag` | Source selection (repeatable, at least one required) |
| `--token` | Snyk API token (overrides `$SNYK_TOKEN`) |
| `--sbom-format` | SBOM format (default `cyclonedx1.6+json`); see note below |
| `--output-prefix` | Filename stem for the two output files (default: `sbom`/`vex` in the current directory) |
| `--no-vex` | Write the SBOM only, skip VEX generation |
| `--fail-fast` | Abort on the first project-level failure instead of continuing |
| `--debug` / `-v` | Verbose logging (HTTP requests, pagination, per-project status) |

## What it does

For the resolved, de-duplicated set of projects:

1. Fetches each in-scope (Open Source/Container) project's SBOM.
2. Merges them into one aggregate CycloneDX document, de-duplicating
   components by package URL and preserving the dependency graph.
3. Derives a CycloneDX VEX document from each project's vulnerability and
   ignore data, cross-referenced to the aggregate SBOM.
4. Writes both documents to disk.

By default this produces `sbom.json` and `vex.json` in the current directory.
With `--output-prefix myrun`, it produces `myrun.sbom.json` and
`myrun.vex.json` instead.

**Current limitation:** merging and VEX derivation are only implemented for
the default CycloneDX+JSON format. Choosing an XML or SPDX `--sbom-format`
still fetches per-project SBOMs, but the aggregate SBOM/VEX files are not
produced for those formats (the run will say so).

## Running the tests

```bash
python3 -m unittest discover -s tests -t .
```

## Disclaimer

This script is provided for demonstration, testing, and educational purposes
only. It is **not** intended for production use. Use it at your own risk.
The author assumes no responsibility or liability for any damage, data loss,
or other consequences resulting from its use — including from the Snyk API
calls it makes, the accuracy of the generated SBOM/VEX documents, or any
action taken based on their contents.
