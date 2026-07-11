# LeakLens

[![CI](https://github.com/carterlasalle/LeakLens/actions/workflows/ci.yml/badge.svg)](https://github.com/carterlasalle/LeakLens/actions/workflows/ci.yml)
[![Security](https://github.com/carterlasalle/LeakLens/actions/workflows/security.yml/badge.svg)](https://github.com/carterlasalle/LeakLens/actions/workflows/security.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0-6e40c9)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/)
[![License: MIT](https://img.shields.io/badge/license-MIT-22c55e.svg)](LICENSE)

LeakLens finds credentials before they become incidents. It scans files, Git worktrees, staged
lines, standard input, and repository history using structured token patterns plus contextual
entropy analysis. It runs fully offline, has no runtime dependencies, and never prints or stores a
raw secret.

```text
$ leaklens scan --staged
SEVERITY  RULE            LOCATION          VALUE      DETAIL
────────  ──────────────  ────────────────  ─────────  ────────────────────────────────────────
CRITICAL  github-pat      src/config.py:8:9 ghp_…7Jq2  Potential credential committed to source
HIGH      generic-secret  deploy.env:14:13  Q9!…7#y    Potential credential committed to source

Found 2 potential secret(s): 1 critical, 1 high
```

## Why LeakLens is different

- **Secret-safe by construction.** Findings contain a redaction and a domain-separated BLAKE2s
  fingerprint. Raw matched values are discarded before a `Finding` exists, so JSON, logs, SARIF,
  tracebacks, and `repr()` cannot leak them later.
- **Scans the view you mean.** Scan a directory, Git-aware worktree, only newly staged lines, or the
  first historical appearance of each credential. History is bounded and attributes introductions
  to exact commits.
- **Useful in a terminal and a security program.** Human tables, JSON, JSONL, CSV, and SARIF 2.1.0
  share one stable model. SARIF findings include partial fingerprints for GitHub deduplication.
- **Explainable detections.** Every result names its detector, confidence, severity, entropy,
  redacted shape, location, and remediation category. No network validation or opaque model call.
- **Safe operational limits.** Symlinks are ignored by default; binary and oversized objects are
  skipped; Git commands have timeouts; staged patches, history depth, and finding counts are bounded.
- **Easy adoption.** One command creates policy, one installs a managed pre-commit hook, and the
  repository includes a reusable GitHub Action and pre-commit manifest.

## Install

LeakLens requires Python 3.11 or later.

```bash
git clone https://github.com/carterlasalle/LeakLens.git
cd LeakLens
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
python -m pip install -e .
leaklens doctor
```

For an isolated global command, use `pipx install .` from the checkout.

## Quick start

```bash
# Scan the current directory
leaklens scan .

# Respect .gitignore and scan tracked plus untracked Git files
leaklens scan --repo

# Pre-commit: inspect only newly added lines in the index
leaklens scan --staged

# Attribute the first appearance of each secret in up to 1,000 commits
leaklens scan --history

# Scan a pipeline without writing sensitive input to disk
printf '%s' "$CONFIG" | leaklens scan --stdin --stdin-filename deploy.env

# Generate GitHub code-scanning output
leaklens scan --repo --format sarif --output leaklens.sarif
```

Exit codes are designed for automation:

| Code | Meaning |
| ---: | --- |
| `0` | Scan completed and no finding met `--fail-on` |
| `1` | At least one finding met `--fail-on` |
| `2` | Configuration, I/O, Git, safety-limit, or reporting error |

Results are emitted before exit `1`. Use `--quiet` when only the code matters.

## Commands

| Command | Purpose |
| --- | --- |
| `leaklens scan [PATH ...]` | Scan files/directories; supports `--repo`, `--staged`, `--history`, or `--stdin` |
| `leaklens baseline create` | Fingerprint current accepted debt without storing secret values |
| `leaklens baseline show` | Inspect baseline version, generation time, and count |
| `leaklens rules` | List active built-in and project-specific detectors |
| `leaklens hook install` | Install a managed staged-line pre-commit hook |
| `leaklens init` | Create a documented `.leaklens.toml` |
| `leaklens doctor` | Validate Python, Git, policy, baseline, and offline operation |

Run `leaklens COMMAND --help` for the full contract.

## Detection catalog

LeakLens ships 16 focused detectors:

| Category | Detectors |
| --- | --- |
| Source control | GitHub PATs, GitLab PATs |
| Cloud | AWS access key IDs, Google API keys |
| AI platforms | OpenAI and Anthropic API keys |
| Collaboration | Slack tokens, SendGrid API keys |
| Payments | Stripe live secret/restricted keys |
| Supply chain | npm access tokens, PyPI upload tokens |
| Authentication | Private-key headers, JWTs, basic-auth URLs |
| Data stores | Credential-bearing PostgreSQL, MySQL, MariaDB, MongoDB, and Redis URLs |
| Contextual | Assigned API keys, client secrets, access/auth tokens, passwords, and secrets with entropy checks |

The structured formats track public provider prefixes documented by
[GitHub](https://docs.github.com/en/code-security/secret-scanning/introduction/supported-secret-scanning-patterns),
[AWS](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html),
[GitLab](https://docs.gitlab.com/security/tokens/), and
[Slack](https://api.slack.com/authentication/token-types). Pattern tests use synthetically assembled
values, never live credentials.

List the exact active policy:

```bash
leaklens rules
leaklens rules --format json
```

## Configuration

Run `leaklens init`, then edit `.leaklens.toml`:

```toml
[scan]
minimum_severity = "low"
max_file_size = 5242880
history_max_commits = 1000
exclude = ["tests/fixtures/**", "generated/**"]
follow_symlinks = false
scan_hidden = false

[baseline]
path = ".leaklens-baseline.json"

[[rules]]
id = "internal-service-token"
title = "Internal service token"
pattern = "(?P<secret>corp_[A-Za-z0-9]{32})"
severity = "critical"
minimum_entropy = 3.0
tags = ["internal", "token"]
keywords = ["corp_"]
```

Custom regexes must use a named `secret` capture group. Configuration is trusted code-policy input:
a pathological custom regex can consume significant CPU. `keywords` provides a cheap prefilter.

Precedence is explicit: CLI severity overrides TOML; CLI baseline path overrides TOML; built-in and
custom rules are combined; configured fingerprints and baseline fingerprints are unioned.

## Suppression and baselines

Suppress an intentional fixture on the same or immediately preceding line:

```python
# leaklens:allow -- synthetically generated documentation fixture
token = build_fake_token()
```

For existing debt, create a baseline:

```bash
leaklens baseline create --output .leaklens-baseline.json
git add .leaklens-baseline.json
leaklens scan --repo
```

The baseline contains only 40-character fingerprints, a schema version, and generation time. A
changed secret produces a different fingerprint and is reported. Prefer revoking and removing real
credentials; a baseline is a migration tool, not remediation.

## Git workflows

### Local hook

```bash
leaklens hook install
```

LeakLens refuses to overwrite a hook it does not own. `--force` is available only for an intentional
replacement. `leaklens hook uninstall` removes only a managed hook.

### pre-commit framework

```yaml
repos:
  - repo: https://github.com/carterlasalle/LeakLens
    rev: v0.1.0
    hooks:
      - id: leaklens
```

### GitHub Actions

Use the reusable action in another repository:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
- uses: carterlasalle/LeakLens@v0.1.0
  with:
    mode: repo
    format: sarif
    output: leaklens.sarif
```

The built-in CI scans LeakLens itself and uploads SARIF only with the permissions explicitly granted
by the workflow. The scanner makes no network requests.

## Machine output

`Finding.to_dict()` is the stable schema boundary. It includes rule metadata, location, commit,
severity, confidence, fingerprint, redacted shape, length, entropy, and message. It cannot include
the raw value because `Finding` never receives it.

```bash
leaklens scan --repo --format json
leaklens scan --staged --format jsonl
leaklens scan . --format csv > findings.csv
leaklens scan --repo --format sarif --output leaklens.sarif
```

See [docs/output-schema.md](docs/output-schema.md) for field stability and SARIF mapping.

## Performance

The scanner compiles its detector catalog once, prefilters rules by literal markers, walks text in
memory, and has no import-time frameworks. A dependency-free benchmark is included:

```bash
python benchmarks/benchmark_scan.py
```

Results depend heavily on file sizes, storage, encoding, and token-like marker density. The
benchmark is a regression tool, not a universal throughput claim.

## Security response

If LeakLens finds a real credential:

1. Revoke or rotate it first; deleting a line does not invalidate the credential.
2. Determine whether it reached a remote, build log, artifact, package, or fork.
3. Remove it from the current tree and, when justified, rewrite history with coordinated force-push.
4. Invalidate caches/artifacts and review provider audit logs for use.
5. Replace inline configuration with a secret manager or CI secret store.
6. Add staged scanning so the failure mode cannot recur.

Detailed containment guidance is in [docs/incident-response.md](docs/incident-response.md).

## Development

```bash
python -m pip install -e '.[dev]'
python -m unittest discover -v
ruff check .
ruff format --check .
mypy src
pytest --cov=leaklens --cov-report=term-missing
python -m build
```

The test suite covers every detector, false-positive fixtures, every output redaction contract,
filesystem policy, baseline/config validation, staged and historical Git behavior, hooks, resource
limits, thousands of arbitrary Unicode strings/byte sequences, and packaging.

Read [CONTRIBUTING.md](CONTRIBUTING.md) before changing a detector. Security reports follow
[SECURITY.md](SECURITY.md). The implementation and trust boundaries are explained in
[docs/architecture.md](docs/architecture.md).

## Non-goals

LeakLens does not transmit candidates for provider validation, prove a credential is active, replace
rotation, decrypt files, scan process memory, or silently rewrite history. Those choices keep the
tool offline, predictable, least-privileged, and safe to run on sensitive repositories.

## License

MIT © Carter LaSalle. See [LICENSE](LICENSE).

