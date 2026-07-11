# Contributing

LeakLens is security tooling; detector changes require evidence and adversarial tests.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
python -m unittest discover -v
```

## Detector checklist

1. Link authoritative provider format documentation in the change description.
2. Add a synthetically assembled positive fixture so no token-shaped value is committed verbatim.
3. Add the provider's public example values and realistic placeholders as negative fixtures.
4. Bound token-sized captures and avoid nested ambiguous quantifiers.
5. Add lowercase literal `keywords` for cheap prefiltering.
6. Assign impact severity separately from pattern confidence.
7. Verify every renderer excludes the complete synthetic value.
8. Run the adversarial suite and benchmark.

Use `leaklens:allow` only with a reason. Do not commit production captures, credentials, credential
hashes copied from incidents, or provider validation responses.

Before committing:

```bash
ruff format .
ruff check .
mypy src
pytest --cov=leaklens --cov-report=term-missing
python -m build
leaklens scan --repo
```

Commit messages use `type: imperative description`, such as
`fix: reject documented AWS example identifiers`.

