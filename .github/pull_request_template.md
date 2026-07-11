## Security behavior

Explain the user-visible change and the trust boundary it affects.

## Verification

- [ ] A failing-first test demonstrates the change.
- [ ] No live or verbatim provider token-shaped credential was added.
- [ ] Positive fixtures are assembled synthetically and negatives cover public examples.
- [ ] All output formats remain unable to serialize raw values.
- [ ] Resource limits and malformed/adversarial inputs were considered.
- [ ] `uv run ruff check .`, strict mypy, coverage, self-scan, and build pass.
- [ ] Documentation and schema notes are updated where required.
