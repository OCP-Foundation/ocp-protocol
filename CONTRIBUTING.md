# Contributing to OCP

Thank you for your interest in the OpenCognition Protocol. This document
explains how to contribute effectively.

## How to contribute

### Reporting issues

Use GitHub Issues for bugs, feature requests, and spec clarifications. Tag
issues with the appropriate scope label: `spec`, `schemas`, `sdk-python`,
`sdk-js`, `sdk-go`, `node`, `tests`, or `docs`.

For security vulnerabilities, **do not open a public issue.** See
[SECURITY.md](SECURITY.md).

### Proposing spec changes (RFC process)

Changes to the protocol specification or JSON schemas follow a heavier process:

1. Open a GitHub Issue tagged `[RFC]` describing the proposed change.
   Include: motivation, proposed change, impact analysis, backward
   compatibility assessment.
2. The TSC labels the issue for discussion (14-day minimum comment period).
3. If a TSC member sponsors the RFC, the author creates a branch
   (`feat/spec/<rfc-number>-<short-name>`) and submits a PR with:
   - Updated `spec/SPECIFICATION.md`
   - Updated or new JSON schemas
   - Updated SDK code (if the change affects wire format)
   - Updated tests
   - CHANGELOG entry
4. The PR requires 2 TSC approvals. Breaking changes require TSC
   supermajority (5/7).

### Contributing code

1. Fork the repository.
2. Create a feature branch: `git checkout -b feat/<scope>/<description>`
3. Write tests for all new functionality.
4. Ensure all checks pass:
   ```bash
   ruff check sdk/python/ node/src/ tests/ examples/
   ruff format --check sdk/python/
   mypy sdk/python/ocp/ --strict
   pytest tests/ -v --cov=ocp --cov-fail-under=85
   python -m ocp.compliance
   ```
5. Submit a Pull Request against `main`.

### Proposing extensions

New domain extensions (`ocp-ext:*`) follow:

1. Copy `spec/extensions/ocp-ext-template.md` to a new file.
2. Fill in all sections (scope, schemas, message types, examples).
3. Submit a PR to `spec/extensions/` and `schemas/`.
4. TSC reviews for: no conflict with core spec, schema validity, test
   coverage. SWG reviews for security. EAB reviews for ethics.
5. 1 TSC approval required.

## Commit convention

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

**Types:** `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`,
`build`, `ci`, `chore`, `revert`, `security`

**Scopes:** `spec`, `schemas`, `sdk-python`, `sdk-js`, `sdk-go`, `node`,
`tests`, `examples`, `docs`, `ci`, `governance`

**Examples:**

```
feat(sdk-python): add WebSocket automatic reconnection with backoff
fix(schemas): correct bond-record expires_at to require date-time format
docs(spec): clarify trust score computation for edge cases
test(tests): add PVL rejection code coverage for PVL-003
security(sdk-python): upgrade cryptography to 44.0 for CVE-2026-XXXXX
feat(spec)!: add recovery_request message type

BREAKING CHANGE: OCPUMF message_type enum now includes two additional
values. Implementations validating against a closed enum must update.
```

## Code style

- **Python:** Ruff formatter (line length 100), type hints required,
  `mypy --strict`, Google-style docstrings, Python 3.11+.
- **JSON Schemas:** Draft 2020-12, 2-space indent, `$id` and `description`
  on every schema and property.
- **Markdown:** 80-char soft wrap, ATX headings.
- **Tests:** Mirror source structure (`ocp/crypto.py` → `tests/test_crypto.py`).
  No network access in unit tests. Integration tests in `tests/integration/`
  marked with `@pytest.mark.integration`.

## Pull request checklist

- [ ] Commits follow Conventional Commits
- [ ] Tests added/updated (coverage ≥ 85%)
- [ ] Documentation updated (if user-facing)
- [ ] `ruff check` and `ruff format --check` pass
- [ ] `mypy --strict` passes
- [ ] CHANGELOG updated (for feat/fix/security)
- [ ] Schemas validate against metaschema (if changed)

## Contributor license agreement

By submitting a PR, you agree that your contributions are licensed under
the MIT License.

## Getting help

- GitHub Discussions for questions and design conversations
- `#ocp-dev` channel on the community chat
- TSC office hours (biweekly, open to all)

## Code of conduct

All participants must follow our [Code of Conduct](CODE_OF_CONDUCT.md).