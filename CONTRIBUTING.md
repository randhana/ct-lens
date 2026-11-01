# Contributing to ct-lens

Thanks for your interest! ct-lens is a small, focused tool and contributions are welcome.

## Ground rules (read these first)

ct-lens is **defensive / threat-intelligence tooling**. Two rules are non-negotiable and are
enforced in code, not just docs (see the README §5 and §6):

1. **Never contact a target server.** ct-lens only reads public Certificate Transparency logs
   (via crt.sh). No live TLS handshakes, no port scanning, no probing.
2. **No name-and-shame.** Published/aggregate output is anonymised by default. Sensitive
   individual findings go through responsible disclosure, never straight into a public report.

A pull request that breaks either rule will not be merged.

## Development setup

```bash
git clone https://github.com/your-org/ct-lens
cd ct-lens
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,analysis]"
pre-commit install          # optional: runs lint/format on commit
```

## Before you push

All of these run in CI and must pass:

```bash
ruff check .          # lint
ruff format .         # auto-format
mypy                  # static types (strict)
pytest                # tests (never hit the network — use recorded fixtures)
```

## Conventions

- **Type hints everywhere.** `mypy` runs in `strict` mode.
- **Docstrings on every public module, class, and function.**
- **Tests must not touch the network.** Mock crt.sh with `respx` and the fixtures in
  `tests/fixtures/`.
- **All real logic lives in `src/ct_lens/core/`.** The CLI and the (future) web API are thin
  wrappers — do not duplicate logic in them.
