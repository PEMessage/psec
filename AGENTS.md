# AGENTS.md

`psec` is a pure-Python payments cryptography library (TR-31, CVV, DES/AES, MAC, PIN, PIN blocks). All modules live in `psec/`; tests in `tests/`.

## Toolchain (uv)

This environment uses the uv toolchain. Run tools through uv:

```
uv run python -m pytest        # test
uv run python -m mypy          # type check (strict)
uv run python -m flake8        # lint
uv run python -m black ./psec ./tests   # format
```

Sync the env with `uv sync` (installs runtime + `dev` dependency-group into `.venv`). `Makefile` targets (`make lint`, `make test`) call bare `python -m ...`; prefer `uv run`.

Packaging metadata lives in `pyproject.toml` `[project]` (there is no `setup.py`); dev tools are in `[dependency-groups]` dev; `uv.lock` is committed. `requirements.txt` / `requirements-dev.txt` are legacy mirrors used by CI — keep them in sync if you change deps.

## Verification order

`make test` runs lint first, then pytest. Match that: `black -> flake8 -> mypy -> pytest`.

## Testing quirks

- pytest is configured (`pyproject.toml`) with `--doctest-modules` and `testpaths = ["tests", "psec"]`. **Docstring examples (`>>>`) in `psec/*.py` are executed as tests** — most modules have them (tr31 ~73, pinblock ~29, des ~23). Keep doctests accurate when editing code.
- Run a single test file: `uv run python -m pytest tests/test_tr31.py`
- Run a single test: `uv run python -m pytest tests/test_tr31.py::test_name`

## Style / config

- `mypy` is `strict` over `psec/**/*.py`.
- flake8 excludes `tests/` and ignores many rules (see `setup.cfg`); black is the formatting authority (double quotes, trailing commas).
- `psec/__init__.py` re-exports modules; `F401` is intentionally ignored there.
- Supports Python 3.8–3.13 + PyPy — avoid newer-only syntax.
- `psec/py.typed` ships type info; keep annotations complete.

## Release

`make build` runs `uv build` + twine check; `make publish` uploads via twine. Version lives in `pyproject.toml` `[project].version`. Do not publish unless asked.
