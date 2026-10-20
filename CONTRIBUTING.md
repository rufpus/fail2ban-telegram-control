# Contributing

Use Python 3.12 or newer. The supported deployment target is Ubuntu 24.04 LTS
with Fail2ban 1.0.2 and nftables. Run the non-privileged suite:

```sh
python3 -m unittest discover -v
python3 tools/check_release.py
```

No bot token, Telegram account, SSH server or root access is needed for unit
tests. Linux integration tests run separately in a disposable container.

For new messages, use English `tr(...)` templates and add matching Russian
entries in `locales/ru.json`; keep their format placeholders identical. Do not
translate log data, IP addresses, command names or callback payloads.

Document behavior changes in both READMEs. Add tests for authorization,
confirmation expiry and retry/restart behavior when changing administration.
Use only documentation or benchmark addresses in fixtures. Never commit local
configuration, databases, keys, logs or private deployment files.

Demo screenshots come from real message-rendering functions with fixed synthetic
fixtures. Their HTML can be regenerated with `python3 tools/build_demo.py`.
Capture the pages at a consistent viewport, retain the **DEMO** label and update
the English and Russian images together.

## Static checks and the coverage baseline

Use Python 3.12+ in a virtual environment:

```bash
python -m pip install -r requirements-dev.txt
python -m ruff check .
python -m mypy
python -m pytest --cov --cov-fail-under=65 --cov-report=term-missing -q
```

These are development dependencies only; the installed service still uses stdlib
and the system Fail2ban package. Ruff checks all Python files with E4/E7/E9/F.
Mypy checks bodies in all six runtime modules targeting Linux; missing upstream
Fail2ban stubs have specific, explained `type: ignore[import-not-found]` comments.
The existing local HTML escaping lambda has a documented E731 exception to avoid
rewriting the message template. No whole runtime module is excluded from typing.

Coverage includes every runtime Python file, including installer, setup and the
Python action loaded through a test importlib fixture. It excludes tests, CI
fixtures and optional documentation tools. The rootless Windows baseline before
this gate was 65.12%; the portable whole-percent floor is 65%. Linux also runs the
POSIX rollback test. Keep the gate enabled and raise it as meaningful tests are
added; passing coverage does not prove service sandbox behavior (see the separate
real-systemd integration job).
