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
