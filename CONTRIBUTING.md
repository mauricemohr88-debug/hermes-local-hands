# Contributing

Thanks for helping test a safer local companion for Hermes. The project is
alpha-stage; its protocol, state format, and CLI can change before a stable
release.

## Development setup and required checks

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'

ruff check .
ruff format --check .
pip-audit --local --skip-editable --progress-spinner off
pytest --cov=hermes_local_hands --cov-report=term-missing
python -m build
python -m twine check dist/*
```

Run checks against the commit you propose. Do not claim a command passed on a
platform where you did not run it. CI also installs the built wheel into a clean
environment; that validates packaging, not a real tunnel or two-host Hermes
deployment.

## Security-sensitive changes

Any change to authentication, client/workspace grants, paths, secret handling,
patch parsing, approvals, request TTL/recovery, receipts, command execution,
proxy trust, or state persistence requires all of the following:

1. A focused test for success and fail-closed behavior.
2. A [THREAT_MODEL.md](THREAT_MODEL.md) update when the trust boundary changes.
3. A review of whether output, errors, logs, or receipts could leak local paths,
   credentials, or source.
4. A clear statement of what remains untrusted. In particular, fixed check
   profiles execute repository code as the local user, are not a sandbox, and
   can cause host-side effects. Git-status observation does not detect effects
   outside the checkout's Git-visible state.

Prefer a smaller denied surface over a convenient implicit fallback. Preserve
the invariant that the remote protocol can neither approve/deny nor write the
active checkout, merge, push, or expose a raw shell.

## Pull requests

Describe the user problem, scope, security impact, validation actually run, and
known limitations. Keep changes narrow. Do not include automatic merge/push,
credentials, private repositories, private state databases, bearer tokens, or
real action receipts. Report security problems privately under
[SECURITY.md](SECURITY.md).
