# Contributing to The Linux Security Suite

LSS is commercial software. We accept three kinds of outside contributions:

1. **Bug reports** — anyone can file
2. **Documentation improvements** — typo fixes, clarifications, README polish (PRs welcome)
3. **CIS control updates** — when CIS publishes a new benchmark version, contributions that update the affected controls are welcome

We do **not** accept feature contributions to the rollback engine, license-key gate, or release pipeline. These are core IP and changes to them must come from the maintainer.

## Filing a Bug

For non-security bugs, open a GitHub issue using the bug report template. Please include:

- LSS version (`lss --version`)
- Distribution and version (`cat /etc/os-release`)
- Steps to reproduce
- The output of the failing command (please redact anything sensitive)
- The relevant entry from `/var/log/lss/journal/<run-id>.json` if the bug is in `harden` or `rollback`

For security vulnerabilities, see [SECURITY.md](SECURITY.md). Do not file public issues for those.

## Submitting a PR

If you've already discussed the change with a maintainer (via an issue or email) and we've agreed to accept it:

1. Fork the repo
2. Create a branch named `fix/short-description` or `docs/short-description`
3. Make your change. Keep it minimal — one PR per logical change.
4. Add or update a test in `tests/` if your change touches behavior. Run `pytest` locally and confirm it passes.
5. Update `CHANGELOG.md` under the `[Unreleased]` heading
6. Submit the PR using the PR template

## Coding Standards

- Python 3.10+, type hints where the value is non-obvious, no `mypy` enforced yet but heading there
- No `shell=True`. Ever. The rollback engine refuses to execute legacy shell-string undos for a reason.
- Every fix that modifies a file must call `journal.backup_file(path)` before the modification
- Every undo is `list[list[str]]` argv. No f-string-interpolated shell commands.
- No `except: pass` — log the exception or re-raise with context
- No comments that just restate the code. Only comment the *why* when it's non-obvious.
- `rich` is the only third-party runtime dependency. Don't add others without discussing first.

## CLA

Substantive code contributions (anything beyond typo fixes) require a Contributor License Agreement. We'll send you the CLA when it's relevant. The CLA is short, exists to keep the IP situation clean, and does not prevent you from using your contribution elsewhere.
