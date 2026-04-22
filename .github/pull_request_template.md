<!-- Before submitting, please confirm with a maintainer (via an issue) that this PR will be accepted. See CONTRIBUTING.md. -->

## What this changes

<!-- One short paragraph. -->

## Why

<!-- The motivation. Tie to an issue if there is one: "Fixes #123" -->

## Test plan

- [ ] `pytest` passes locally
- [ ] Added or updated a test in `tests/` if behavior changed
- [ ] Updated `CHANGELOG.md` under `[Unreleased]`
- [ ] Ran `lss audit` and `lss list` against the patched code on a real Debian/Ubuntu/Kali host

## Checklist

- [ ] No `shell=True` introduced anywhere
- [ ] Any new file-modifying fix calls `journal.backup_file(path)` before writing
- [ ] Any new undo is `list[list[str]]` argv, not a shell string
- [ ] No `except: pass` blocks added
- [ ] No new third-party runtime dependencies (rich is the only one)
- [ ] CLA acknowledged if this is a substantive code change
