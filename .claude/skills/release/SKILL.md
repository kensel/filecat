---
name: release
description: Cut a filecat release - bump the one shared version (Python package and Rust agent) with scripts/version.py, commit, tag vX.Y.Z, push, and verify the GitHub release with the static agent binaries. Use when asked to release, bump the version, tag a version, or publish the agents.
---

# Release filecat

The full procedure and the reasons are in `docs/releasing.md`; read it first. This is the
checklist to run it.

Arguments: the version (`X.Y.Z` or `vX.Y.Z`) and optionally the release headline. If the version
is missing, propose one from `git tag -n`, `docs/roadmap.md` and the commits since the last tag
(`git log --oneline $(git describe --tags --abbrev=0)..HEAD`), and ask.

## 1. Preconditions

- On `main`, clean (`git status --short` empty), up to date (`git pull --ff-only`).
- CI green on `main`'s last commit: `gh run list --branch main --limit 3`. Stop and report if not.
- The tag does not exist yet: `git tag -l vX.Y.Z` and `git ls-remote --tags origin vX.Y.Z` empty.

## 2. Bump

```
uv run python scripts/version.py set X.Y.Z
uv run python scripts/version.py --check vX.Y.Z
```

Then the by-hand items in `docs/releasing.md` ("Not covered by the script"):

- `git grep -n -I -F "<old version>" -- docs README.md` and update only the lines that show the
  *current* version as example output; leave "new in", "older than" and history lines alone.
- If `agent/src/allowlist.rs` or the deny list changed since the last tag
  (`git diff --stat <last tag>..HEAD -- agent/src`), the hashes in
  `src/filecat/data/agent_expected.json` must match: `cd agent && ./build.sh hashes` (Linux/WSL).
  If you cannot run it, say so; CI's `expected_json_matches_this_build` will catch it.
- Mark the release's section `(done)` in `docs/roadmap.md` if it has one.

## 3. Verify

`uv run pytest -q`. Report failures with their output; do not tag over them.

## 4. Commit, push, tag: confirm with the user first

Show the diff summary, the version and the tag message, and get a yes before pushing (it is
public). Then:

```
git commit -am "filecat X.Y.Z"      # plus the attribution trailer the session asks for
git push origin main
```

Wait for CI on that commit (`gh run watch <id> --exit-status`). Then:

```
git tag -a vX.Y.Z -m "filecat X.Y.Z: <headline>"
git push origin vX.Y.Z
```

## 5. Confirm the release

```
gh run list --workflow release.yml --limit 1     # then gh run watch <id> --exit-status
gh release view vX.Y.Z
```

Expect `filecat-agent-X.Y.Z-linux-x86_64`, `-armv7`, `-aarch64` and `SHA256SUMS`. If the run
failed, follow "When the release run fails" in `docs/releasing.md`. Do not move a tag whose
release was published without asking.

Report: the release URL, the assets, and anything skipped (for example the hash check).
