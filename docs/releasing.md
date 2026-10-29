# Releasing filecat

filecat (the Python package) and filecat-agent (the Rust agent in `agent/`) share **one
version**, `X.Y.Z`, and a release is an annotated tag `vX.Y.Z` on `main`. Pushing the tag runs
`.github/workflows/release.yml`, which builds the static Linux agents and publishes the GitHub
release. Agents (Claude Code) follow the same steps through the `release` skill
(`.claude/skills/release/SKILL.md`).

## Where the version lives

`scripts/version.py` knows every place (its `PLACES` list) and is the only thing that should
change them:

| file | what | read by |
|---|---|---|
| `pyproject.toml` | `[project] version` | the wheel, `uv pip install`, `uv tool install` |
| `src/filecat/__init__.py` | `__version__` | `filecat` at run time |
| `uv.lock` | the `filecat` package entry | `uv sync` (stale if not updated) |
| `agent/Cargo.toml` | `[package] version` | `env!("CARGO_PKG_VERSION")`: `--version`, the startup line, `hello`'s `agent_version` |
| `agent/Cargo.lock` | the `filecat-agent` package entry | cargo (rewrites it if stale) |

```
uv run python scripts/version.py                  # each place and its version
uv run python scripts/version.py set 0.2.2        # write 0.2.2 everywhere
uv run python scripts/version.py --check v0.2.2   # exit 1 unless all agree with the tag
```

Each of those lines carries a comment pointing at the script. `tests/test_version.py` fails CI
when the places disagree, and `release.yml` refuses a tag that does not match them.

Not covered by the script, update by hand when they change:

- **Docs that quote the current agent version** as example output: `docs/agent-deploy.md` (the
  startup line, section 8 "To X.Y.Z" notes), `docs/agent-protocol.md` (the `hello` example) and
  `docs/agent-server.md` (the `agents status` example). Old version numbers that say when a
  feature arrived ("new in 0.2.1", "an agent older than 0.2.1") stay as they are.
- **`src/filecat/data/agent_expected.json`**: the allowlist and deny list hashes, not the version.
  Only when `agent/src/allowlist.rs` or the deny list changed: `cd agent && ./build.sh hashes`,
  copy the values in (CI's `expected_json_matches_this_build` fails until they match).
- **`docs/roadmap.md`**: mark the release's section `(done)`.

## Steps

1. Start from an up-to-date, clean `main` with CI green on its last commit
   (`gh run list --branch main --limit 3`).
2. Pick the version: patch for fixes, minor for features or a protocol addition, and the
   number the roadmap already names when there is one.
3. `uv run python scripts/version.py set X.Y.Z`, then the by-hand items above.
4. Check locally: `uv run python scripts/version.py --check vX.Y.Z` and `uv run pytest -q`
   (the agent builds on Linux/WSL: `cd agent && cargo test && ./build.sh all`; otherwise CI does it).
5. Commit (`filecat X.Y.Z`) and push to `main`; wait for CI to pass on it.
6. Tag and push the tag. The tag message is the release notes' first line, in the style of
   the earlier tags (`git tag -n`):
   ```
   git tag -a vX.Y.Z -m "filecat X.Y.Z: <what this release is about>"
   git push origin vX.Y.Z
   ```
7. Watch the release run (`gh run list --workflow release.yml --limit 1`, `gh run watch <id>`)
   and confirm `gh release view vX.Y.Z` lists `filecat-agent-X.Y.Z-linux-{x86_64,armv7,aarch64}`
   and `SHA256SUMS`.

Install a release with `uv tool install "filecat[...] @ git+https://github.com/kensel/filecat@vX.Y.Z"`
(see the README's Install section).

## When the release run fails

The tag is already public. Before anything else downloads it: fix on `main`, then move the tag
(`git tag -d vX.Y.Z && git push origin :refs/tags/vX.Y.Z`, delete a half-made release with
`gh release delete vX.Y.Z`), and tag the fixed commit. Once a release has been published and
used, do not move its tag: release `X.Y.Z+1` instead.
