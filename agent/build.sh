#!/bin/sh
# Build the static filecat-agent for Synology DSM / any x86_64 Linux (musl, no shared libraries).
#
#   ./build.sh            release binary
#   ./build.sh test       cargo test (the unit tests)
#   ./build.sh conformance   the binary the Python conformance run uses (feature test-root)
#
# Needs rustc + cargo and the musl target (`rustup target add x86_64-unknown-linux-musl`). ring
# compiles a little C with the host gcc; no musl-gcc is needed. Output goes to $CARGO_TARGET_DIR
# (default ~/.cache/filecat-agent-target) so a build from a Windows-mounted checkout stays fast.
set -eu
cd "$(dirname "$0")"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/filecat-agent-target}"
export CC_x86_64_unknown_linux_musl="${CC_x86_64_unknown_linux_musl:-gcc}"
TARGET=x86_64-unknown-linux-musl
case "${1:-release}" in
  test) cargo test ;;
  conformance)
    cargo build --release --target "$TARGET" --features test-root --target-dir "$CARGO_TARGET_DIR-conformance"
    echo "$CARGO_TARGET_DIR-conformance/$TARGET/release/filecat-agent" ;;
  release)
    cargo build --release --target "$TARGET"
    BIN="$CARGO_TARGET_DIR/$TARGET/release/filecat-agent"
    ls -l "$BIN"
    file "$BIN" 2>/dev/null || true
    echo "$BIN" ;;
  *) echo "usage: $0 [release|test|conformance]" >&2; exit 2 ;;
esac
