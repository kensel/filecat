#!/bin/sh
# Build the static filecat-agent for Synology DSM / any Linux (musl, no shared libraries).
#
#   ./build.sh                    release binary, x86_64 (the default)
#   ./build.sh release [TARGET]   TARGET: x86_64 | armv7 | aarch64 | all
#   ./build.sh x86_64|armv7|aarch64|all     same, shorthand
#   ./build.sh test [TARGET]      cargo test; for armv7/aarch64 under qemu-user (qemu-arm-static ...)
#   ./build.sh conformance        the x86_64 binary the Python conformance run uses (feature test-root)
#   ./build.sh hashes             print the Rust allowlist_sha256 / deny_sha256 (compare with
#                                 src/filecat/data/agent_expected.json; see docs/agent-deploy.md)
#
# Pick the binary on the NAS by `uname -m`: x86_64 -> x86_64, armv7l -> armv7, aarch64 -> aarch64.
#
# Needs rustc + cargo and the musl targets (`rustup target add x86_64-unknown-linux-musl
# armv7-unknown-linux-musleabihf aarch64-unknown-linux-musl`). ring compiles a little C: x86_64 uses
# the host gcc; the ARM targets use the Debian/Ubuntu cross compilers (`apt-get install
# gcc-arm-linux-gnueabihf gcc-aarch64-linux-gnu`), which are also the linker driver (rustc supplies
# the self-contained musl crt and libc.a, so the result is fully static). `qemu-user-static` runs the
# ARM tests. Output goes to $CARGO_TARGET_DIR (default agent/target, which is gitignored; on WSL set it to a path
# on the Linux filesystem, e.g. ~/.cache/filecat-agent-target, which is much faster than /mnt/c).
# The conformance build goes to $CARGO_TARGET_DIR-conformance (agent/target-conformance, ignored too).
set -eu
cd "$(dirname "$0")"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target}"
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

triple() {
  case "$1" in
    x86_64)  echo x86_64-unknown-linux-musl ;;
    armv7)   echo armv7-unknown-linux-musleabihf ;;
    aarch64) echo aarch64-unknown-linux-musl ;;
    *) echo "unknown target '$1' (x86_64 | armv7 | aarch64 | all)" >&2; exit 2 ;;
  esac
}

# Export CC / linker / runner variables for one short target name.
setup() {
  case "$1" in
    x86_64)
      export CC_x86_64_unknown_linux_musl="${CC_x86_64_unknown_linux_musl:-gcc}" ;;
    armv7)
      # Linked for 64 KiB pages: Synology's "alpine" kernels (DS2015xs, Linux 3.10.108; not
      # "alpine4k") use them, and a segment whose address and file offset differ by other than a
      # multiple of 64 KiB cannot be mapped there: the agent is SIGKILLed at exec, silently. GNU ld
      # aligns armv7 for 4 KiB pages by default (aarch64 already for 64 KiB). check_pages below.
      export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_RUSTFLAGS="${CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_RUSTFLAGS:--C link-arg=-Wl,-z,max-page-size=0x10000}"
      export CC_armv7_unknown_linux_musleabihf="${CC_armv7_unknown_linux_musleabihf:-arm-linux-gnueabihf-gcc}"
      export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_LINKER="${CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_LINKER:-arm-linux-gnueabihf-gcc}"
      export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_RUNNER="${CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_RUNNER:-qemu-arm-static}" ;;
    aarch64)
      export CC_aarch64_unknown_linux_musl="${CC_aarch64_unknown_linux_musl:-aarch64-linux-gnu-gcc}"
      export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER:-aarch64-linux-gnu-gcc}"
      export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER="${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER:-qemu-aarch64-static}" ;;
  esac
}

expand() { if [ "${1:-x86_64}" = all ]; then echo "x86_64 armv7 aarch64"; else echo "${1:-x86_64}"; fi; }

report() {  # path, short name
  size=$(wc -c < "$1" | tr -d ' ')
  sum=$(sha256sum "$1" | cut -d' ' -f1)
  echo "artefact $2"
  echo "  path    $1"
  echo "  size    $size bytes"
  echo "  sha256  $sum"
  command -v file >/dev/null 2>&1 && echo "  file    $(file -b "$1")"
  return 0
}

# ARM builds: every LOAD segment must load on a 64 KiB-page kernel (see setup): address and file
# offset congruent modulo 64 KiB, alignment at least 64 KiB, and no 64 KiB page shared by two
# segments (the later mapping would replace the earlier one's permissions on it).
PAGE64K=$((0x10000))
check_pages() {  # path
  command -v readelf >/dev/null 2>&1 || { echo "  pages   not checked (no readelf)"; return 0; }
  bad=; prev=-1
  # Offset:VirtAddr:MemSiz:Align (Align is the last field: Flg may hold a space, "R E")
  for seg in $(readelf -lW "$1" | awk '$1 == "LOAD" { print $2 ":" $3 ":" $6 ":" $NF }'); do
    off=$((${seg%%:*})); rest=${seg#*:}; va=$((${rest%%:*})); rest=${rest#*:}
    msz=$((${rest%%:*})); align=$((${rest#*:}))
    [ $(( (va - off) % PAGE64K )) -eq 0 ] || bad="$bad va 0x$(printf %x $va) vs offset 0x$(printf %x $off);"
    [ "$align" -ge "$PAGE64K" ] || bad="$bad align 0x$(printf %x $align) at va 0x$(printf %x $va);"
    [ $((va / PAGE64K)) -gt "$prev" ] || bad="$bad va 0x$(printf %x $va) shares a 64 KiB page;"
    prev=$(( (va + msz - 1) / PAGE64K ))
  done
  if [ -n "$bad" ]; then
    echo "  pages   NOT loadable with 64 KiB pages:$bad" >&2
    return 1
  fi
  echo "  pages   loadable with 64 KiB pages"
}

release() {
  for t in $(expand "${1:-x86_64}"); do
    tr=$(triple "$t"); setup "$t"
    cargo build --release --target "$tr"
    report "$CARGO_TARGET_DIR/$tr/release/filecat-agent" "$t ($tr)"
    if [ "$t" != x86_64 ]; then check_pages "$CARGO_TARGET_DIR/$tr/release/filecat-agent"; fi
  done
}

cmd="${1:-release}"
case "$cmd" in
  test)
    t="${2:-x86_64}"
    if [ "$t" = x86_64 ]; then cargo test; else
      for x in $(expand "$t"); do setup "$x"; cargo test --target "$(triple "$x")"; done
    fi ;;
  conformance)
    TARGET=x86_64-unknown-linux-musl; setup x86_64
    cargo build --release --target "$TARGET" --features test-root --target-dir "$CARGO_TARGET_DIR-conformance"
    echo "$CARGO_TARGET_DIR-conformance/$TARGET/release/filecat-agent" ;;
  hashes)
    cargo test print_expected_hashes -- --nocapture --test-threads=1 | sed -n 's/.*\(EXPECTED .*\)/\1/p' ;;
  release) release "${2:-x86_64}" ;;
  x86_64|armv7|aarch64|all) release "$cmd" ;;
  *) echo "usage: $0 [release [TARGET]|TARGET|test [TARGET]|conformance|hashes]  (TARGET: x86_64|armv7|aarch64|all)" >&2; exit 2 ;;
esac
