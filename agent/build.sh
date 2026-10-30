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
      # Built for size: a DS2015xs (Linux 3.10.108, alpine) SIGKILLs at exec, silently, any armv7
      # agent whose loaded image spans more than ~0x197000 bytes; opt-level 3 reached that in 0.2.2.
      # check_span below fails the build before it gets there again.
      export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_RUSTFLAGS="${CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_RUSTFLAGS:--C opt-level=s}"
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

# armv7 only: the span of the LOAD segments (lowest address to the end of the bss, in pages) must
# stay below the largest that ran on the DS2015xs (0x197000; one page more is killed at exec).
# Fails above ARMV7_MAX_SPAN, warns within 64 KiB of it.
ARMV7_MAX_SPAN=$((0x197000))
check_span() {  # path
  command -v readelf >/dev/null 2>&1 || { echo "  span    not checked (no readelf)"; return 0; }
  min=; max=0
  for seg in $(readelf -lW "$1" | awk '$1 == "LOAD" { print $3 ":" $6 }'); do  # VirtAddr:MemSiz
    lo=$((${seg%%:*})); hi=$((lo + ${seg#*:}))
    if [ -z "$min" ] || [ "$lo" -lt "$min" ]; then min=$lo; fi
    if [ "$hi" -gt "$max" ]; then max=$hi; fi
  done
  span=$(( (max + 4095) / 4096 * 4096 - min / 4096 * 4096 ))
  printf '  span    0x%x bytes (limit 0x%x)\n' "$span" "$ARMV7_MAX_SPAN"
  if [ "$span" -gt "$ARMV7_MAX_SPAN" ]; then
    echo "armv7 image span 0x$(printf %x "$span") is over 0x$(printf %x "$ARMV7_MAX_SPAN"): the DS2015xs kills it at exec (see setup)" >&2
    return 1
  fi
  [ "$span" -gt $((ARMV7_MAX_SPAN - 0x10000)) ] && echo "  warning: within 64 KiB of the armv7 span limit" >&2
  return 0
}

release() {
  for t in $(expand "${1:-x86_64}"); do
    tr=$(triple "$t"); setup "$t"
    cargo build --release --target "$tr"
    report "$CARGO_TARGET_DIR/$tr/release/filecat-agent" "$t ($tr)"
    if [ "$t" = armv7 ]; then check_span "$CARGO_TARGET_DIR/$tr/release/filecat-agent"; fi
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
