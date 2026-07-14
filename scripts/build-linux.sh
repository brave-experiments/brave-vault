#!/usr/bin/env bash
# Build the Linux release bundles (.deb + .rpm) inside a Docker container so it
# works from a macOS host. Requires Docker to be running.
#
# The frontend (crates/app/dist) must already be built — `make linux` does that
# first. This script only compiles the Rust/Tauri backend + bundles it, using an
# image that carries the webkit2gtk / GTK toolchain Tauri links against on Linux.
#
# IMPORTANT: cargo compiles into a CONTAINER-LOCAL dir (/build), NOT the macOS
# bind mount. Compiling directly on the osxfs/virtiofs mount causes intermittent
# "can't find crate" errors — the mount's coarse mtime + flaky locking makes
# cargo lose .rlibs it just wrote. We rsync the source in, build on the fast
# native fs, then copy only the finished packages back to the mounted volume.
set -euo pipefail

cd "$(dirname "$0")/.."

if ! docker info >/dev/null 2>&1; then
  echo "error: Docker is not running. Start Docker Desktop and retry." >&2
  exit 1
fi

# Debian bookworm + Rust + the GTK/webkit2gtk deps Tauri needs on Linux. Rust
# must be recent enough for the dependency tree (some deps need >=1.88); pin to a
# digest for fully reproducible builds.
IMAGE="rust:1.90-bookworm"

# Named volumes cache the cargo registry + installed tauri-cli across runs so
# only the app itself recompiles each time.
CARGO_REGISTRY_VOL="brave-vault-cargo-registry"
CARGO_BIN_VOL="brave-vault-cargo-bin"

# We build x86_64 Linux. On Apple Silicon this runs under emulation (slower);
# pass --platform so the toolchain matches the target regardless of host arch.
docker run --rm \
  --platform linux/amd64 \
  -v "$PWD":/work \
  -v "$CARGO_REGISTRY_VOL":/usr/local/cargo/registry \
  -v "$CARGO_BIN_VOL":/cargo-bin \
  -w /work \
  "$IMAGE" \
  bash -euo pipefail -c '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq \
      libwebkit2gtk-4.1-dev \
      libgtk-3-dev \
      libayatana-appindicator3-dev \
      librsvg2-dev \
      libssl-dev \
      pkg-config \
      file \
      rpm \
      rsync \
      >/dev/null

    # tauri-cli (cached in the bin volume across runs).
    export PATH="/cargo-bin:$PATH"
    if [ ! -x /cargo-bin/cargo-tauri ]; then
      cargo install tauri-cli --version "^2" --locked --root /cargo-bin-install
      cp /cargo-bin-install/bin/cargo-tauri /cargo-bin/
    fi

    # Copy the source onto the container-local fs (fast, reliable) — never build
    # on the /work bind mount. Exclude the host target dirs and node_modules.
    mkdir -p /build
    rsync -a --delete \
      --exclude target --exclude node_modules --exclude .git \
      /work/ /build/
    cd /build/crates/app

    cargo tauri build --bundles deb rpm

    # Copy just the finished packages back to the mounted volume.
    mkdir -p /work/target/linux/bundle/deb /work/target/linux/bundle/rpm
    cp /build/target/release/bundle/deb/*.deb  /work/target/linux/bundle/deb/  2>/dev/null || true
    cp /build/target/release/bundle/rpm/*.rpm  /work/target/linux/bundle/rpm/  2>/dev/null || true
  '

echo ""
echo "Linux bundles:"
ls -1 target/linux/bundle/deb/*.deb target/linux/bundle/rpm/*.rpm 2>/dev/null || \
  echo "  (none produced — see build output above)"
