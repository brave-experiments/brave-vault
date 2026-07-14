# Brave Vault build.
#
#   make            build for the CURRENT platform (fast debug build)
#   make run        build, then launch (loads BRAVE_SERVICES_KEY from .envrc)
#
#   make mac        release .app + .dmg           (native; macOS host)
#   make windows    release NSIS installer         (cross-compiled via cargo-xwin)
#   make linux      release .deb + .rpm             (via Docker)
#   make all        mac + windows + linux release bundles
#
#   make frontend   build only the React/Vite frontend -> crates/app/dist
#   make icons      regenerate app icons from icons/icon.png (incl. Windows .ico)
#   make clean      remove build artifacts

# Use the rustup toolchain explicitly — the system cargo in /usr/local/bin is
# 1.83 and too old for some deps (edition2024). Call the toolchain binary by
# absolute path so PATH ordering can't pick the wrong one.
RUST_BIN  := $(HOME)/.rustup/toolchains/stable-x86_64-apple-darwin/bin
CARGO     := $(RUST_BIN)/cargo
CARGO_BIN := $(HOME)/.cargo/bin
LLVM_BIN  := /usr/local/opt/llvm/bin
export PATH := $(RUST_BIN):$(CARGO_BIN):$(PATH)

APP_DIR    := crates/app
TAURI_DIR  := $(APP_DIR)/src-tauri
BIN        := target/debug/brave_vault
WIN_TARGET := x86_64-pc-windows-msvc

# Default: build for the machine you're on.
.DEFAULT_GOAL := native

.PHONY: native
native: backend

# ---- frontend ----
# Install deps on first run, then Vite build into crates/app/dist.
.PHONY: frontend
frontend: $(APP_DIR)/node_modules
	cd $(APP_DIR) && npm run build

$(APP_DIR)/node_modules: $(APP_DIR)/package.json
	cd $(APP_DIR) && npm install
	@touch $@

# ---- current-platform debug build (dev loop) ----
# Backend embeds dist/ at compile time, so it depends on the frontend build.
.PHONY: backend
backend: frontend
	$(CARGO) build --bin brave_vault

.PHONY: run
run: backend
	( set -a; . ./.envrc; set +a; $(BIN) )

# ---- release bundles per platform ----

# macOS: native .app + .dmg. Only runs on a macOS host.
.PHONY: mac
mac: frontend
	cd $(APP_DIR) && $(CARGO) tauri build

# Windows: cross-compiled from macOS via cargo-xwin, packaged as an NSIS
# installer. Needs LLVM (clang-cl/lld-link) on PATH and makensis installed
# (see `make setup-windows`). Unsigned — Windows SmartScreen will warn.
.PHONY: windows
windows: frontend
	cd $(APP_DIR) && PATH="$(LLVM_BIN):$$PATH" $(CARGO) tauri build \
		--runner cargo-xwin --target $(WIN_TARGET) --bundles nsis

# Linux: built inside a Docker container with the webkit2gtk toolchain.
# Produces .deb + .rpm.
.PHONY: linux
linux: frontend
	./scripts/build-linux.sh

.PHONY: all
all: mac windows linux

# ---- one-time cross-build setup ----
.PHONY: setup-windows
setup-windows:
	$(CARGO) install tauri-cli --version "^2" --locked || true
	$(CARGO) install cargo-xwin --locked || true
	rustup target add $(WIN_TARGET)
	@command -v makensis >/dev/null 2>&1 || brew install makensis
	@ln -sf "$$(command -v makensis)" "$(CARGO_BIN)/makensis.exe"
	@echo "Windows cross-build ready. Ensure LLVM is installed: brew install llvm"

.PHONY: icons
icons:
	cd $(TAURI_DIR) && $(CARGO) tauri icon icons/icon.png

.PHONY: clean
clean:
	$(CARGO) clean
	rm -rf $(APP_DIR)/dist
