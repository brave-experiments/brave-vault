# Brave Vault

## Login

The vault password is temporarily hardcoded to `testing` (to be replaced later).

## Setup

Set `BRAVE_SERVICES_KEY` before running:

```sh
cp .envrc.example .envrc
# edit .envrc and fill in BRAVE_SERVICES_KEY
```

`make run` sources `.envrc` on its own. Alternatively you can use
[direnv](https://direnv.net/): run `direnv allow` once and it loads `.envrc`
automatically.

## Build

```sh
make            # debug build for the current platform
make run        # build, then launch (loads BRAVE_SERVICES_KEY from .envrc)
make frontend   # build only the React/Vite frontend
make clean      # remove build artifacts
```

On Linux, run `make setup-linux` once first to install the GTK/webkit2gtk dev
libraries Tauri needs.

Release bundles:

```sh
make mac        # .app + .dmg (macOS host)
make windows    # NSIS installer (cross-compiled via cargo-xwin)
make linux      # .deb + .rpm (via Docker)
make all        # all three
```
