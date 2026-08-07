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

## Agent access

Give an agent access to vault items without handing it the vault. The agent
runs `brave-vault-agent`, which talks to the running app over a local socket.
It never holds the vault secret — only a handle that lets it ask.

```sh
brave-vault-agent enroll --label "my agent"   # you confirm a popup in the app
brave-vault-agent request --item example.com --action reveal
brave-vault-agent reveal --grant <id>          # copies the password to clipboard
```

- Each request pops up in the app for approval, unless you pre-authorized it in
  the app's **Agents** panel.
- Access is per-item, single-use, and expires. Revoke any agent or grant from
  the Agents panel.
- `--action use` asks the app to open the site and fill the password itself, so
  the agent never sees it.

See `docs/agent-access-plan.md` for the design.
