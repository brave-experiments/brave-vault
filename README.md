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

### reveal vs use (two clearly-labeled capabilities)

A grant authorizes exactly one action, and the token the agent holds cannot be
redeemed for the other — you choose which at approval time:

- **`reveal`** returns the plaintext to the agent once (e.g. for the agent to
  type it). You are opting into the agent seeing the secret.
- **`use`** asks the app to perform the login so the agent never sees the
  password. This is the zero-knowledge path:

  ```sh
  brave-vault-agent request --item example.com --action use
  brave-vault-agent use --grant <id>              # default: --via inject
  ```

  `--via inject` (default) fills the login form via the app's Brave browser
  extension (see `extension/`), driven by a native-messaging host the app
  provisions automatically. The credential flows app → native host → extension →
  form and is filled only on the credential's own origin. `--via clipboard` is
  an explicit opt-in that copies the password to the clipboard — **readable by
  other local apps**, so it is not zero-knowledge and is labeled as such in the
  audit log.

Same-user caveat: no software boundary fully stops a same-user attacker. `use`
raises the bar (the secret goes to the browser-spawned host, not the agent), but
true isolation requires running the app/browser under a separate OS user.

### session (grab a logged-in browser session)

For sites that use 2FA (or where you're already logged in), the agent can grab
the **live session cookies** for an approved set of hosts and replay them in its
own automation browser — no password, no re-login:

```sh
brave-vault-agent request --action session --item "mail.google.com,accounts.google.com"
brave-vault-agent grab-session --grant <id>     # prints the cookies as JSON
```

- You approve the exact **host set** at the popup (a multi-domain login like
  Google needs its several hosts). The grab covers only those hosts.
- **Browser-enforced scope:** the extension holds no standing cookie access; it
  requests permission for exactly the approved hosts at grab time, and Brave
  prompts and refuses every other origin — so authorizing Google can never touch
  your bank.
- **Bearer-token caveat:** grabbed cookies are a full-account session until they
  expire. The grant is short-lived and single-use; revoke from the Agents panel.
  Origin-scoping controls *which* session the agent gets, not what it does with
  it once it has it.

See `docs/agent-access-plan.md` for the design.
