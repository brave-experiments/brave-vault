# Agent Access to the Vault — Design & Multi-Step Plan

## Goal

Let an autonomous agent (typically a CLI-driven LLM agent) obtain one or more
items from the vault — a password, an identity, a note — **without ever holding
a long-lived, broadly-scoped secret**, and ideally, where possible, **without
ever seeing the credential plaintext at all**. Access is mediated by a **broker**
(the Brave Vault desktop app), which holds the real secrets, can prompt the user
for live approval, and can also honor **grants the user pre-created** ahead of
time.

This document is the north star. Each phase is independently shippable.

---

## Threat model (why the design is shaped this way)

An agent is a hostile-by-default environment for a secret:

- **Prompt injection** — a malicious web page or file can hijack the agent and
  make it exfiltrate anything in its context or reachable via its tools.
- **Log/transcript leakage** — agent stdout, shell history, and conversation
  transcripts are often persisted and shipped to third parties.
- **Broad blast radius** — a single leaked long-lived, unscoped token exposes
  the *entire* vault forever.

Design principles that follow:

1. **The agent never holds the vault mnemonic or `BRAVE_SERVICES_KEY`.** Those
   live only inside the broker's trust boundary.
2. **Capabilities, not credentials.** The agent holds a *handle* that lets it
   *ask*; it does not hold the secret itself.
3. **Short-lived + single-use.** Anything that crosses into the agent's process
   is scoped to one item, expires in seconds, and is invalidated after one use.
4. **Least privilege.** A grant names exactly which item(s) and which action
   (`reveal` vs `use`), nothing broader.
5. **Prefer never-reveal.** Where the broker can *perform* the privileged action
   (fill a login, sign a request), the plaintext never enters the agent at all.
6. **Auditable & revocable.** Every grant and every use is logged and can be
   revoked instantly.

---

## Answering the three core questions

### Q1. "Agents should never have access to a token" — correct?

Correct *in spirit*: an agent should never hold a **long-lived, broadly-scoped**
secret. It is fine for an agent to briefly hold a **narrow, single-use,
short-TTL capability**, because leaking it exposes at most one item for a few
seconds. So the rule is not "no token ever" — it's "no *durable, powerful*
token."

### Q2. "A one-time-use token generated from a token it never sees"

Yes — this is the **capability-handle + ephemeral-grant exchange**:

- The agent is provisioned once with a **handle**: an opaque capability ID plus
  a secret it can prove possession of. The secret is stored in the OS keychain
  and **never printed**. The handle alone grants nothing — it only lets the
  agent *request*.
- At the moment of need, the agent exchanges the handle for a **single-use,
  short-TTL access grant** via the broker. The broker may require live user
  approval for that exchange.
- The powerful secret (mnemonic / services key) never leaves the broker. The
  only thing "in flight" is the one-shot grant, useless after one use.

### Q3. "Use a shared item without ever seeing it"

Achievable in two modes; we support both and default to the first where
feasible:

- **Broker-performs (true zero-knowledge).** Agent says "log into example.com";
  the *broker* injects the credential via the Brave browser extension (see
  `extension/`) driven by a native-messaging host (`brave-vault-injector`). The
  agent never receives plaintext — the credential flows broker → native host →
  extension → form, filled only on the credential's own origin. Gold standard.
- **Just-in-time reveal.** The broker streams the plaintext to the agent's
  ephemeral subprocess for a single use, scoped and approval-gated. The agent
  briefly sees it. Pragmatic fallback for "the agent must type it itself."

---

## Architecture overview

```
                    ┌───────────────────────────────────────────┐
                    │        Brave Vault app (BROKER)             │
                    │  - holds mnemonic + BRAVE_SERVICES_KEY      │
                    │  - unlocked, encrypted-at-rest vault        │
                    │  - approval UI (popup)                      │
                    │  - grant store (pre-created + ad-hoc)       │
                    │  - audit log                                │
                    │                                             │
                    │   ┌───────────────────────────────────┐    │
   agent  ── IPC ──▶│   │  Local broker endpoint            │    │
 (holds handle,     │   │  (unix socket / named pipe)       │    │
  not the secret)   │   └───────────────────────────────────┘    │
                    └───────────────────────────────────────────┘
                                     │
                         brave_vault_core (unchanged core:
                         session / sync / commit / vault)
```

Key components to build:

- **Broker service** — a local IPC endpoint hosted *inside* the Vault app (which
  is already the only process that unlocks the vault). Not a network service.
- **`brave-vault-agent` CLI** — the binary the agent actually runs. Holds only a
  handle; talks to the broker over the local socket; can request a grant, reveal
  an item once, or ask the broker to *use* an item.
- **Grant store** — records of capabilities: scope (which items), action
  (`reveal`/`use`), TTL, use-count, pre-approval flag, provenance. Persisted
  encrypted in the existing vault file.
- **Approval UI** — a Tauri window/popup the broker raises to ask the user
  "Agent X wants the password for example.com — allow once / allow 5 min /
  deny."
- **Audit log** — append-only record of issuance and use.

---

## Core concepts / data model

### Handle (long-lived, provisioned once)

```
handle_id:       opaque random id (safe to log/pass around)
handle_secret:   high-entropy secret, stored in OS keychain on the agent host,
                 NEVER printed after creation; agent proves possession per call
label:           human name ("Claude research agent on laptop")
created / last_used / revoked
default_policy:  what this handle is allowed to ask for without a fresh popup
                 (may be "nothing — always prompt")
```

A handle by itself unlocks nothing. It authenticates the *asker*.

### Grant (short-lived capability, the "one-time token")

```
grant_id
handle_id:       who it was issued to
scope:           explicit item id(s) — reuse existing id scheme:
                   pw:<realm>|<user>  /  bm:<guid>  /  id:<guid>
action:          "reveal" (return plaintext once) | "use" (broker performs)
ttl:             seconds (short — default 60)
max_uses:        default 1
uses_remaining
created / expires / consumed
approved_by:     "user-popup" | "pre-created" | "handle-policy"
```

The grant is what may briefly cross into the agent (for `reveal`) — or never
does (for `use`).

### Pre-created grant (the user sets it up ahead of time)

Same shape as a grant, but issued from the app UI before the agent asks — e.g.
"allow my research agent to read the example.com login, up to 10 times over the
next 24h." Stored in the grant store, consumed like any other grant. No popup at
use time (that was the point of pre-creating), but every use is still audited.

---

## Protocol sketch (agent ↔ broker)

Local IPC (unix domain socket on macOS/Linux, named pipe on Windows). No TCP.
Every request carries `handle_id` + a per-request proof of `handle_secret`
(HMAC over a broker-issued nonce, so the raw secret never crosses the wire).

```
agent → broker:  HELLO {handle_id}
broker → agent:  NONCE {nonce}
agent → broker:  REQUEST {
                   handle_id, mac(nonce, handle_secret),
                   scope: "pw:https://example.com/|alice",
                   action: "reveal" | "use",
                   reason: "logging into example.com to check X"
                 }
broker:          - verify handle + mac
                 - match a pre-created grant? -> use it (no popup)
                 - else raise approval popup (unless handle policy pre-allows)
broker → agent:  GRANT {grant_id, ttl}          # capability minted
--- for action=reveal ---
agent → broker:  CONSUME {grant_id}
broker → agent:  SECRET {value}                 # streamed once, then invalidated
--- for action=use ---
agent → broker:  PERFORM {grant_id, target}     # e.g. "open+fill example.com"
broker:          performs the action itself; agent gets only success/failure
```

Notes:
- For `reveal`, the CLI should write the secret to a **pipe/fd or clipboard**,
  not argv or a file, to minimize leakage surface. Never echo to stdout by
  default.
- All timestamps come from the broker; the agent host clock is untrusted.

---

## CLI surface (`brave-vault-agent`)

```
brave-vault-agent request \
    --item "example.com" \        # resolved to an item id by the broker
    --action reveal|use \
    --reason "..."                # shown in the approval popup / audit log
# -> prints grant_id + ttl (NOT the secret)

brave-vault-agent reveal --grant <grant_id>
# -> streams the secret to a fd/clipboard once; then the grant is dead

brave-vault-agent use --grant <grant_id> [--target <url>] [--via inject|clipboard]
# -> broker performs the action; prints success/failure only.
# --via inject (default) fills the form via the browser extension (the agent
#   never sees the password); --via clipboard is an explicit, clearly-labeled
#   opt-in (readable by other local apps).

brave-vault-agent list-grants          # what am I currently allowed to do
brave-vault-agent whoami               # handle label, policy
```

Provisioning (run by the *user*, in the app or a privileged CLI — never the
agent): `brave-vault-agent enroll --label "..."` → creates a handle, stores the
secret in the OS keychain, prints only the `handle_id`.

---

## Implementation status

Phases 1–6 are implemented in this repo:

- **`crates/core/src/agent/`** — `model` (handles, grants, `decide`),
  `auth` (HMAC challenge-response + id/secret generation), `protocol` (wire
  messages + endpoint path), `resolve` (human query → item ids). Unit-tested.
- **`crates/core/src/vault`** — `VaultData` gained `agent_handles`,
  `agent_grants`, `agent_audit`, persisted encrypted-at-rest.
- **`crates/core/src/agent/transport.rs`** — the cross-platform local IPC
  transport (via the `interprocess` crate): unix domain sockets on macOS/Linux,
  named pipes on Windows, behind one blocking `Listener`/`connect` API. A
  `tests/transport_roundtrip.rs` integration test exercises a real bind →
  connect → exchange on whatever platform runs the tests. All three crates
  compile clean for `x86_64-pc-windows-msvc` as well as the host.
- **`crates/app/src-tauri/src/broker.rs`** — the local IPC broker: listener
  started at app launch (via `transport::Listener`), HELLO/NONCE handshake,
  handle auth, grant matching (pre-created + policy), approval-popup bridge,
  single-use `reveal`, and broker-performs `use` (extension injection by
  default; explicit clipboard opt-in). Holds the injector job registry that
  rendezvous the agent's `PERFORM` with the injector host's `AWAITJOB`.
- **`crates/injector-host/`** (`brave-vault-injector`) — the Brave native-
  messaging host: bridges the broker and the extension, authenticating as the
  injector-kind handle. Chrome-framed stdio to the browser; unix socket to the
  broker.
- **`extension/`** — the Brave MV3 extension: background worker (native
  messaging + tab matching) and content script (origin-guarded form fill).
- **`crates/agent-cli/`** (`brave-vault-agent`) — the binary agents run:
  `enroll` / `whoami` / `forget` / `ping` / `request` / `reveal` / `use` /
  `list-grants`. Handle secret lives in the OS keychain; `reveal` copies to the
  clipboard by default (never stdout unless `--print`); `use` defaults to
  `--via inject`.
- The shared broker IPC client lives in **`crates/core/src/agent/client.rs`**,
  reused by both the agent CLI and the injector host.
- **App UI (`App.jsx`)** — an "Agents" panel to view/revoke handles, pre-create
  grants, view live grants, and read the audit log; plus a global approval popup
  wired to the `agent://approval-request` event.

Phase 9 (session grab) is also implemented: `Action::Session`, origin-scoped
grants, the `grab-session` CLI, the `GrabJob`/`SessionResult` protocol, and the
extension's `optional_host_permissions` + `chrome.cookies.getAll` path.

Remaining: Phase 0 sign-off, Phase 7 hardening (rate limits, peer-cred checks,
global kill-switch), running the app/browser under a separate OS user for true
isolation, and the optional Phase 8 MCP wrapper. The browser end (extension
`connectNative`, form fill, cookie grab) is verified by manual QA only — it
cannot be automated headlessly.

## Phased plan

Each phase builds on the last and is shippable on its own. Earlier phases
deliver value even if later phases slip.

### Phase 0 — Design lock-in & threat-model review
- Ratify this document with the team; confirm the two delivery modes
  (broker-performs vs just-in-time reveal) and the IPC transport choice.
- Decide the OS keychain integration per platform (macOS Keychain, Windows
  Credential Manager, libsecret on Linux).
- **Exit:** signed-off spec; no code yet.

### Phase 1 — Broker IPC skeleton (no secrets yet)
- Add a local IPC listener inside the Tauri app (unix socket / named pipe),
  started only while the vault is unlocked. Torn down on lock.
- Implement `HELLO`/`NONCE` handshake and a no-op `PING`.
- Add the `brave-vault-agent` crate with `whoami`/`ping` talking to the broker.
- **Exit:** agent CLI can round-trip a ping to the running app; nothing
  sensitive is exposed.

### Phase 2 — Handle enrollment & authentication
- Implement handle creation (`enroll`): random id + secret, secret stored in OS
  keychain on the agent host; broker persists the handle record (hashed secret)
  in the encrypted vault file (new `agent_handles` field on `VaultData`).
- Implement per-request HMAC proof over the broker nonce.
- Add revoke/list handles in the app UI.
- **Exit:** an enrolled agent authenticates; a revoked handle is rejected.

### Phase 3 — Grant store + ad-hoc approval popup
- Add the grant data model + encrypted persistence (`agent_grants` on
  `VaultData`).
- Implement `REQUEST` → raise a Tauri approval popup ("Agent X wants
  reveal/use of <item> because <reason>: Deny / Allow once / Allow N min").
- Mint a single-use, short-TTL grant on approval.
- **Exit:** agent requests an item, user approves in a popup, agent receives a
  `grant_id` (still no secret delivered).

### Phase 4 — `reveal` delivery (just-in-time, single-use)
- Implement `CONSUME` → resolve the item via the existing `Session`/vault,
  stream the plaintext once to the agent over the socket, then mark the grant
  consumed.
- CLI writes the secret to an fd/clipboard, never stdout/argv by default.
- Enforce TTL + single-use + scope on the broker side.
- **Exit:** end-to-end "agent asks → user approves → agent gets the one password
  once, and only that one, and only once."

### Phase 5 — Pre-created grants (user sets it up ahead of time)
- App UI to mint grants proactively: pick item(s), action, TTL window,
  max-uses, target handle.
- `REQUEST` matches an existing pre-created grant and skips the popup (still
  audited).
- **Exit:** user pre-authorizes an item; agent later uses it with no live
  prompt; every use is logged.

### Phase 6 — `use` delivery (broker-performs / never-reveal)
- Implement `PERFORM`: the broker carries out the privileged action so the
  plaintext never enters the agent. Two channels, chosen by `--via`:
  - **`inject` (default, zero-knowledge):** the broker hands the credential to a
    Brave browser extension via a native-messaging host (`brave-vault-injector`,
    a new crate). The host long-polls the broker (`AWAITJOB`), gated to an
    injector-kind handle so an ordinary agent can never register as the injector
    or receive the plaintext `JOB`. The extension fills the form only on the
    credential's own origin (checked in the broker, the background worker, and
    the content script). The app auto-provisions the injector handle + keychain
    secret + native-messaging manifest on startup.
  - **`clipboard` (explicit opt-in):** open URL + copy password to the clipboard.
    NOT zero-knowledge — any local process can read the clipboard — so it is
    labeled that way in the audit log. There is no silent fallback to this path.
- **Exit:** agent triggers a login to a site and never sees the password.
- **Same-user caveat:** the injector secret lives in the OS keychain under a
  distinct service, so impersonating the injector requires keychain access, not
  just socket access. No software boundary fully stops a same-user attacker;
  true isolation would run the app/browser under a separate OS user (future).

### Phase 7 — Audit log, revocation & policy hardening
- Append-only audit log (issuance + every consume/perform) surfaced in the app.
- Instant revoke of handles and grants; a live "agent activity" view.
- Rate limits, per-handle default policies, and a global kill-switch.
- **Exit:** the user can see exactly what agents did and cut them off instantly.

### Phase 8 (optional) — MCP / standard-agent integration
- Wrap the agent CLI as an MCP server (or equivalent) so LLM agents can call
  `request`/`reveal`/`use` as tools with the same broker guarantees.
- **Exit:** a Claude/other agent uses the vault through the broker with no raw
  secret in its context.

### Phase 9 — Session grab (reuse a logged-in browser session)
- Motivation: 2FA sites can't be re-logged-in by an agent. Instead, grab the
  **live session cookies** for an approved origin set from a logged-in browser
  and let the agent replay them. Implemented as a third action, `Action::Session`.
- A `session` request targets a comma-separated **host set** (not a vault item),
  so it bypasses `resolve` and always prompts. On approval the broker mints an
  origin-scoped grant (`scope = ["origin:<host>", ...]`).
- `grab-session` dispatches a `GrabJob` to the injector; the extension grabs the
  cookies and returns them (`SessionResult`), which the broker returns to the
  agent (`Response::Session`). Cookies are **not** stored — a one-shot live grab.
- **Browser-enforced scope is the guarantee:** the extension holds no standing
  cookie/host access; it requests `optional_host_permissions` for exactly the
  approved hosts at grab time, and Brave prompts + refuses all others (e.g. a
  bank) at the sandbox level.
- **Bearer-token caveat:** a grabbed session is full-account access until it
  expires; origin-scoping controls *which* session the agent gets, not what it
  does with it. Short TTL + single-use + revoke bound the exposure. For an API-
  backed service (e.g. Gmail), a scoped OAuth token is preferable to cookie grab.
- **Exit:** agent authorizes and reuses a logged-in session for an approved host
  set, and cannot read cookies for any other origin.

---

## Cross-cutting decisions to settle early

- **Transport:** unix socket + named pipe (chosen over TCP to avoid a network
  surface), implemented once via the `interprocess` crate so a single code path
  serves macOS, Linux, and Windows. Peer credential checks (SO_PEERCRED /
  equivalent) where available remain a Phase 7 hardening item.
- **Keychain per platform:** macOS Keychain / Windows Credential Manager /
  libsecret. Fallback behavior if unavailable = refuse to store, force
  always-prompt.
- **Item resolution:** the agent passes a human string ("example.com"); the
  broker resolves it to a concrete item id and, if ambiguous, forces the popup
  so the user disambiguates.
- **Default TTL / max-uses:** 60s / 1 use for ad-hoc; user-configurable for
  pre-created.
- **Secret delivery channel:** fd/clipboard, never argv/stdout/tempfile.
- **Clock authority:** broker only.
- **Vault password:** the current hardcoded `"testing"` must be replaced before
  any of this ships for real — the broker's security rests on the vault being
  genuinely locked.

---

## What we deliberately do NOT do

- No long-lived bearer token handed to the agent.
- No network-exposed broker endpoint.
- No storing secrets (grants/handles) in plaintext or in the agent's env/argv.
- No unscoped "read the whole vault" grant.
```