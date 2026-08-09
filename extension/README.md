# Brave Vault Injector extension

Fills logins requested by the Brave Vault app via its native-messaging host
(`brave-vault-injector`). The credential flows broker → native host → this
extension → the page's form. It never reaches an automation agent, and it is
only ever filled on the exact origin the credential belongs to (checked in the
broker, the background worker, and again in the content script).

## Load for development

1. Build the host binary: `cargo build -p brave_vault_injector`.
2. Run the Brave Vault app once so it writes the native-messaging manifest and
   the injector sidecar.
3. In Brave: `brave://extensions` → enable Developer mode → **Load unpacked** →
   select this `extension/` directory.
4. Note the extension id Brave assigns. Two values must match for the host to
   launch:
   - `allowed_origins` in the native-messaging manifest
     (`~/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts/com.brave.vault.injector.json`),
     written from `EXTENSION_ID` in `crates/app/src-tauri/src/injector.rs`.
   - The `key` in `manifest.json`, which pins the id across machines.

   For a stable id, set `manifest.json`'s `key` to a fixed public key and set
   `EXTENSION_ID` to the id it produces, then rebuild the app so the manifest is
   rewritten.

## Test

There is no headless test for the browser side. Manual QA:

- Request a `use` grant, approve it, and confirm the login form fills on the
  real origin.
- Point an explicit `--target` at a different origin and confirm the fill is
  refused (origin mismatch).
- Confirm the agent never receives the password (only `done: ...`).
