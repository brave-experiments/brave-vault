//! Thin client for talking to the local broker over the IPC endpoint.
//!
//! Uses the cross-platform transport in [`super::transport`] (unix domain
//! sockets on macOS/Linux, named pipes on Windows). Messages are newline-
//! delimited JSON (see [`super::protocol`]).
//!
//! Lives in core (rather than the agent CLI) so every trusted client — the
//! agent CLI *and* the browser-injector native-messaging host — shares one
//! connect/HELLO/proof implementation. Errors are plain `String`s to keep core
//! free of an `anyhow` dependency.

use std::io::{BufRead, BufReader, Write};

use super::protocol::{self, Request, Response};
use super::transport::{self, Conn};

/// A connected broker session. Holds the last nonce the broker issued so the
/// caller can compute HMAC proofs.
pub struct Broker {
    conn: Conn,
    pub nonce: Option<String>,
}

impl Broker {
    /// Connect to the running broker. Fails clearly if the app isn't running /
    /// unlocked (no endpoint to connect to).
    pub fn connect() -> Result<Self, String> {
        let conn = transport::connect().map_err(|e| {
            format!(
                "{e} (endpoint {})\nIs the Brave Vault app running and unlocked? \
                 The broker only listens while unlocked.",
                protocol::endpoint_path()
            )
        })?;
        Ok(Broker { conn, nonce: None })
    }

    fn send(&mut self, req: &Request) -> Result<(), String> {
        (&self.conn)
            .write_all(protocol::encode_line(req).as_bytes())
            .map_err(|e| format!("writing to broker: {e}"))?;
        (&self.conn)
            .flush()
            .map_err(|e| format!("flushing to broker: {e}"))?;
        Ok(())
    }

    fn recv(&mut self) -> Result<Response, String> {
        let mut reader = BufReader::new(&self.conn);
        let mut line = String::new();
        let n = reader
            .read_line(&mut line)
            .map_err(|e| format!("reading from broker: {e}"))?;
        if n == 0 {
            return Err("broker closed the connection".into());
        }
        protocol::decode_line::<Response>(&line)
    }

    /// One request → one response round-trip.
    pub fn call(&mut self, req: &Request) -> Result<Response, String> {
        self.send(req)?;
        self.recv()
    }

    /// Perform HELLO and stash the returned nonce for later proof computation.
    pub fn hello(&mut self, handle_id: &str) -> Result<(), String> {
        match self.call(&Request::Hello {
            handle_id: handle_id.to_string(),
        })? {
            Response::Nonce { nonce } => {
                self.nonce = Some(nonce);
                Ok(())
            }
            Response::Error { message } => Err(message),
            other => Err(format!("unexpected reply to HELLO: {other:?}")),
        }
    }

    pub fn nonce(&self) -> Result<&str, String> {
        self.nonce
            .as_deref()
            .ok_or_else(|| "no nonce; call hello() first".to_string())
    }
}
