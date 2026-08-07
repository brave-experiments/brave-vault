//! Thin client for talking to the local broker over the IPC endpoint.
//!
//! Uses the cross-platform transport in `brave_vault_core::agent::transport`
//! (unix domain sockets on macOS/Linux, named pipes on Windows). Messages are
//! newline-delimited JSON (see `brave_vault_core::agent::protocol`).

use std::io::{BufRead, BufReader, Write};

use anyhow::{anyhow, Context, Result};
use brave_vault_core::agent::protocol::{self, Request, Response};
use brave_vault_core::agent::transport::{self, Conn};

/// A connected broker session. Holds the last nonce the broker issued so the
/// caller can compute HMAC proofs.
pub struct Broker {
    conn: Conn,
    pub nonce: Option<String>,
}

impl Broker {
    /// Connect to the running broker. Fails clearly if the app isn't running /
    /// unlocked (no endpoint to connect to).
    pub fn connect() -> Result<Self> {
        let conn = transport::connect().map_err(|e| {
            anyhow!(
                "{e} (endpoint {})\nIs the Brave Vault app running and unlocked? \
                 The broker only listens while unlocked.",
                protocol::endpoint_path()
            )
        })?;
        Ok(Broker { conn, nonce: None })
    }

    fn send(&mut self, req: &Request) -> Result<()> {
        (&self.conn)
            .write_all(protocol::encode_line(req).as_bytes())
            .context("writing to broker")?;
        (&self.conn).flush()?;
        Ok(())
    }

    fn recv(&mut self) -> Result<Response> {
        let mut reader = BufReader::new(&self.conn);
        let mut line = String::new();
        let n = reader.read_line(&mut line).context("reading from broker")?;
        if n == 0 {
            return Err(anyhow!("broker closed the connection"));
        }
        protocol::decode_line::<Response>(&line).map_err(|e| anyhow!(e))
    }

    /// One request → one response round-trip.
    pub fn call(&mut self, req: &Request) -> Result<Response> {
        self.send(req)?;
        self.recv()
    }

    /// Perform HELLO and stash the returned nonce for later proof computation.
    pub fn hello(&mut self, handle_id: &str) -> Result<()> {
        match self.call(&Request::Hello {
            handle_id: handle_id.to_string(),
        })? {
            Response::Nonce { nonce } => {
                self.nonce = Some(nonce);
                Ok(())
            }
            Response::Error { message } => Err(anyhow!(message)),
            other => Err(anyhow!("unexpected reply to HELLO: {other:?}")),
        }
    }

    pub fn nonce(&self) -> Result<&str> {
        self.nonce
            .as_deref()
            .ok_or_else(|| anyhow!("no nonce; call hello() first"))
    }
}
