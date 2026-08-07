//! Cross-platform local IPC transport for the broker ↔ agent connection.
//!
//! Uses the `interprocess` crate so the same blocking API works on every
//! platform: unix domain sockets on macOS/Linux, named pipes on Windows. Never
//! TCP — this is a local-only channel between processes on one machine.
//!
//! The broker calls [`Listener::bind`] and iterates [`Listener::incoming`]; the
//! agent calls [`connect`]. Both sides get a [`Conn`] that implements
//! `Read + Write`, over which they speak the newline-JSON protocol.

use std::io;

#[cfg(not(windows))]
use interprocess::local_socket::GenericFilePath;
#[cfg(windows)]
use interprocess::local_socket::GenericNamespaced;
use interprocess::local_socket::{prelude::*, ListenerOptions, Name, Stream};

/// A live IPC connection. Both `Conn` and `&Conn` implement `Read` + `Write`
/// (like `TcpStream`), so one connection can be read via a `BufReader<&Conn>`
/// while writes go to another `&Conn` borrow — no socket cloning needed.
pub struct Conn(Stream);

impl io::Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&self.0).read(buf)
    }
}
impl io::Write for Conn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&self.0).write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        (&self.0).flush()
    }
}
impl io::Read for &Conn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&self.0).read(buf)
    }
}
impl io::Write for &Conn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&self.0).write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        (&self.0).flush()
    }
}

/// Resolve the platform-appropriate socket name.
///
/// - Windows: a namespaced name (backed by a named pipe), no filesystem path.
/// - Unix: a filesystem path under the user runtime dir (see [`socket_path`]).
fn endpoint_name() -> io::Result<Name<'static>> {
    #[cfg(windows)]
    {
        // Namespaced pipe name — the OS prefixes \\.\pipe\ for us.
        "brave-vault-broker.sock".to_ns_name::<GenericNamespaced>()
    }
    #[cfg(not(windows))]
    {
        let path = socket_path();
        // Leak to obtain a 'static Name; the path string lives for the process.
        let leaked: &'static str = Box::leak(path.into_boxed_str());
        leaked.to_fs_name::<GenericFilePath>()
    }
}

/// The unix socket filesystem path (also used to clean up a stale socket on
/// bind). Prefers `XDG_RUNTIME_DIR`, then `~/.brave_vault`, then `/tmp`.
#[cfg(not(windows))]
pub fn socket_path() -> String {
    if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
        if !dir.is_empty() {
            return format!("{dir}/brave-vault-broker.sock");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        return format!("{home}/.brave_vault/broker.sock");
    }
    "/tmp/brave-vault-broker.sock".to_string()
}

/// A human-readable label for the endpoint, for log/error messages.
pub fn endpoint_label() -> String {
    #[cfg(windows)]
    {
        r"\\.\pipe\brave-vault-broker.sock".to_string()
    }
    #[cfg(not(windows))]
    {
        socket_path()
    }
}

/// The broker-side listener.
pub struct Listener {
    inner: interprocess::local_socket::Listener,
}

impl Listener {
    /// Bind the local endpoint. On unix a stale socket file from a previous run
    /// is removed first; on Windows the namespace entry is managed by the OS.
    pub fn bind() -> io::Result<Self> {
        #[cfg(not(windows))]
        {
            let _ = std::fs::remove_file(socket_path());
            if let Some(parent) = std::path::Path::new(&socket_path()).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        let name = endpoint_name()?;
        let inner = ListenerOptions::new().name(name).create_sync()?;
        let listener = Listener { inner };
        listener.lock_down();
        Ok(listener)
    }

    /// Restrict the socket to the current user (owner-only) where the platform
    /// exposes filesystem permissions. No-op on Windows (the default named-pipe
    /// DACL already grants access to the creating user and administrators).
    fn lock_down(&self) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(socket_path(), std::fs::Permissions::from_mode(0o600));
        }
    }

    /// Iterate incoming connections. Each item is a `Conn` or an accept error.
    pub fn incoming(&self) -> impl Iterator<Item = io::Result<Conn>> + '_ {
        self.inner.incoming().map(|c| c.map(Conn))
    }
}

/// Agent-side connect to the running broker.
pub fn connect() -> io::Result<Conn> {
    let name = endpoint_name()?;
    Stream::connect(name).map(Conn)
}
