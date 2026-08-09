//! Chrome/Brave native-messaging framing.
//!
//! Each message on the browser↔host stdio channel is a 4-byte little-endian
//! length prefix followed by that many bytes of UTF-8 JSON. The browser owns
//! this pipe, so it is private to the browser process — the agent cannot read
//! it.
//!
//! CRITICAL: nothing may be written to stdout except framed messages. A stray
//! `println!` corrupts the stream. All diagnostics must go to stderr.

use std::io::{self, Read, Write};

use serde_json::Value;

/// Read one framed message. Returns `Ok(None)` on clean EOF (the browser closed
/// the port — the host should exit).
pub fn read_message<R: Read>(r: &mut R) -> io::Result<Option<Value>> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    let v: Value =
        serde_json::from_slice(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(Some(v))
}

/// Write one framed message.
pub fn write_message<W: Write>(w: &mut W, msg: &Value) -> io::Result<()> {
    let bytes = serde_json::to_vec(msg)?;
    let len = u32::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "message too large"))?;
    w.write_all(&len.to_le_bytes())?;
    w.write_all(&bytes)?;
    w.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn round_trips_a_message() {
        let msg = json!({"type": "fill", "job_id": "j1", "ok": true});
        let mut buf = Vec::new();
        write_message(&mut buf, &msg).unwrap();
        // 4-byte length prefix + body.
        assert!(buf.len() > 4);
        let body_len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        assert_eq!(body_len, buf.len() - 4);

        let mut cursor = io::Cursor::new(buf);
        let back = read_message(&mut cursor).unwrap().unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn clean_eof_returns_none() {
        let mut empty = io::Cursor::new(Vec::new());
        assert!(read_message(&mut empty).unwrap().is_none());
    }

    #[test]
    fn two_messages_read_in_order() {
        let a = json!({"n": 1});
        let b = json!({"n": 2});
        let mut buf = Vec::new();
        write_message(&mut buf, &a).unwrap();
        write_message(&mut buf, &b).unwrap();
        let mut cursor = io::Cursor::new(buf);
        assert_eq!(read_message(&mut cursor).unwrap().unwrap(), a);
        assert_eq!(read_message(&mut cursor).unwrap().unwrap(), b);
        assert!(read_message(&mut cursor).unwrap().is_none());
    }
}
