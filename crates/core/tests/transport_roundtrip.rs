//! End-to-end transport round-trip: bind, connect, exchange one line. Runs on
//! whatever platform the tests are executed on (unix socket / Windows pipe).
use std::io::{BufRead, BufReader, Write};

use brave_vault_core::agent::transport::{connect, Listener};

#[test]
fn round_trip_line() {
    let listener = Listener::bind().expect("bind");
    let server = std::thread::spawn(move || {
        let conn = listener.incoming().next().unwrap().expect("accept");
        let mut reader = BufReader::new(&conn);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert_eq!(line, "ping\n");
        (&conn).write_all(b"pong\n").unwrap();
        (&conn).flush().unwrap();
    });

    // Give the listener a moment to be ready, retrying the connect.
    let mut conn = None;
    for _ in 0..50 {
        match connect() {
            Ok(c) => {
                conn = Some(c);
                break;
            }
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(20)),
        }
    }
    let conn = conn.expect("connect");
    (&conn).write_all(b"ping\n").unwrap();
    (&conn).flush().unwrap();
    let mut reader = BufReader::new(&conn);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert_eq!(line, "pong\n");
    server.join().unwrap();
}
