//! The app's own connections out through one chosen exit ([`crate::compiler::PROBE`]): an HTTP CONNECT to the engine's
//! loopback proxy, whose user name picks the tunnel, then TLS with the system's certificates and the host name checked.

use crate::error::{Error, Result};
use crate::vpn::live;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, RootCertStore};
use std::io::{self, BufReader, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpStream};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// A socket another thread can close at any time: a connect, read or write blocked on it then ends at once, and once
/// closed it never connects. Clones are the same socket.
#[derive(Clone, Default)]
pub struct Raw(Arc<Mutex<(bool, Option<TcpStream>)>>);

impl PartialEq for Raw {
    fn eq(&self, other: &Raw) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Raw {
    pub fn close(&self) {
        let mut s = lock(&self.0);
        s.0 = true;
        if let Some(t) = &s.1 {
            let _ = t.shutdown(Shutdown::Both);
        }
    }

    fn connect(&self, to: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
        let closed = || io::Error::new(io::ErrorKind::NotConnected, "Socket closed");
        if lock(&self.0).0 {
            return Err(closed());
        }
        let t = TcpStream::connect_timeout(&to, timeout)?;
        let mut s = lock(&self.0);
        if s.0 {
            return Err(closed());
        }
        s.1 = Some(t.try_clone()?);
        Ok(t)
    }
}

/// A TLS connection through an exit. One thread may read `input` while another writes `output`; `close` ends both from
/// any thread.
pub struct Conn {
    pub input: BufReader<Input>,
    pub output: Output,
    pub raw: Raw,
}

impl Conn {
    pub fn close(&self) {
        self.raw.close();
    }
}

/// What a [`Conn`] receives, decrypted.
pub struct Input {
    tls: Arc<Mutex<ClientConnection>>,
    tcp: TcpStream,
    /// Received and not yet taken by TLS, which holds only so much undelivered data.
    pending: Vec<u8>,
    eof: bool,
}

impl Read for Input {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            {
                let mut c = lock(&self.tls);
                while !self.pending.is_empty() {
                    match c.read_tls(&mut &self.pending[..]) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => drop(self.pending.drain(..n)),
                    }
                    c.process_new_packets().map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                }
                if self.eof && self.pending.is_empty() {
                    let _ = c.read_tls(&mut io::empty());
                }
                match c.reader().read(buf) {
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock && !self.eof => {}
                    // A server that closes without TLS's goodbye ends the stream all the same, as the earlier app read it.
                    Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::UnexpectedEof) => {
                        return Ok(0);
                    }
                    r => return r,
                }
            }
            // Nothing decrypted yet: wait for the network without holding the connection, so the writer goes on.
            let mut more = [0u8; 1 << 14];
            match self.tcp.read(&mut more)? {
                0 => self.eof = true,
                n => self.pending.extend_from_slice(&more[..n]),
            }
        }
    }
}

/// What a [`Conn`] sends, encrypted and on its way at once.
pub struct Output {
    tls: Arc<Mutex<ClientConnection>>,
    tcp: TcpStream,
    sealed: Vec<u8>,
}

impl Write for Output {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.sealed.clear();
        let n = {
            let mut c = lock(&self.tls);
            let n = c.writer().write(buf)?;
            while c.wants_write() {
                c.write_tls(&mut self.sealed)?;
            }
            n
        };
        self.tcp.write_all(&self.sealed)?;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tcp.flush()
    }
}

/// A TLS connection to `host` through the tunnel `tag`; fails if the VPN isn't on or the exit doesn't answer. Closing
/// `raw` from another thread ends a blocked attempt at once. `tls` replaces the system's trust store (tests).
pub fn open(tag: &str, host: &str, port: u16, timeout_ms: u64, raw: &Raw, tls: Option<&RootCertStore>) -> Result<Conn> {
    let (proxy_port, password) = live().probe().ok_or_else(|| Error::State("Connect first".into()))?;
    let conn = (|| {
        let timeout = Duration::from_millis(timeout_ms);
        let mut tcp = raw.connect(SocketAddr::from((Ipv4Addr::LOCALHOST, proxy_port)), timeout)?;
        tcp.set_read_timeout(Some(timeout))?;
        let auth = BASE64.encode(format!("{tag}:{password}"));
        tcp.write_all(
            format!(
                "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nProxy-Authorization: Basic {auth}\r\n\r\n"
            )
            .as_bytes(),
        )?;
        let status = head(&mut tcp)?.into_iter().next().unwrap_or_default();
        if status.split(' ').nth(1) != Some("200") {
            return Err(Error::State("The exit didn't connect".into()));
        }
        let name =
            ServerName::try_from(host.to_string()).map_err(|_| Error::Io(format!("Invalid host name: {host}")))?;
        let mut c = ClientConnection::new(Arc::new(crate::http::named(tls, None)?), name)
            .map_err(|e| Error::Io(e.to_string()))?;
        while c.is_handshaking() {
            c.complete_io(&mut tcp)?;
        }
        let tls = Arc::new(Mutex::new(c));
        let input = Input { tls: tls.clone(), tcp: tcp.try_clone()?, pending: Vec::new(), eof: false };
        Ok(Conn {
            input: BufReader::with_capacity(1 << 16, input),
            output: Output { tls, tcp, sealed: Vec::new() },
            raw: raw.clone(),
        })
    })();
    if conn.is_err() {
        raw.close();
    }
    conn
}

/// Runs the blocking `f` on a fresh socket, off the caller's thread; dropping the future (a cancel) closes that socket,
/// so `f` ends at once instead of after its timeouts.
pub async fn cancellable<T: Send + 'static>(f: impl FnOnce(&Raw) -> Result<T> + Send + 'static) -> Result<T> {
    struct Closing(Raw);
    impl Drop for Closing {
        fn drop(&mut self) {
            self.0.close();
        }
    }
    let raw = Raw::default();
    let _closing = Closing(raw.clone());
    tokio::task::spawn_blocking(move || f(&raw)).await.unwrap_or_else(|e| Err(Error::State(e.to_string())))
}

/// A small HTTPS GET through `tag`; the body as text, at most `max` bytes (the server is trusted no further).
pub fn get(tag: &str, host: &str, path: &str, max: usize, accept: &str, raw: &Raw) -> Result<String> {
    let mut c = open(tag, host, 443, 10_000, raw, None)?;
    let body = (|| {
        c.output.write_all(
            format!("GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: unbraid\r\nAccept: {accept}\r\n\r\n")
                .as_bytes(),
        )?;
        let status = head(&mut c.input)?.into_iter().next().unwrap_or_default();
        if status.split(' ').nth(1) != Some("200") {
            return Err(Error::State(format!(
                "HTTP {}",
                status.split_once(' ').map_or(status.as_str(), |(_, rest)| rest)
            )));
        }
        let mut body = Vec::new();
        (&mut c.input).take(max as u64 + 1).read_to_end(&mut body)?;
        if body.len() > max {
            return Err(Error::Io("Response too large".into()));
        }
        Ok(String::from_utf8_lossy(&body).into_owned())
    })();
    c.close();
    body
}

/// One TCP handshake with `host` through `tag`, in ms: the engine's SOCKS5 side answers only once its own connection
/// to the server is up, so the wait is one round trip through the tunnel (Ookla's "ping"). No data, no TLS.
pub fn handshake_ms(tag: &str, host: &str, port: u16) -> Result<i64> {
    let (proxy_port, password) = live().probe().ok_or_else(|| Error::State("Connect first".into()))?;
    let mut s =
        TcpStream::connect_timeout(&SocketAddr::from((Ipv4Addr::LOCALHOST, proxy_port)), Duration::from_secs(5))?;
    s.set_nodelay(true)?;
    s.set_read_timeout(Some(Duration::from_secs(5)))?;
    let refused = || Error::State("Proxy refused".into());
    s.write_all(&[5, 1, 2])?; // SOCKS5, user name and password (RFC 1929)
    if byte(&mut s)? != 5 || byte(&mut s)? != 2 {
        return Err(refused());
    }
    let (u, p) = (tag.as_bytes(), password.as_bytes());
    s.write_all(&[&[1, u.len() as u8], u, &[p.len() as u8], p].concat())?;
    if byte(&mut s)? != 1 || byte(&mut s)? != 0 {
        return Err(refused());
    }
    let h = host.as_bytes();
    let start = Instant::now();
    s.write_all(&[&[5, 1, 0, 3, h.len() as u8], h, &port.to_be_bytes()].concat())?;
    byte(&mut s)?;
    if byte(&mut s)? != 0 {
        return Err(Error::State("The server didn't answer".into()));
    }
    Ok((start.elapsed().as_nanos() as i64 + 500_000) / 1_000_000)
}

fn byte(s: &mut impl Read) -> io::Result<u8> {
    let mut b = [0u8];
    s.read_exact(&mut b)?;
    Ok(b[0])
}

/// Reads an HTTP head byte by byte (never past it), as its lines.
pub fn head(input: &mut impl Read) -> io::Result<Vec<String>> {
    let mut b = Vec::new();
    while !b.ends_with(b"\r\n\r\n") {
        let mut one = [0u8];
        match input.read_exact(&mut one) {
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            r => r?,
        }
        if b.len() > 16_384 {
            break;
        }
        b.push(one[0]);
    }
    let text: String = b.iter().map(|&c| c as char).collect();
    Ok(text.split("\r\n").filter(|l| !l.is_empty()).map(String::from).collect())
}

/// An error's kind, for logs: its message can hold an address.
pub(crate) fn kind(e: &Error) -> &'static str {
    match e {
        Error::Auth { .. } => "Auth",
        Error::Challenge(_) => "Challenge",
        Error::NoLongerOffered(_) => "NoLongerOffered",
        Error::Fail(_) => "Fail",
        Error::Status { .. } => "Status",
        Error::Io(_) => "Io",
        Error::Invalid(_) => "Invalid",
        Error::State(_) => "State",
    }
}

/// The lock, even if a thread panicked while holding it.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{ServerConfig, ServerConnection, StreamOwned};
    use std::net::TcpListener;
    use std::thread;

    type Served = StreamOwned<ServerConnection, TcpStream>;

    /// The probe setting is the whole process's: tests that use it take turns.
    static TURN: Mutex<()> = Mutex::new(());

    /// Stands in for the engine's probe proxy on 127.0.0.1: it answers CONNECT, then is the server itself (a
    /// certificate for unbraid.test, made now) and does `serve`. Its port, and a trust store with that certificate.
    fn proxy(serve: fn(&mut Served)) -> (u16, RootCertStore) {
        let mut params = rcgen::CertificateParams::new(vec!["unbraid.test".to_string()]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(rcgen::DnType::CommonName, "unbraid.test");
        let key = rcgen::KeyPair::generate().unwrap();
        let cert: CertificateDer<'static> = params.self_signed(&key).unwrap().der().clone();
        let key: PrivateKeyDer<'static> = PrivatePkcs8KeyDer::from(key.serialize_der()).into();
        let tls = Arc::new(
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![cert.clone()], key)
                .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for mut s in listener.incoming().flatten() {
                let tls = tls.clone();
                thread::spawn(move || {
                    let _ = head(&mut s);
                    let _ = s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n");
                    serve(&mut StreamOwned::new(ServerConnection::new(tls).unwrap(), s));
                });
            }
        });
        let mut roots = RootCertStore::empty();
        roots.add(cert).unwrap();
        (port, roots)
    }

    /// `host` through the proxy on `port`.
    fn through(port: u16, host: &str, roots: &RootCertStore) -> Result<Conn> {
        let _turn = lock(&TURN);
        let was = live().probe();
        live().set_probe(Some((port, "test".into())));
        let c = open("direct", host, 443, 10_000, &Raw::default(), Some(roots));
        live().set_probe(was);
        c
    }

    /// The app's way into an exit: a server's certificate counts for its own name, and only for it.
    #[test]
    fn probe_checks_the_servers_name() {
        let (port, roots) = proxy(|t| drop(t.read(&mut [0u8])));
        assert!(through(port, "unbraid.test", &roots).map(|c| c.close()).is_ok());
        let other = through(port, "other.test", &roots).err();
        assert!(matches!(&other, Some(Error::Io(m)) if m.contains("certificate not valid for name")), "{other:?}");
    }

    /// One thread reads while another writes, as the upload does; a server that closes without TLS's goodbye ends the
    /// stream as one that says it.
    #[test]
    fn a_connection_reads_while_it_writes() {
        let (port, roots) = proxy(|t| {
            let (mut got, mut buf) = (0, vec![0u8; 1 << 16]);
            while got < 4 << 20 {
                match t.read(&mut buf) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => got += n,
                }
            }
            let _ = t.write_all(&[7u8; 1 << 20]);
            let _ = t.flush();
        });
        let Conn { mut input, mut output, raw } = through(port, "unbraid.test", &roots).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let mut all = Vec::new();
            let _ = tx.send(input.read_to_end(&mut all).map(|_| all));
        });
        for _ in 0..64 {
            output.write_all(&[1u8; 1 << 16]).unwrap();
        }
        let got = rx.recv_timeout(Duration::from_secs(20)).expect("the reader ends").unwrap();
        assert_eq!(1 << 20, got.len());
        assert!(got.iter().all(|b| *b == 7));
        raw.close();
    }
}
