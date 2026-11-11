//! M-Lab's ndt7 speed test (measurementlab.net; protocol: github.com/m-lab/ndt-server, spec/ndt7-protocol.md) through
//! one exit: locate a server, measure [`ping`], then ten seconds of download and ten of upload over a WebSocket.

use crate::clock::elapsed_realtime;
use crate::error::{Error, Result};
use crate::probe::{self, Conn, Raw};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use rand::RngCore;
use regex::Regex;
use serde_json::{Map, Value};
use sha1::{Digest, Sha1};
use std::cell::Cell;
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{LazyLock, Mutex, MutexGuard, mpsc};
use std::thread;
use std::time::Duration;
use url::Url;

/// `others`: Locate's other candidates, tried in turn when this one turns the test away.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Server {
    pub machine: String,
    pub city: String,
    pub country: String,
    pub download: String,
    pub upload: String,
    pub others: Vec<Server>,
}

/// Why the test server turned the WebSocket away ([`refused`]); another of Locate's candidates may not.
pub const REFUSED: &str = "The test server refused the test";

/// Locate answered 204 (an HTTP 204 from [`locate`]): M-Lab limits tests per address, and this exit's (often a VPN
/// server's, shared) is used up.
pub fn limited(e: &Error) -> bool {
    matches!(e, Error::Status { code: 204 })
}

/// The test server turned the test away: another of Locate's candidates may not.
pub fn refused(e: &Error) -> bool {
    matches!(e, Error::Io(m) if m == REFUSED)
}

const SECONDS: i64 = 10;
const LOCATE: &str = "locate.measurementlab.net";

/// The M-Lab server nearest the exit's own address, inside `country` when given; none if M-Lab has none there. Fails
/// [`limited`] when M-Lab is rate-limiting the exit's address.
pub fn locate(tag: &str, country: Option<&str>) -> Result<Option<Server>> {
    let q = client() + &country.map(|c| format!("&country={c}&strict=true")).unwrap_or_default();
    let body = match probe::get(tag, LOCATE, &format!("/v2/nearest/ndt/ndt7?{q}"), 256 * 1024, "application/json", &Raw::default()) {
        Err(Error::State(m)) if m.starts_with("HTTP 204") => return Err(Error::Status { code: 204 }),
        Err(Error::State(m)) if country.is_some() && m.starts_with("HTTP") => return Ok(None),
        r => r?,
    };
    let bad = || Error::Fail("Unexpected reply from M-Lab. Try again later".into());
    let reply: Value = serde_json::from_str(&body).map_err(|_| bad())?;
    let results = match reply.as_object().ok_or_else(bad)?.get("results") {
        None => vec![],
        Some(Value::Array(a)) => a.clone(),
        Some(_) => return Err(bad()),
    };
    let mut all = Vec::new();
    for r in &results {
        let r = r.as_object().ok_or_else(bad)?;
        let loc = match r.get("location") {
            None => None,
            Some(Value::Object(l)) => Some(l),
            Some(_) => return Err(bad()),
        };
        let urls = r.get("urls").and_then(Value::as_object).ok_or_else(bad)?;
        let field = |o: Option<&Map<String, Value>>, k: &str| o.map_or(Ok(String::new()), |o| str(o, k)).map_err(|_| bad());
        all.push(Server {
            machine: field(Some(r), "machine")?,
            city: field(loc, "city")?,
            country: field(loc, "country")?,
            download: field(Some(urls), "wss:///ndt/v7/download")?,
            upload: field(Some(urls), "wss:///ndt/v7/upload")?,
            others: vec![],
        });
    }
    if all.is_empty() {
        return Ok(None);
    }
    let mut first = all.remove(0);
    first.others = all;
    Ok(Some(first))
}

/// A field as text, numbers and `null` as written; empty when missing.
fn str(o: &Map<String, Value>, k: &str) -> std::result::Result<String, ()> {
    match o.get(k) {
        None => Ok(String::new()),
        Some(Value::String(s)) => Ok(s.clone()),
        Some(Value::Array(_) | Value::Object(_)) => Err(()),
        Some(v) => Ok(v.to_string()),
    }
}

/// Who is testing, kept by the server with the result; a combined run adds how many exits shared the line.
fn client() -> String {
    format!("client_name=unbraid&client_version={}", crate::VERSION_NAME)
}

/// Ping in ms: the median of five, and the lowest and highest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ping {
    pub median: i32,
    pub low: i32,
    pub high: i32,
}

/// Ookla-style ping: five TCP handshakes with the test server through the exit, after one untimed connection that
/// resolves its name. Measured by the app: many M-Lab sites sit behind a cloud proxy, so the server's own round-trip
/// figure only sees the proxy next to it. The median shrugs off one slow handshake, unlike the mean.
pub fn ping(tag: &str, server: &Server) -> Result<Ping> {
    let host = Url::parse(&server.download).ok().and_then(|u| u.host_str().map(String::from)).ok_or_else(|| Error::Invalid("No test server address".into()))?;
    probe::handshake_ms(tag, &host, 443)?;
    let mut ms = (0..5).map(|_| probe::handshake_ms(tag, &host, 443).map(|m| (m as i32).max(1))).collect::<Result<Vec<_>>>()?;
    ms.sort();
    Ok(Ping { median: ms[2], low: ms[0], high: ms[4] })
}

/// Receives until the server ends the test; `rate` gets bits/s every quarter second. `sample` gets the time
/// (elapsed-realtime ms) and running count at most every 20 ms and at the end (`extra` URL parameters tag a combined run).
pub fn download(tag: &str, url: &str, stop: impl Fn() -> bool, extra: &str, sample: impl Fn(i64, i64), rate: impl Fn(i64)) -> Result<i64> {
    let mut c = socket(tag, url, extra)?;
    let start = elapsed_realtime();
    let (got, noted) = (Cell::new(0i64), Cell::new(start));
    let count = |n: i64| {
        got.set(got.get() + n);
        let now = elapsed_realtime();
        if now - noted.get() >= 20 {
            noted.set(now);
            sample(now, got.get());
        }
    };
    sample(start, 0);
    let bps = (|| {
        let mut scratch = vec![0u8; 1 << 16];
        let mut told = start;
        while !stop() && elapsed_realtime() - start < (SECONDS + 3) * 1000 {
            let Some((op, len)) = header(&mut c.input)? else { break };
            match op {
                8 => break,
                // The server's own reports; the app counts what it receives.
                1 => {
                    count(len);
                    skip(&mut c.input, len)?;
                }
                9 => {
                    let p = payload(&mut c.input, len)?;
                    frame(&mut c.output, 10, &p, p.len())?;
                }
                _ => {
                    let mut left = len;
                    while left > 0 && !stop() {
                        let n = c.input.read(&mut scratch[..left.min(1 << 16) as usize])?;
                        if n == 0 {
                            break;
                        }
                        left -= n as i64;
                        count(n as i64);
                    }
                }
            }
            let now = elapsed_realtime();
            if now - told >= 250 {
                told = now;
                rate(got.get() * 8000 / (now - start).max(1));
            }
        }
        sample(elapsed_realtime(), got.get());
        Ok(got.get() * 8000 / (elapsed_realtime() - start).max(1))
    })();
    c.close();
    unlive(&c.raw);
    bps
}

/// Sends for ten seconds; the rate is what the server says it received (its TCPInfo), not what left the app's
/// buffers. The live figure falls back to bytes sent until the server's first report. `sample` gets the server's
/// received count as each report arrives, timed by the server's own clock from the connection's start.
pub fn upload(tag: &str, url: &str, stop: impl Fn() -> bool, extra: &str, sample: impl Fn(i64, i64) + Sync, rate: impl Fn(i64)) -> Result<i64> {
    let mut c = socket(tag, url, extra)?;
    let opened = elapsed_realtime();
    sample(opened, 0);
    let server = AtomicI64::new(-1);
    // Only the sending loop writes: the reader leaves the server's pings here for it, so neither ever waits on the other.
    let pong = Mutex::new(None::<Vec<u8>>);
    let (input, output, raw) = (&mut c.input, &mut c.output, &c.raw);
    let bps = thread::scope(|scope| {
        let (ended, reader_ended) = mpsc::channel::<()>();
        // The server reports what it has received a few times a second, as text messages; read them alongside.
        scope.spawn(|| {
            let _ended = ended;
            let _ = (|| -> Option<()> {
                loop {
                    let (op, len) = header(input).ok()??;
                    // Data isn't expected while uploading: never buffered.
                    if op == 0 || op == 2 {
                        skip(input, len).ok()?;
                        continue;
                    }
                    let p = payload(input, len).ok()?;
                    match op {
                        8 => return Some(()),
                        9 => *lock(&pong) = Some(p),
                        1 => {
                            let text = String::from_utf8_lossy(&p);
                            let t = text.split_once("\"TCPInfo\"").map_or("", |(_, t)| t);
                            let got = BYTES_RECEIVED.captures(t).map(|g| g[1].parse::<i64>()).transpose().ok()?;
                            let us = ELAPSED.captures(t).map(|g| g[1].parse::<i64>()).transpose().ok()?;
                            if let (Some(got), Some(us)) = (got, us)
                                && us > 0
                            {
                                server.store(got.wrapping_mul(8_000_000) / us, Ordering::SeqCst);
                                sample(opened + us / 1000, got);
                            }
                        }
                        _ => {}
                    }
                }
            })();
        });
        let sending = (|| {
            // Random bytes need no masking work: masking random data with any key leaves it just as random.
            let mut data = vec![0u8; 1 << 20];
            rand::rng().fill_bytes(&mut data);
            let start = elapsed_realtime();
            let (mut size, mut sent, mut told) = (1usize << 13, 0i64, start);
            while !stop() && elapsed_realtime() - start < SECONDS * 1000 {
                if let Some(p) = lock(&pong).take() {
                    frame(output, 10, &p, p.len())?;
                }
                frame(output, 2, &data, size)?;
                sent += size as i64;
                // The spec's message scaling.
                if size < data.len() && (size as i64) < sent / 16 {
                    size *= 2;
                }
                let now = elapsed_realtime();
                if now - told >= 250 {
                    told = now;
                    let s = server.load(Ordering::SeqCst);
                    rate(if s > 0 { s } else { sent * 8000 / (now - start).max(1) });
                }
            }
            let _ = frame(output, 8, &data, 0);
            let _ = reader_ended.recv_timeout(Duration::from_millis(1500));
            // What left the app may still sit in buffers: without the server's own count there is no honest result.
            match server.load(Ordering::SeqCst) {
                s if s > 0 => Ok(s),
                _ => Err(Error::Io("The test server didn't report the upload".into())),
            }
        })();
        raw.close();
        sending
    });
    unlive(&c.raw);
    bps
}

static BYTES_RECEIVED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#""BytesReceived":([0-9]+)"#).unwrap());
static ELAPSED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#""ElapsedTime":([0-9]+)"#).unwrap());

/// The tests' open sockets, so a cancel can close them under a blocked read or write.
static LIVE: Mutex<Vec<Raw>> = Mutex::new(Vec::new());

/// Ends whatever a test is doing on the network now.
pub fn abort() {
    lock(&LIVE).iter().for_each(Raw::close);
}

fn unlive(raw: &Raw) {
    lock(&LIVE).retain(|r| r != raw);
}

/// Opens the test's WebSocket (RFC 6455) through the exit and checks the server accepted it.
fn socket(tag: &str, url: &str, extra: &str) -> Result<Conn> {
    let u = Url::parse(url).map_err(|e| Error::Invalid(e.to_string()))?;
    let host = u.host_str().ok_or_else(|| Error::Invalid("No test server address".into()))?.to_string();
    let mut c = probe::open(tag, &host, u.port().unwrap_or(443), 15_000, &Raw::default(), None)?;
    lock(&LIVE).push(c.raw.clone());
    let upgraded = (|| {
        let mut nonce = [0u8; 16];
        rand::rng().fill_bytes(&mut nonce);
        let key = BASE64.encode(nonce);
        let client = client();
        let query = [u.query(), Some(client.as_str()), Some(extra).filter(|e| !e.is_empty())].into_iter().flatten().collect::<Vec<_>>().join("&");
        c.output.write_all(
            format!(
                "GET {}?{query} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: net.measurementlab.ndt.v7\r\nUser-Agent: unbraid/{}\r\n\r\n",
                u.path(),
                crate::VERSION_NAME
            )
            .as_bytes(),
        )?;
        let head = probe::head(&mut c.input)?;
        let accept = BASE64.encode(Sha1::digest(format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11")));
        let accepted = |l: &String| {
            l.get(..21).is_some_and(|p| p.eq_ignore_ascii_case("Sec-WebSocket-Accept:")) && l.split_once(':').map_or(l.as_str(), |(_, v)| v).trim() == accept
        };
        if head.first().and_then(|s| s.split(' ').nth(1)) != Some("101") || !head.iter().any(accepted) {
            return Err(Error::Io(REFUSED.into()));
        }
        Ok(())
    })();
    match upgraded {
        Ok(()) => Ok(c),
        Err(e) => {
            c.close();
            unlive(&c.raw);
            Err(e)
        }
    }
}

const MAX_MESSAGE: i64 = 1 << 20; // measurement messages are a few hundred bytes
const MAX_DATA: i64 = 1 << 25; // ndt7 data frames are at most 16 MiB

/// A frame's opcode and length (servers never mask theirs); none at the end of the stream. The length comes from the
/// server, so it is bounded: data frames are streamed past, but text and control frames are read into memory.
pub(crate) fn header(i: &mut impl Read) -> io::Result<Option<(u8, i64)>> {
    let mut b = [0u8; 2];
    match i.read_exact(&mut b[..1]) {
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        r => r?,
    }
    i.read_exact(&mut b[1..])?;
    let len = match b[1] & 0x7f {
        126 => {
            let mut l = [0u8; 2];
            i.read_exact(&mut l)?;
            u16::from_be_bytes(l) as i64
        }
        127 => {
            let mut l = [0u8; 8];
            i.read_exact(&mut l)?;
            i64::from_be_bytes(l)
        }
        l => l as i64,
    };
    if b[1] & 0x80 != 0 {
        skip(i, 4)?;
    }
    let op = b[0] & 0x0f;
    if len < 0 || len > if op == 2 || op == 0 { MAX_DATA } else { MAX_MESSAGE } {
        return Err(io::Error::other("Bad frame from the test server"));
    }
    Ok(Some((op, len)))
}

fn skip(i: &mut impl Read, n: i64) -> io::Result<()> {
    io::copy(&mut i.take(n as u64), &mut io::sink()).map(drop)
}

fn payload(i: &mut impl Read, n: i64) -> io::Result<Vec<u8>> {
    let mut p = vec![0u8; n as usize];
    i.read_exact(&mut p)?;
    Ok(p)
}

/// One final client frame, masked as the spec requires; the key is random, the payload sent as it is (see upload).
pub(crate) fn frame(o: &mut impl Write, op: u8, payload: &[u8], len: usize) -> io::Result<()> {
    let mut h = Vec::with_capacity(14);
    h.push(0x80 | op);
    if len < 126 {
        h.push(0x80 | len as u8);
    } else if len < 65536 {
        h.push(0x80 | 126);
        h.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        h.push(0x80 | 127);
        h.extend_from_slice(&(len as u64).to_be_bytes());
    }
    let mask: [u8; 4] = rand::random();
    h.extend_from_slice(&mask);
    o.write_all(&h)?;
    if op == 2 {
        o.write_all(&payload[..len])?;
    } else {
        // Pongs echo real bytes.
        o.write_all(&payload[..len].iter().enumerate().map(|(i, b)| b ^ mask[i % 4]).collect::<Vec<_>>())?;
    }
    o.flush()
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(b: &[u8]) -> io::Result<Option<(u8, i64)>> {
        header(&mut &b[..])
    }

    /// The opcode and the 7, 16 or 64-bit length of a server frame; a masked frame's key is skipped; the end of the stream is none.
    #[test]
    fn headers_carry_opcode_and_length() {
        assert_eq!(Some((2, 5)), h(&[0x82, 5]).unwrap());
        assert_eq!(Some((1, 300)), h(&[0x81, 126, 0x01, 0x2c]).unwrap());
        assert_eq!(Some((2, 70_000)), h(&[0x82, 127, 0, 0, 0, 0, 0, 1, 0x11, 0x70]).unwrap());
        assert_eq!(Some((1, 3)), h(&[0x81, 0x83, 9, 9, 9, 9]).unwrap());
        assert_eq!(None, h(&[]).unwrap());
    }

    /// The length comes from the server: text and control frames are held in memory, so they are capped far below data frames.
    #[test]
    fn oversized_frames_are_refused() {
        assert_eq!(Some((2, 1 << 25)), h(&[0x82, 127, 0, 0, 0, 0, 2, 0, 0, 0]).unwrap());
        assert_eq!(Some((1, 1 << 20)), h(&[0x81, 127, 0, 0, 0, 0, 0, 0x10, 0, 0]).unwrap());
        for b in [
            [0x82, 127, 0, 0, 0, 0, 2, 0, 0, 1],    // data over 32 MiB
            [0x81, 127, 0, 0, 0, 0, 0, 0x10, 0, 1], // text over 1 MiB
            [0x89, 127, 0, 0, 0, 0, 0, 0x10, 0, 1], // ping over 1 MiB
            [0x82, 127, 0x80, 0, 0, 0, 0, 0, 0, 0], // a negative 64-bit length
        ] {
            let e = h(&b).expect_err(&format!("accepted {b:?}"));
            assert_eq!("Bad frame from the test server", e.to_string());
        }
    }

    fn sent(op: u8, payload: &[u8], len: usize) -> Vec<u8> {
        let mut o = Vec::new();
        frame(&mut o, op, payload, len).unwrap();
        o
    }

    /// Client frames are final and masked, with the length in the shortest form; control frames carry their payload under the mask.
    #[test]
    fn frames_are_masked_and_sized() {
        let ping = b"hello";
        let f = sent(10, ping, 5);
        assert_eq!(0x8a, f[0]);
        assert_eq!(0x80 | 5, f[1]);
        let mask = &f[2..6];
        assert_eq!(ping.to_vec(), (0..5).map(|i| f[6 + i] ^ mask[i % 4]).collect::<Vec<_>>());
        assert_eq!(6 + 5, f.len());

        let close = sent(8, &[], 0);
        assert_eq!([0x88, 0x80], close[..2]);
        assert_eq!(6, close.len());

        let mid = sent(2, &[0; 300], 300);
        assert_eq!([0x82, 0x80 | 126, 1, 0x2c], mid[..4]);
        assert_eq!(4 + 4 + 300, mid.len());

        let big = sent(2, &vec![0; 70_000], 70_000);
        assert_eq!([0x82, 0x80 | 127, 0, 0, 0, 0, 0, 1, 0x11, 0x70], big[..10]);
        assert_eq!(10 + 4 + 70_000, big.len());
    }

    /// Only the first `len` bytes of a buffer are sent: the upload reuses one buffer for growing messages.
    #[test]
    fn only_len_bytes_are_sent() {
        assert_eq!(2 + 4 + 16, sent(2, &vec![0; 1 << 20], 16).len());
    }
}
