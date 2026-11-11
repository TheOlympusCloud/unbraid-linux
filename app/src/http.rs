//! Minimal blocking HTTPS client shared by providers: size-capped bodies, the certificate name always checked.
//! A transient DNS failure gets one more try. Every call blocks; run them off the window's thread.

use crate::error::{Error, Result};
use crate::redact;
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use reqwest::{Method, redirect};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{verify_server_cert_signed_by_trust_anchor, verify_server_name};
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::ParsedCertificate;
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use std::io::Read;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, LazyLock};
use std::thread;
use std::time::Duration;
use url::{Host, Url};

const MAX_BODY: usize = 8 << 20;

pub fn get(url: &str, headers: &[(&str, &str)], tls: Option<&RootCertStore>, verify_host: Option<&str>) -> Result<String> {
    call(Method::GET, url, headers, None, tls, verify_host)
}

pub fn delete(url: &str, headers: &[(&str, &str)]) -> Result<String> {
    call(Method::DELETE, url, headers, None, None, None)
}

/// Parses a provider reply. JSON errors quote the input, which may hold tokens or keys, so they are replaced by a fixed
/// message with no cause.
pub fn parsed<T>(what: &str, f: impl FnOnce() -> serde_json::Result<T>) -> Result<T> {
    f().map_err(|_| Error::Fail(format!("Unexpected reply from {what}. Try again later")))
}

/// What a failed sign-in at `provider` tells the user: the reason when the app knows it, never a reply's own text.
pub fn explain(e: &(dyn std::error::Error + 'static), provider: &str) -> String {
    let own = || {
        let m = redact::clean(&e.to_string());
        if m.trim().is_empty() { format!("{provider} didn't accept these details") } else { m }
    };
    match e.downcast_ref::<Error>() {
        Some(Error::Invalid(_) | Error::Auth { .. } | Error::Fail(_) | Error::NoLongerOffered(_)) => own(),
        // A JSON error is input that couldn't be used, like any other.
        None if e.is::<serde_json::Error>() => own(),
        Some(Error::Status { code: 429 }) => format!("{provider} has had too many attempts. Wait a few minutes and try again"),
        Some(Error::Status { code }) => format!("{provider} couldn't sign you in right now (error {code}). Try again later"),
        Some(Error::Io(_) | Error::Challenge(_)) => format!("Couldn't reach {provider}. Check the connection."),
        None if e.is::<std::io::Error>() => format!("Couldn't reach {provider}. Check the connection."),
        _ => format!("Something went wrong signing in to {provider}. Try again"),
    }
}

pub fn post_form(url: &str, form: &[(&str, &str)], headers: &[(&str, &str)]) -> Result<String> {
    let body = form.iter().map(|(k, v)| enc(k) + "=" + &enc(v)).collect::<Vec<_>>().join("&");
    call(Method::POST, url, headers, Some((body, "application/x-www-form-urlencoded")), None, None)
}

/// `s` encoded for a form or a query: letters, digits and `.-*_` as they are, a space as `+`, the rest as `%XX`.
pub fn enc(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// A TLS setup that checks the server's certificate against the name it was made for in the handshake itself
/// (RFC 2818, as browsers do): `verify_host` when given, whatever address the connection goes to, else the host
/// connected to. `tls` replaces the system's trust store (e.g. a provider's pinned CA).
pub fn named(tls: Option<&RootCertStore>, verify_host: Option<&str>) -> Result<ClientConfig> {
    let roots = tls.map_or_else(|| SYSTEM.clone(), |r| Arc::new(r.clone()));
    // A name no certificate can hold fails like a handshake would.
    let name = verify_host.map(|h| ServerName::try_from(h.to_string()).map_err(|_| Error::Io(format!("Invalid host name: {h}")))).transpose()?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let algs = provider.signature_verification_algorithms;
    Ok(ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::State(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Named { roots, name, algs }))
        .with_no_client_auth())
}

/// The system's CA certificates, read once.
static SYSTEM: LazyLock<Arc<RootCertStore>> = LazyLock::new(|| {
    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    Arc::new(roots)
});

/// Checks a server's certificate: its chain up to `roots`, then the name (`name` when given, else the host connected
/// to) among its DNS names or, when it has none, in its CN, as RFC 2818 allows. PIA's certificates name the server in
/// the CN only.
#[derive(Debug)]
struct Named {
    roots: Arc<RootCertStore>,
    name: Option<ServerName<'static>>,
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for Named {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let cert = ParsedCertificate::try_from(end_entity)?;
        verify_server_cert_signed_by_trust_anchor(&cert, &self.roots, intermediates, now, self.algs.all)?;
        let name = match &self.name {
            Some(n) => n,
            None => server_name,
        };
        match verify_server_name(&cert, name) {
            Err(rustls::Error::InvalidCertificate(CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. }))
                if common_name(end_entity, name) => {}
            r => r?,
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// OIDs (DER contents) of subjectAltName and of the CN.
const SAN: &[u8] = &[0x55, 0x1d, 0x11];
const CN: &[u8] = &[0x55, 0x04, 0x03];

/// Whether `cert`, which has no DNS name in its subjectAltName, names `name` in its subject's most specific CN: the
/// whole name, letter case aside, and never with a wildcard. An address is only ever checked against IP names.
fn common_name(cert: &[u8], name: &ServerName<'_>) -> bool {
    let ServerName::DnsName(name) = name else { return false };
    let Some((subject, false)) = subject_and_dns_names(cert) else { return false };
    most_specific_cn(subject).is_some_and(|cn| cn.eq_ignore_ascii_case(name.as_ref()))
}

/// A certificate's subject, and whether its subjectAltName holds any DNS name; none if it can't be read.
fn subject_and_dns_names(cert: &[u8]) -> Option<(&[u8], bool)> {
    let (0x30, cert, _) = der(cert)? else { return None };
    let (0x30, tbs, _) = der(cert)? else { return None };
    let mut fields = items(tbs)?;
    if fields.first()?.0 == 0xa0 {
        fields.remove(0); // the version
    }
    // Serial, signature algorithm, issuer, validity, subject, key, then the optional unique IDs and extensions ([3]).
    let (0x30, subject) = *fields.get(4)? else { return None };
    let mut dns = false;
    if let Some(&(_, extensions)) = fields.iter().find(|(tag, _)| *tag == 0xa3) {
        let (0x30, list, _) = der(extensions)? else { return None };
        for (_, extension) in items(list)? {
            let extension = items(extension)?;
            if extension.first() == Some(&(0x06, SAN)) {
                let &(0x04, value) = extension.last()? else { return None };
                let (0x30, names, _) = der(value)? else { return None };
                dns = items(names)?.iter().any(|(tag, _)| *tag == 0x82);
            }
        }
    }
    Some((subject, dns))
}

/// The first CN of the last relative name that has one, as text.
fn most_specific_cn(subject: &[u8]) -> Option<&str> {
    let mut cn = None;
    for (_, rdn) in items(subject)? {
        let mut first = None;
        for (_, attribute) in items(rdn)? {
            if let [(0x06, oid), (kind, value)] = items(attribute)?[..]
                && oid == CN
            {
                first = first.or(Some((kind, value)));
            }
        }
        cn = first.or(cn);
    }
    // UTF8String, PrintableString, T61String or IA5String: the string types a host name comes in.
    let (kind, value) = cn?;
    if matches!(kind, 0x0c | 0x13 | 0x14 | 0x16) { std::str::from_utf8(value).ok() } else { None }
}

/// The DER element at the start of `d`: its tag, its contents and what follows it.
fn der(d: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, d) = d.split_first()?;
    let (&first, d) = d.split_first()?;
    let (len, d) = match first {
        0..=0x7f => (first as usize, d),
        0x81..=0x84 => {
            let (bytes, d) = d.split_at_checked((first & 0x7f) as usize)?;
            (bytes.iter().fold(0usize, |a, &b| a << 8 | b as usize), d)
        }
        _ => return None,
    };
    // Tags of more than one byte never occur where this reads.
    if tag & 0x1f == 0x1f {
        return None;
    }
    let (contents, rest) = d.split_at_checked(len)?;
    Some((tag, contents, rest))
}

/// The elements of a constructed DER value: all of them, or none if one can't be read.
fn items(mut d: &[u8]) -> Option<Vec<(u8, &[u8])>> {
    let mut all = Vec::new();
    while !d.is_empty() {
        let (tag, contents, rest) = der(d)?;
        all.push((tag, contents));
        d = rest;
    }
    Some(all)
}

/// `tls` replaces the trust store (e.g. a provider's pinned CA); `verify_host` checks the certificate against that
/// name instead of the URL host (needed when connecting to a server by IP).
fn call(
    method: Method,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<(String, &str)>,
    tls: Option<&RootCertStore>,
    verify_host: Option<&str>,
) -> Result<String> {
    // The URL is left out of errors: it may carry a token.
    let url = Url::parse(url).map_err(|e| Error::Io(format!("Invalid URL: {e}")))?;
    if url.scheme() != "https" {
        return Err(Error::Invalid("HTTPS only".into()));
    }
    let addrs = match addresses(&url) {
        Err(_) => {
            thread::sleep(Duration::from_millis(1500));
            addresses(&url)?
        }
        Ok(addrs) => addrs,
    };
    once(method, &url, &addrs, headers, body, tls, verify_host)
}

/// The addresses of `url`'s host, looked up before connecting so that a failed lookup can be told apart.
fn addresses(url: &Url) -> Result<Vec<SocketAddr>> {
    let Some(Host::Domain(host)) = url.host() else { return Ok(vec![]) };
    let port = url.port_or_known_default().unwrap_or(443);
    (host, port).to_socket_addrs().map(Iterator::collect).map_err(|e| Error::Io(format!("{host}: {e}")))
}

fn once(
    method: Method,
    url: &Url,
    addrs: &[SocketAddr],
    headers: &[(&str, &str)],
    body: Option<(String, &str)>,
    tls: Option<&RootCertStore>,
    verify_host: Option<&str>,
) -> Result<String> {
    let mut client = Client::builder()
        .tls_backend_preconfigured(named(tls, verify_host)?)
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(15))
        .no_proxy()
        // Redirects stay on HTTPS: one elsewhere ends the call with its 3xx.
        .redirect(redirect::Policy::custom(|a| {
            if a.url().scheme() != "https" {
                a.stop()
            } else if a.previous().len() > 20 {
                a.error("Too many redirects")
            } else {
                a.follow()
            }
        }));
    if let Some(Host::Domain(host)) = url.host() {
        client = client.resolve_to_addrs(host, addrs);
    }
    let mut h = HeaderMap::new();
    h.insert(ACCEPT, HeaderValue::from_static("application/json"));
    for (k, v) in headers {
        h.insert(HeaderName::from_bytes(k.as_bytes()).map_err(|e| Error::Invalid(e.to_string()))?, value(v)?);
    }
    let mut request = client.build().map_err(io)?.request(method, url.clone());
    if let Some((body, kind)) = body {
        h.insert(CONTENT_TYPE, value(kind)?);
        request = request.body(body);
    }
    let reply = request.headers(h).send().map_err(io)?;
    let code = reply.status().as_u16();
    if code == 401 {
        return Err(Error::Auth { message: "Sign-in was refused".into(), url: None });
    }
    if !(200..=299).contains(&code) {
        return Err(Error::Status { code });
    }
    let mut b = Vec::new();
    reply.take(MAX_BODY as u64 + 1).read_to_end(&mut b)?;
    if b.len() > MAX_BODY {
        return Err(Error::Io("Response too large".into()));
    }
    Ok(String::from_utf8_lossy(&b).into_owned())
}

fn value(v: &str) -> Result<HeaderValue> {
    HeaderValue::from_str(v).map_err(|e| Error::Invalid(e.to_string()))
}

/// A failed exchange as one line, its causes included and the URL left out (it may carry a token).
fn io(e: reqwest::Error) -> Error {
    let e = e.without_url();
    let mut text = e.to_string();
    let mut cause = std::error::Error::source(&e);
    while let Some(c) = cause {
        text = format!("{text}: {c}");
        cause = c.source();
    }
    Error::Io(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{ServerConfig, ServerConnection, StreamOwned};
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;

    /// Sign-in failures say what happened, in the app's own words; a provider's reply text never reaches the screen.
    #[test]
    fn sign_in_failures_are_explained() {
        fn x(e: &(dyn std::error::Error + 'static)) -> String {
            explain(e, "Mullvad")
        }
        assert_eq!("Mullvad has had too many attempts. Wait a few minutes and try again", x(&Error::Status { code: 429 }));
        assert_eq!("Mullvad couldn't sign you in right now (error 503). Try again later", x(&Error::Status { code: 503 }));
        assert_eq!("Couldn't reach Mullvad. Check the connection.", x(&Error::Io("api.mullvad.net".into())));
        assert_eq!("Couldn't reach Mullvad. Check the connection.", x(&Error::Io("timeout".into())));
        assert_eq!("Sign-in was refused", x(&Error::Auth { message: "Sign-in was refused".into(), url: None }));
        let parse = parsed("Mullvad", || serde_json::from_str::<HashMap<String, i32>>("{\"token\":\"secret-value\"}")).unwrap_err();
        assert_eq!("Unexpected reply from Mullvad. Try again later", x(&parse));
        let unknown: Box<dyn std::error::Error + Send + Sync> = "o[k] secret-value".into();
        assert_eq!("Something went wrong signing in to Mullvad. Try again", x(&*unknown));
        assert_eq!("That account number isn't valid", x(&Error::Invalid("That account number isn't valid".into())));
    }

    /// A key and a self-signed certificate for `cn` (and `san` when given), made at test time.
    fn keys(cn: &str, san: Option<&str>) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let mut params = rcgen::CertificateParams::new(san.map(|s| vec![s.to_string()]).unwrap_or_default()).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(rcgen::DnType::CommonName, cn);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        (cert.der().clone(), PrivatePkcs8KeyDer::from(key.serialize_der()).into())
    }

    fn trusting(cert: &CertificateDer<'static>) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(cert.clone()).unwrap();
        roots
    }

    /// An HTTPS server on 127.0.0.1 answering "{}" to every request, for as long as the tests run; its port.
    fn serving(cert: CertificateDer<'static>, key: PrivateKeyDer<'static>) -> u16 {
        let tls = Arc::new(
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![cert], key)
                .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for tcp in listener.incoming().flatten() {
                let mut s = BufReader::new(StreamOwned::new(ServerConnection::new(tls.clone()).unwrap(), tcp));
                let mut line = String::new();
                while s.read_line(&mut line).is_ok_and(|n| n > 2) {
                    line.clear();
                }
                let mut s = s.into_inner();
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
                s.conn.send_close_notify();
                let _ = s.flush();
            }
        });
        port
    }

    /// A server reached by its address, its certificate checked against a name the caller gives (PIA's, whose
    /// certificates name the server in CN only): that name passes, another doesn't, and the address never counts.
    #[test]
    fn http_checks_the_given_name() {
        let (cert, key) = keys("unbraid-test", None);
        let url = format!("https://127.0.0.1:{}/addKey", serving(cert.clone(), key));
        assert_eq!("{}", get(&url, &[], Some(&trusting(&cert)), Some("unbraid-test")).unwrap());
        let e = get(&url, &[], Some(&trusting(&cert)), Some("other-test")).unwrap_err();
        assert!(matches!(&e, Error::Io(m) if m.contains("certificate not valid for name")), "{e:?}");
    }

    /// The CN counts only for a certificate with no DNS name, only as the whole name and never for an address; and
    /// nothing counts before the chain is trusted.
    #[test]
    fn a_common_name_counts_only_where_rfc_2818_allows() {
        let name = |n: &str| ServerName::try_from(n.to_string()).unwrap();
        let (cn_only, _) = keys("unbraid-test", None);
        assert!(common_name(&cn_only, &name("unbraid-test")));
        assert!(common_name(&cn_only, &name("UNBRAID-Test")));
        assert!(!common_name(&cn_only, &name("other-test")));
        assert!(!common_name(&cn_only, &name("unbraid-test.example")));
        assert!(!common_name(&cn_only, &name("127.0.0.1")));
        assert!(!common_name(&keys("unbraid-test", Some("other-test")).0, &name("unbraid-test")));
        assert!(!common_name(&keys("*.unbraid.test", None).0, &name("a.unbraid.test")));

        let (cert, key) = keys("unbraid-test", None);
        let url = format!("https://127.0.0.1:{}/", serving(cert.clone(), key));
        assert!(get(&url, &[], Some(&trusting(&cert)), None).is_err());
        let stranger = keys("unbraid-test", None).0;
        let e = get(&url, &[], Some(&trusting(&stranger)), Some("unbraid-test")).unwrap_err();
        assert!(matches!(&e, Error::Io(m) if m.contains("invalid peer certificate")), "{e:?}");
    }
}
