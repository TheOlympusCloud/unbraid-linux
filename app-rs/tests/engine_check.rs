//! The real engine (engine/build.sh) checks every config the compiler's tests compiled, made Linux configs: what the
//! app would run must be what the engine accepts. Run after `cargo test --lib`, which keeps those configs under
//! `target/compiled*`; skipped while the engine isn't built (`UNBRAID_ENGINE_BIN`).

use serde_json::{Value, json};
use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tonic::transport::Channel;
use unbraid::apps::Matchers;
use unbraid::compiler::{Input, compile};
use unbraid::engine::{Engine, channel};
use unbraid::engine_api::daemon::started_service_client::StartedServiceClient;
use unbraid::engine_api::desktop::StartServiceRequest;
use unbraid::engine_api::desktop::desktop_service_client::DesktopServiceClient;
use unbraid::linux_pass;
use unbraid::model::{DIRECT, Link, Location, Route, Server, Setup, SsProfile};

const OUT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/target");

/// The engine to run, if it is built: $UNBRAID_ENGINE_BIN, else the one engine/build.sh built.
fn engine() -> Option<PathBuf> {
    let built = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../engine/out/unbraid-engine"));
    let p = std::env::var_os("UNBRAID_ENGINE_BIN").map_or(built, PathBuf::from);
    std::fs::metadata(&p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0).then_some(p)
}

fn apps(k: &str) -> Matchers {
    if k.starts_with('/') {
        Matchers { paths: vec![k.into()], ..Matchers::default() }
    } else {
        Matchers { dirs: vec![format!("/opt/{k}/")], names: vec![k.rsplit('.').next().unwrap_or(k).into()], ..Matchers::default() }
    }
}

/// The JSON files in `dir`, by name.
fn configs(dir: &Path) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .map(|p| (p.file_name().unwrap().to_string_lossy().into_owned(), std::fs::read_to_string(&p).unwrap()))
        .collect();
    out.sort();
    out
}

#[tokio::test]
async fn engine_accepts_every_linux_config() {
    let Some(bin) = engine() else {
        eprintln!("skipped: the engine isn't built (UNBRAID_ENGINE_BIN)");
        return;
    };
    let golden = configs(Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/compiler")));
    let golden = golden.into_iter().filter(|(n, _)| n.starts_with("golden-") && n != "golden-cache-keys.json");
    let (raw_golden, linux_golden): (Vec<_>, Vec<_>) = golden.partition(|(n, _)| n.starts_with("golden-raw-"));
    let android: Vec<(String, String)> = configs(&Path::new(OUT).join("compiled"))
        .into_iter()
        .chain(raw_golden)
        .map(|(n, c)| (n, linux_pass::config(&c, apps, Some("/usr/lib/unbraid/bin/unbraid"))))
        .collect();
    let linux: Vec<(String, String)> = configs(&Path::new(OUT).join("compiled-linux")).into_iter().chain(linux_golden).collect();
    assert!(android.len() > 50 && !linux.is_empty(), "run the other tests first (cargo test --lib)");
    let tmp = tempfile::tempdir().unwrap();
    let e = Engine::new(&tmp.path().join("none.sock"), &bin, tmp.path());
    let mut refused = vec![];
    for (name, c) in android.iter().chain(&linux) {
        if let Err(s) = e.check(c).await {
            refused.push(format!("{name}: {}", s.message()));
        }
    }
    assert_eq!(Vec::<String>::new(), refused);
    eprintln!("the engine accepted {} configs", android.len() + linux.len());
    // And it really checks: an unknown option is refused.
    assert!(e.check(&linux[0].1.replace("\"find_process\"", "\"find_processes\"")).await.is_err());
}

fn port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// A web server that answers with the address it saw.
fn echo() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            let _ = s.read(&mut [0; 4096]);
            let ip = s.peer_addr().map(|a| a.ip().to_string()).unwrap_or_default();
            let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{ip}", ip.len());
        }
    });
    port
}

/// The engine, run as this user: without a TUN it needs no root, and it then looks up processes as the system service
/// does, from the computer's own user namespace (a sandboxed one may not read other namespaces' processes).
struct Daemon {
    child: Child,
    channel: Channel,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn daemon(bin: &Path, dir: &Path, name: &str) -> Daemon {
    let (work, socket) = (dir.join(format!("{name}-work")), dir.join(format!("{name}.sock")));
    std::fs::create_dir_all(&work).unwrap();
    let log = File::create(Path::new(OUT).join(format!("engine-{name}.log"))).unwrap();
    let child = Command::new(bin)
        .args(["run", "--working-directory"])
        .arg(&work)
        .arg("--socket")
        .arg(&socket)
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(socket.exists(), "{name} engine didn't start: {}", std::fs::read_to_string(Path::new(OUT).join(format!("engine-{name}.log"))).unwrap_or_default());
    Daemon { child, channel: channel(&socket) }
}

async fn start(d: &Daemon, config: String) {
    DesktopServiceClient::new(d.channel.clone()).start_service(StartServiceRequest { config_content: config, options: None }).await.unwrap();
}

/// Per-app routing through the real engine: three programs (copies of curl, told apart by their paths, as the engine
/// tells apps apart) reach one echo server, which answers with the address it saw. The default route and route B are
/// Shadowsocks exits leaving from 127.0.0.2 and 127.0.0.3; Direct leaves from 127.0.0.1. A local proxy inbound stands in
/// for the TUN, which needs a real machine; everything behind it is the Linux config as the app compiles it.
#[tokio::test]
async fn each_program_leaves_through_its_own_exit() {
    let Some(bin) = engine() else {
        eprintln!("skipped: the engine isn't built (UNBRAID_ENGINE_BIN)");
        return;
    };
    if !Path::new("/usr/bin/curl").exists() {
        eprintln!("skipped: needs curl");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let echo = echo();
    let (p1, p2, proxy) = (port(), port(), port());
    let exits = daemon(&bin, tmp.path(), "exits");
    let routing = json!({
        "log": {"level": "warn"},
        "inbounds": [{"type": "shadowsocks", "tag": "ss1", "listen": "127.0.0.1", "listen_port": p1, "method": "aes-128-gcm", "password": "one"},
                     {"type": "shadowsocks", "tag": "ss2", "listen": "127.0.0.1", "listen_port": p2, "method": "aes-128-gcm", "password": "two"}],
        "outbounds": [{"type": "direct", "tag": "from2", "inet4_bind_address": "127.0.0.2"}, {"type": "direct", "tag": "from3", "inet4_bind_address": "127.0.0.3"}],
        "route": {"rules": [{"inbound": ["ss1"], "outbound": "from2"}, {"inbound": ["ss2"], "outbound": "from3"}]},
    });
    start(&exits, routing.to_string()).await;

    let bin_dir = tmp.path().join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    let curls: Vec<PathBuf> = ["curl-default", "curl-b", "curl-direct"]
        .iter()
        .map(|n| {
            let f = bin_dir.join(n);
            std::fs::copy("/usr/bin/curl", &f).unwrap();
            f
        })
        .collect();
    let path = |p: &PathBuf| p.to_string_lossy().into_owned();
    let ss = |name: &str, port: u16, password: &str| SsProfile {
        name: name.into(),
        server: "127.0.0.1".into(),
        port: port.into(),
        method: "aes-128-gcm".into(),
        password: password.into(),
        plugin: None,
        plugin_opts: None,
    };
    let setup = Setup {
        routes: vec![Route { ss: Some(ss("Exit A", p1, "one")), ..Route::new("a", Location::default()) }, Route { ss: Some(ss("Exit B", p2, "two")), hue: 1, ..Route::new("b", Location::default()) }],
        default_route: "a".into(),
        apps: [(path(&curls[1]), "b".to_string()), (path(&curls[2]), DIRECT.to_string())].into_iter().collect(),
        ..Setup::default()
    };
    let links = setup
        .active_routes()
        .iter()
        .map(|r| (r.id.clone(), Link::Ss { server: Server { name: r.name(), host: "127.0.0.1".into(), ip: "127.0.0.1".into(), ..Server::default() }, profile: r.ss.clone().unwrap() }))
        .collect();
    let input = Input::new(setup, links, "app.unbraid", true, "tailscale", "cache.db");
    let mut config: Value = serde_json::from_str(&linux_pass::config(&compile(&input).unwrap(), |k| Matchers { paths: vec![k.into()], ..Matchers::default() }, None)).unwrap();
    // At debug level the engine logs each connection's process and the rule it matched: kept for a failure, below.
    config["log"] = json!({"level": "debug"});
    for i in config["inbounds"].as_array_mut().unwrap() {
        if i["type"] == "tun" {
            *i = json!({"type": "mixed", "tag": "tun", "listen": "127.0.0.1", "listen_port": proxy});
        }
    }
    let app = daemon(&bin, tmp.path(), "app");
    start(&app, config.to_string()).await;

    let seen = |curl: &PathBuf| {
        let out = Command::new(curl)
            .args(["-s", "--max-time", "10", "--proxy", &format!("socks5://127.0.0.1:{proxy}"), &format!("http://127.0.0.1:{echo}/")])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    let got: Vec<String> = curls.iter().map(seen).collect();
    let mut lines = vec![];
    if let Ok(mut logs) = StartedServiceClient::new(app.channel.clone()).subscribe_log(()).await.map(|r| r.into_inner()) {
        let _ = tokio::time::timeout(Duration::from_secs(3), async {
            while let Ok(Some(l)) = logs.message().await
                && lines.len() < 400
            {
                lines.extend(l.messages.into_iter().map(|m| m.message));
            }
        })
        .await;
    }
    std::fs::write(Path::new(OUT).join("engine-routing.log"), lines.join("\n")).unwrap();
    assert_eq!(vec!["127.0.0.2", "127.0.0.3", "127.0.0.1"], got);
}
