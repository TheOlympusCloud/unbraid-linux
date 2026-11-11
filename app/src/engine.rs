//! The engine: unbraid-engine, sing-box's Linux daemon running as a system service, over gRPC on its Unix socket. It is
//! what libbox's command server and clients are on Android, call for call; the daemon knows the app's user from the
//! socket.

use crate::engine_api::daemon::managed_service_client::ManagedServiceClient;
use crate::engine_api::daemon::started_service_client::StartedServiceClient;
use crate::engine_api::daemon::{
    ConnectionEvents, ServiceStatus, SetTailscaleExitNodeRequest, Status as EngineStatus, StunTestProgress,
    StunTestRequest, SubscribeConnectionsRequest, SubscribeStatusRequest, TailscaleLogoutRequest,
    TailscaleStatusUpdate, service_status,
};
use crate::engine_api::desktop::application_service_client::ApplicationServiceClient;
use crate::engine_api::desktop::desktop_service_client::DesktopServiceClient;
use crate::engine_api::desktop::{ConfigContent, DaemonOwnership, StartServiceRequest};
use hyper_util::rt::TokioIo;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tonic::{Code, Request, Status, Streaming};

/// The engine isn't there at all (service stopped or not installed), as opposed to one that refused something.
pub const MISSING: &str = "The unbraid engine isn't running. Start it with: sudo systemctl enable --now unbraid-engine";

/// The engine the app talks to ([`crate::paths::engine`]). Its first use must be inside the async runtime, where the
/// channel starts its task; the runtime folder exists by then (the app checks it at start).
pub fn get() -> &'static Engine {
    static ENGINE: LazyLock<Engine> = LazyLock::new(|| {
        let runtime = crate::paths::runtime().expect("the runtime folder is made at start");
        Engine::new(Path::new(&crate::paths::engine()), Path::new(&crate::paths::engine_binary()), runtime)
    });
    &ENGINE
}

/// A gRPC channel to the daemon on `socket`, connected on first use.
pub fn channel(socket: &Path) -> Channel {
    let path: PathBuf = socket.to_path_buf();
    // The URI is only a placeholder: every connection goes to the socket.
    Endpoint::from_static("http://[::]:0").connect_with_connector_lazy(tower::service_fn(move |_: Uri| {
        let p = path.clone();
        async move { Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(p).await?)) }
    }))
}

fn timed<T>(message: T, seconds: u64) -> Request<T> {
    let mut r = Request::new(message);
    r.set_timeout(Duration::from_secs(seconds));
    r
}

/// The call `f`, ended with DEADLINE_EXCEEDED after `seconds` even if the engine never answers.
async fn deadline<T>(seconds: u64, f: impl Future<Output = Result<T, Status>>) -> Result<T, Status> {
    tokio::time::timeout(Duration::from_secs(seconds), f)
        .await
        .unwrap_or_else(|_| Err(Status::deadline_exceeded("Deadline exceeded")))
}

/// The engine isn't there at all (service stopped or not installed), as opposed to one that refused something.
pub fn missing(e: &Status) -> bool {
    e.code() == Code::Unavailable
}

pub fn running(s: &ServiceStatus) -> bool {
    s.status == service_status::Type::Started as i32 || s.status == service_status::Type::Starting as i32
}

pub struct Engine {
    channel: Channel,
    engine_binary: PathBuf,
    runtime_dir: PathBuf,
    worker: Mutex<Option<(Child, Channel)>>,
}

impl Engine {
    /// The engine on `socket`; `engine_binary` runs the worker that checks configs, with its socket in `runtime_dir`.
    pub fn new(socket: &Path, engine_binary: &Path, runtime_dir: &Path) -> Engine {
        Engine {
            channel: channel(socket),
            engine_binary: engine_binary.into(),
            runtime_dir: runtime_dir.into(),
            worker: Mutex::new(None),
        }
    }

    fn desktop(&self) -> DesktopServiceClient<Channel> {
        DesktopServiceClient::new(self.channel.clone())
    }
    fn managed(&self) -> ManagedServiceClient<Channel> {
        ManagedServiceClient::new(self.channel.clone())
    }
    fn started(&self) -> StartedServiceClient<Channel> {
        StartedServiceClient::new(self.channel.clone())
    }

    /// Fails if the engine would refuse `config`, without stopping what runs: the system service replaces its running
    /// config only by stopping it first. Its message can quote the config, keys included: callers redact it.
    pub async fn check(&self, config: &str) -> Result<(), Status> {
        // A worker that won't start is the app's own failure, not a missing service ([`missing`]).
        let ch = self.worker().map_err(|e| Status::unknown(e.to_string()))?;
        let mut c = ApplicationServiceClient::new(ch);
        deadline(30, c.check_config(timed(ConfigContent { content: config.into() }, 30))).await.map(|_| ())
    }

    /// The engine's unprivileged worker (`unbraid-engine worker`), which checks configs as this user. It must be the
    /// app's own child, says READY once it serves, and quits with the app (when its stdin closes).
    fn worker(&self) -> std::io::Result<Channel> {
        let mut w = self.worker.lock().unwrap();
        if let Some((child, ch)) = w.as_mut()
            && child.try_wait().ok().flatten().is_none()
        {
            return Ok(ch.clone());
        }
        let socket = self.runtime_dir.join("worker.sock");
        let child = start_worker(&self.engine_binary, &socket, 20)?;
        let ch = channel(&socket);
        *w = Some((child, ch.clone()));
        Ok(ch)
    }

    /// Runs `config` in place of whatever runs. A service another user on this computer started is taken over first,
    /// which polkit lets the user allow.
    pub async fn start(&self, config: &str) -> Result<(), Status> {
        let request = StartServiceRequest { config_content: config.into(), options: None };
        // 120 s: with nobody owning it the engine asks polkit first, which away from the session at the screen is a password.
        // The calls own their clients and request, so a start can run on any of the runtime's threads (it is Send).
        let (start, owner, take) = (self.desktop(), self.desktop(), self.desktop());
        starting(
            move || {
                let (mut c, r) = (start.clone(), request.clone());
                async move { deadline(120, c.start_service(timed(r, 120))).await.map(|_| ()) }
            },
            move || {
                let mut c = owner.clone();
                async move {
                    deadline(30, c.get_daemon_info(timed((), 30)))
                        .await
                        .map(|i| i.into_inner().ownership == DaemonOwnership::Other as i32)
                }
            },
            move || {
                let mut c = take.clone();
                async move { deadline(120, c.take_over_service(timed((), 120))).await.map(|_| ()) }
            },
        )
        .await
    }

    pub async fn stop(&self) -> Result<(), Status> {
        deadline(30, self.managed().stop_service(timed((), 30))).await.map(|_| ())
    }

    pub async fn set_tailscale_exit_node(&self, tag: &str, stable_id: &str) -> Result<(), Status> {
        let r = SetTailscaleExitNodeRequest { endpoint_tag: tag.into(), stable_id: stable_id.into() };
        deadline(15, self.started().set_tailscale_exit_node(timed(r, 15))).await.map(|_| ())
    }

    pub async fn tailscale_logout(&self, tag: &str) -> Result<(), Status> {
        deadline(15, self.started().tailscale_logout(timed(TailscaleLogoutRequest { endpoint_tag: tag.into() }, 15)))
            .await
            .map(|_| ())
    }

    /// Deletes this user's files in the engine (the Tailscale node above all); it refuses while a service runs.
    pub async fn forget(&self) -> Result<(), Status> {
        deadline(30, self.desktop().destroy_working_directory(timed((), 30))).await.map(|_| ())
    }

    pub async fn service_status(&self) -> Result<Streaming<ServiceStatus>, Status> {
        self.started().subscribe_service_status(()).await.map(|r| r.into_inner())
    }

    pub async fn tailscale_status(&self) -> Result<Streaming<TailscaleStatusUpdate>, Status> {
        self.started().subscribe_tailscale_status(()).await.map(|r| r.into_inner())
    }

    pub async fn status(&self, interval_ns: i64) -> Result<Streaming<EngineStatus>, Status> {
        self.started().subscribe_status(SubscribeStatusRequest { interval: interval_ns }).await.map(|r| r.into_inner())
    }

    pub async fn connections(&self, interval_ns: i64) -> Result<Streaming<ConnectionEvents>, Status> {
        self.started()
            .subscribe_connections(SubscribeConnectionsRequest { interval: interval_ns })
            .await
            .map(|r| r.into_inner())
    }

    pub async fn stun(&self, server: &str, tag: &str) -> Result<Streaming<StunTestProgress>, Status> {
        self.started()
            .start_stun_test(StunTestRequest { server: server.into(), outbound_tag: tag.into() })
            .await
            .map(|r| r.into_inner())
    }
}

/// `start`, taking the service over first (`take_over`) only from another user: refused while nobody owns it, it was the
/// claim itself that polkit refused, and asking again would show the prompt twice. An engine that lost its owner between
/// its check and its lock (ABORTED) is asked once more, claim and all; a second time the error stands.
pub async fn starting(
    mut start: impl AsyncFnMut() -> Result<(), Status>,
    mut owned_by_other: impl AsyncFnMut() -> Result<bool, Status>,
    mut take_over: impl AsyncFnMut() -> Result<(), Status>,
) -> Result<(), Status> {
    for attempt in 0..2 {
        let once = async {
            match start().await {
                Err(e) if e.code() == Code::PermissionDenied => {
                    if !owned_by_other().await? {
                        return Err(e);
                    }
                    take_over().await?;
                    start().await
                }
                r => r,
            }
        }
        .await;
        match once {
            Err(e) if e.code() == Code::Aborted && attempt == 0 => continue,
            r => return r,
        }
    }
    unreachable!("the second attempt returns")
}

/// Starts the worker for `socket` and waits for its READY, at most `seconds`: one that hangs fails the check, not the app.
pub fn start_worker(bin: &Path, socket: &Path, seconds: u64) -> std::io::Result<Child> {
    let mut child = Command::new(bin)
        .args(["worker", "--socket"])
        .arg(socket)
        .args(["--parent-pid", &std::process::id().to_string()])
        .current_dir(socket.parent().unwrap_or(Path::new("/")))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let out = child.stdout.take().expect("the worker's output");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let _ = BufReader::new(out).read_line(&mut line);
        let _ = tx.send(line.trim_end().to_string());
    });
    if rx.recv_timeout(Duration::from_secs(seconds)).ok().as_deref() != Some("READY") {
        let _ = child.kill();
        let _ = child.wait();
        return Err(std::io::Error::other("The engine's worker didn't start"));
    }
    Ok(child)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Connecting: another user's service is taken over; a refused claim isn't asked twice; a lost owner is asked once more.
    #[tokio::test]
    async fn engine_start() {
        async fn run(codes: &[Option<Code>], other: bool) -> (Vec<&'static str>, Option<Code>) {
            let calls = Arc::new(Mutex::new(Vec::new()));
            let left = Arc::new(Mutex::new(codes.to_vec()));
            let (c1, c2, c3) = (calls.clone(), calls.clone(), calls.clone());
            let r = starting(
                async move || {
                    c1.lock().unwrap().push("start");
                    match left.lock().unwrap().remove(0) {
                        Some(code) => Err(Status::new(code, "")),
                        None => Ok(()),
                    }
                },
                async move || {
                    c2.lock().unwrap().push("owner");
                    Ok(other)
                },
                async move || {
                    c3.lock().unwrap().push("takeOver");
                    Ok(())
                },
            )
            .await;
            let calls = calls.lock().unwrap().clone();
            (calls, r.err().map(|e| e.code()))
        }
        let denied = Code::PermissionDenied;
        let aborted = Code::Aborted;
        assert_eq!((vec!["start"], None), run(&[None], false).await);
        assert_eq!((vec!["start", "owner", "takeOver", "start"], None), run(&[Some(denied), None], true).await);
        // Nobody owns it: polkit refused the claim itself. No take-over, so no second prompt.
        assert_eq!((vec!["start", "owner"], Some(denied)), run(&[Some(denied)], false).await);
        // The owner left mid-call: once more, and only once.
        assert_eq!((vec!["start", "start"], None), run(&[Some(aborted), None], false).await);
        assert_eq!((vec!["start", "start"], Some(aborted)), run(&[Some(aborted), Some(aborted)], false).await);
        assert_eq!((vec!["start"], Some(Code::Unavailable)), run(&[Some(Code::Unavailable)], false).await);
    }

    /// The engine's worker must say READY in time; one that hangs fails the config check instead of blocking it.
    #[test]
    fn worker_start_is_bounded() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join("w.sock");
        let script = |name: &str, body: &str| {
            let f = tmp.path().join(name);
            std::fs::write(&f, body).unwrap();
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
            f
        };
        let hang = script("hang-worker", "#!/bin/sh\nsleep 30\n");
        let start = std::time::Instant::now();
        assert!(start_worker(&hang, &socket, 1).is_err());
        assert!(start.elapsed() < Duration::from_secs(10), "took {:?}", start.elapsed());
        let ready = script("ready-worker", "#!/bin/sh\necho READY\nsleep 30\n");
        let mut worker = start_worker(&ready, &socket, 5).unwrap();
        let _ = worker.kill();
        let _ = worker.wait();
    }
}
