package app.unbraid.vpn

import app.unbraid.engine.daemon.ManagedServiceGrpc
import app.unbraid.engine.daemon.STUNTestRequest
import app.unbraid.engine.daemon.ServiceStatus
import app.unbraid.engine.daemon.SetTailscaleExitNodeRequest
import app.unbraid.engine.daemon.StartedServiceGrpc
import app.unbraid.engine.daemon.StartedServiceGrpcKt
import app.unbraid.engine.daemon.SubscribeConnectionsRequest
import app.unbraid.engine.daemon.SubscribeStatusRequest
import app.unbraid.engine.daemon.TailscaleLogoutRequest
import app.unbraid.engine.desktop.ApplicationServiceGrpc
import app.unbraid.engine.desktop.ConfigContent
import app.unbraid.engine.desktop.DaemonOwnership
import app.unbraid.engine.desktop.DesktopServiceGrpc
import app.unbraid.engine.desktop.StartServiceRequest
import app.unbraid.linux.Paths
import com.google.protobuf.Empty
import io.grpc.ManagedChannel
import io.grpc.Status
import io.grpc.StatusRuntimeException
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder
import io.grpc.netty.shaded.io.netty.channel.epoll.EpollDomainSocketChannel
import io.grpc.netty.shaded.io.netty.channel.epoll.EpollEventLoopGroup
import io.grpc.netty.shaded.io.netty.channel.unix.DomainSocketAddress
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * The engine: unbraid-engine, sing-box's Linux daemon running as a system service, over gRPC on its unix socket. It is
 * what libbox's command server and clients are on Android, call for call; the daemon knows the app's user from the socket.
 */
object Engine {
    private val empty = Empty.getDefaultInstance()
    private val loop by lazy { EpollEventLoopGroup(1) }
    private fun channel(socket: String): ManagedChannel = NettyChannelBuilder.forAddress(DomainSocketAddress(socket))
        .eventLoopGroup(loop).channelType(EpollDomainSocketChannel::class.java).usePlaintext().build()
    private val channel by lazy { channel(Paths.engine) }
    private fun desktop(seconds: Long = 30) = DesktopServiceGrpc.newBlockingStub(channel).withDeadlineAfter(seconds, TimeUnit.SECONDS)
    private fun managed() = ManagedServiceGrpc.newBlockingStub(channel).withDeadlineAfter(30, TimeUnit.SECONDS)
    private fun started() = StartedServiceGrpc.newBlockingStub(channel).withDeadlineAfter(15, TimeUnit.SECONDS)
    private val streams by lazy { StartedServiceGrpcKt.StartedServiceCoroutineStub(channel) }

    /**
     * Throws if the engine would refuse [config], without stopping what runs: the system service replaces its running
     * config only by stopping it first. Its message can quote the config, keys included: callers redact it.
     */
    fun check(config: String) { worker().checkConfig(ConfigContent.newBuilder().setContent(config).build()) }

    private var worker: Process? = null
    private var workerChannel: ManagedChannel? = null

    /**
     * The engine's unprivileged worker (`unbraid-engine worker`), which checks configs as this user. It must be the app's
     * own child, says READY once it serves, and quits with the app (when its stdin closes).
     */
    @Synchronized private fun worker(): ApplicationServiceGrpc.ApplicationServiceBlockingStub {
        if (worker?.isAlive != true) {
            workerChannel?.shutdownNow()
            val socket = File(Paths.runtime, "worker.sock")
            worker = startWorker(Paths.engineBinary, socket)
            workerChannel = channel(socket.path)
        }
        return ApplicationServiceGrpc.newBlockingStub(workerChannel).withDeadlineAfter(30, TimeUnit.SECONDS)
    }

    /**
     * Runs [config] in place of whatever runs. A service another user on this computer started is taken over first,
     * which polkit lets the user allow.
     */
    fun start(config: String) {
        val request = StartServiceRequest.newBuilder().setConfigContent(config).build()
        // 120 s: with nobody owning it the engine asks polkit first, which away from the session at the screen is a password.
        starting({ desktop(120).startService(request) }, { desktop().getDaemonInfo(empty).ownership == DaemonOwnership.DAEMON_OWNERSHIP_OTHER },
            { desktop(120).takeOverService(empty) })
    }

    /**
     * [start], taking the service over first ([takeOver]) only from another user: refused while nobody owns it, it was the
     * claim itself that polkit refused, and asking again would show the prompt twice. An engine that lost its owner between
     * its check and its lock (ABORTED) is asked once more, claim and all; a second time the error stands.
     */
    internal fun starting(start: () -> Unit, ownedByOther: () -> Boolean, takeOver: () -> Unit) {
        fun once() = try { start() } catch (e: StatusRuntimeException) {
            if (e.status.code != Status.Code.PERMISSION_DENIED || !ownedByOther()) throw e
            takeOver()
            start()
        }
        try { once() } catch (e: StatusRuntimeException) { if (e.status.code != Status.Code.ABORTED) throw e; once() }
    }

    fun stop() { managed().stopService(empty) }

    fun setTailscaleExitNode(tag: String, stableId: String) {
        started().setTailscaleExitNode(SetTailscaleExitNodeRequest.newBuilder().setEndpointTag(tag).setStableID(stableId).build())
    }

    fun tailscaleLogout(tag: String) { started().tailscaleLogout(TailscaleLogoutRequest.newBuilder().setEndpointTag(tag).build()) }

    /** Deletes this user's files in the engine (the Tailscale node above all); it refuses while a service runs. */
    fun forget() { desktop().destroyWorkingDirectory(empty) }

    /** Starts the worker for [socket] and waits for its READY, at most [seconds]: one that hangs fails the check, not the app. */
    internal fun startWorker(bin: String, socket: File, seconds: Long = 20): Process {
        val p = ProcessBuilder(bin, "worker", "--socket", socket.path, "--parent-pid", "${ProcessHandle.current().pid()}")
            .directory(socket.parentFile).redirectError(ProcessBuilder.Redirect.DISCARD).start()
        val ready = java.util.concurrent.CompletableFuture.supplyAsync { p.inputStream.bufferedReader().readLine() }
        if (runCatching { ready.get(seconds, TimeUnit.SECONDS) }.getOrNull() != "READY") { p.destroyForcibly(); error("The engine's worker didn't start") }
        return p
    }

    fun serviceStatus() = streams.subscribeServiceStatus(empty)
    fun tailscaleStatus() = streams.subscribeTailscaleStatus(empty)
    fun status(intervalNs: Long) = streams.subscribeStatus(SubscribeStatusRequest.newBuilder().setInterval(intervalNs).build())
    fun connections(intervalNs: Long) = streams.subscribeConnections(SubscribeConnectionsRequest.newBuilder().setInterval(intervalNs).build())
    fun stun(server: String, tag: String) = streams.startSTUNTest(STUNTestRequest.newBuilder().setServer(server).setOutboundTag(tag).build())

    /** The engine isn't there at all (service stopped or not installed), as opposed to one that refused something. */
    fun missing(e: Throwable) = (e as? StatusRuntimeException)?.status?.code == Status.Code.UNAVAILABLE

    const val MISSING = "The unbraid engine isn't running. Start it with: sudo systemctl enable --now unbraid-engine"

    fun running(s: ServiceStatus) = s.status == ServiceStatus.Type.STARTED || s.status == ServiceStatus.Type.STARTING
}
