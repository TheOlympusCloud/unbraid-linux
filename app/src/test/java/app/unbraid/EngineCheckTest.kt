package app.unbraid

import app.unbraid.data.DIRECT
import app.unbraid.data.Route
import app.unbraid.data.Server
import app.unbraid.data.Setup
import app.unbraid.data.SsLink
import app.unbraid.data.SsProfile
import app.unbraid.engine.desktop.DesktopServiceGrpc
import app.unbraid.engine.desktop.StartServiceRequest
import app.unbraid.vpn.Compiler
import app.unbraid.vpn.Engine
import app.unbraid.vpn.Linux
import app.unbraid.vpn.Matchers
import com.sun.net.httpserver.HttpServer
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder
import io.grpc.netty.shaded.io.netty.channel.epoll.EpollDomainSocketChannel
import io.grpc.netty.shaded.io.netty.channel.epoll.EpollEventLoopGroup
import io.grpc.netty.shaded.io.netty.channel.unix.DomainSocketAddress
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.util.concurrent.TimeUnit

/**
 * The real engine (engine/build.sh) checks every config the other tests compiled, made Linux configs: what the app
 * would run must be what the engine accepts. Run by `./gradlew engineTest`, after `test` wrote them.
 */
class EngineCheckTest {
    @get:Rule val tmp = TemporaryFolder()
    private val engine = File(System.getenv("UNBRAID_ENGINE_BIN") ?: "")
    private fun apps(k: String) = if (k.startsWith('/')) Matchers(paths = listOf(k)) else Matchers(dirs = listOf("/opt/$k/"), names = listOf(k.substringAfterLast('.')))

    @Test fun engineAcceptsEveryLinuxConfig() {
        assumeTrue("engine not built", engine.canExecute())
        val android = File("build/compiled").listFiles().orEmpty().map { it.name to Linux.config(it.readText(), ::apps, "/usr/lib/unbraid/bin/unbraid") }
        val linux = File("build/compiled-linux").listFiles().orEmpty().map { it.name to it.readText() }
        assertTrue("run the other tests first", android.size > 50 && linux.isNotEmpty())
        val refused = (android + linux).mapNotNull { (name, c) -> runCatching { Engine.check(c) }.exceptionOrNull()?.let { "$name: ${it.message}" } }
        assertEquals(emptyList<String>(), refused)
        // And it really checks: an unknown option is refused, as Android's libbox refuses it.
        assertTrue(runCatching { Engine.check(linux.first().second.replace("\"find_process\"", "\"find_processes\"")) }.isFailure)
    }

    private fun port() = ServerSocket(0).use { it.localPort }

    /**
     * The engine, run as this user: without a TUN it needs no root, and it then looks up processes as the system service
     * does, from the computer's own user namespace (a sandboxed one may not read other namespaces' processes).
     */
    private val channels = HashMap<String, io.grpc.ManagedChannel>()

    private fun daemon(name: String): DesktopServiceGrpc.DesktopServiceBlockingStub {
        val sock = File("/tmp/ubrt-${ProcessHandle.current().pid()}").apply { mkdirs(); deleteOnExit() }
        val p = ProcessBuilder(engine.path, "run", "--working-directory", tmp.newFolder("$name-work").path, "--socket", "${sock.path}/$name.sock")
            .redirectErrorStream(true).redirectOutput(File("build/engine-$name.log")).start()
        Runtime.getRuntime().addShutdownHook(Thread { p.destroy() })
        val path = File(sock, "$name.sock")
        repeat(100) { if (!path.exists()) Thread.sleep(100) }
        assertTrue("$name engine didn't start: ${File("build/engine-$name.log").readText()}", path.exists())
        val channel = NettyChannelBuilder.forAddress(DomainSocketAddress(path.path)).eventLoopGroup(EpollEventLoopGroup(1))
            .channelType(EpollDomainSocketChannel::class.java).usePlaintext().build()
        channels[name] = channel
        return DesktopServiceGrpc.newBlockingStub(channel).withDeadlineAfter(30, TimeUnit.SECONDS)
    }

    /**
     * Per-app routing through the real engine: three programs (copies of curl, told apart by their paths, as the engine tells
     * apps apart) reach one echo server, which answers with the address it saw. The default route and route B are
     * Shadowsocks exits leaving from 127.0.0.2 and 127.0.0.3; Direct leaves from 127.0.0.1. A local proxy inbound stands in
     * for the TUN, which needs a real machine; everything behind it is the Linux config as the app compiles it.
     */
    @Test fun eachProgramLeavesThroughItsOwnExit() {
        assumeTrue("engine not built", engine.canExecute())
        assumeTrue("needs curl", File("/usr/bin/curl").canExecute())
        val echo = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0).apply {
            createContext("/") { ex -> val b = ex.remoteAddress.address.hostAddress.toByteArray(); ex.sendResponseHeaders(200, b.size.toLong()); ex.responseBody.use { it.write(b) } }
            start()
        }
        val (p1, p2, proxy) = Triple(port(), port(), port())
        daemon("exits").startService(StartServiceRequest.newBuilder().setConfigContent("""
            {"log": {"level": "warn"},
             "inbounds": [{"type": "shadowsocks", "tag": "ss1", "listen": "127.0.0.1", "listen_port": $p1, "method": "aes-128-gcm", "password": "one"},
                          {"type": "shadowsocks", "tag": "ss2", "listen": "127.0.0.1", "listen_port": $p2, "method": "aes-128-gcm", "password": "two"}],
             "outbounds": [{"type": "direct", "tag": "from2", "inet4_bind_address": "127.0.0.2"}, {"type": "direct", "tag": "from3", "inet4_bind_address": "127.0.0.3"}],
             "route": {"rules": [{"inbound": ["ss1"], "outbound": "from2"}, {"inbound": ["ss2"], "outbound": "from3"}]}}
        """.trimIndent()).build())

        val bin = tmp.newFolder("bin")
        val (viaA, viaB, direct) = listOf("curl-default", "curl-b", "curl-direct").map { n -> File(bin, n).also { File("/usr/bin/curl").copyTo(it); it.setExecutable(true) } }
        val setup = Setup(
            routes = listOf(Route("a", ss = SsProfile("Exit A", "127.0.0.1", p1, "aes-128-gcm", "one")), Route("b", ss = SsProfile("Exit B", "127.0.0.1", p2, "aes-128-gcm", "two"), hue = 1)),
            defaultRoute = "a", apps = mapOf(viaB.path to "b", direct.path to DIRECT),
        )
        val links = setup.activeRoutes.associate { r -> r.id to SsLink(Server(r.name, "127.0.0.1", "127.0.0.1", "", 0), r.ss!!) }
        val compiled = Json.parseToJsonElement(Linux.config(Compiler.compile(Compiler.Input(setup, links, "app.unbraid", true, "tailscale", "cache.db")), { Matchers(paths = listOf(it)) }, null)).jsonObject
        // At debug level the engine logs each connection's process and the rule it matched: kept for a failure, below.
        val config = JsonObject(compiled + ("log" to Json.parseToJsonElement("""{"level": "debug"}""")) + ("inbounds" to JsonArray(compiled["inbounds"]!!.jsonArray.map { i ->
            if (i.jsonObject["type"] == JsonPrimitive("tun")) Json.parseToJsonElement("""{"type": "mixed", "tag": "tun", "listen": "127.0.0.1", "listen_port": $proxy}""") else i
        })))
        daemon("app").startService(StartServiceRequest.newBuilder().setConfigContent(config.toString()).build())

        fun seen(curl: File) = ProcessBuilder(curl.path, "-s", "--max-time", "10", "--proxy", "socks5://127.0.0.1:$proxy", "http://127.0.0.1:${echo.address.port}/")
            .redirectErrorStream(true).start().let { p -> p.inputStream.bufferedReader().readText().also { p.waitFor() } }
        val got = listOf(seen(viaA), seen(viaB), seen(direct))
        val logs = app.unbraid.engine.daemon.StartedServiceGrpc.newBlockingStub(channels["app"]).withDeadlineAfter(3, TimeUnit.SECONDS)
            .subscribeLog(com.google.protobuf.Empty.getDefaultInstance())
        val lines = ArrayList<String>()
        runCatching { while (logs.hasNext() && lines.size < 400) logs.next().messagesList.forEach { lines += it.message } }
        File("build/engine-routing.log").writeText(lines.joinToString("\n"))
        assertEquals(listOf("127.0.0.2", "127.0.0.3", "127.0.0.1"), got)
        echo.stop(0)
    }
}
