package app.unbraid

import app.unbraid.data.Http
import app.unbraid.vpn.Probe
import app.unbraid.vpn.UnbraidVpn
import com.sun.net.httpserver.HttpsConfigurator
import com.sun.net.httpserver.HttpsServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.security.KeyStore
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory
import kotlin.concurrent.thread

/**
 * Certificate names, checked the JVM's way, in the TLS handshake: its default HostnameVerifier, unlike Android's, accepts
 * nothing, which failed every speed test, the health check's HTTPS and the exit check. Test servers' own certificates,
 * trusted by these tests only.
 */
class TlsNamesTest {
    /** A key and a self-signed certificate for [cn] (and [san] when given), made with the JDK's keytool. */
    private fun keys(cn: String, san: String?): KeyStore {
        val f = File.createTempFile("unbraid-tls", ".p12").apply { delete(); deleteOnExit() }
        val p = ProcessBuilder(listOf(File(System.getProperty("java.home"), "bin/keytool").path, "-genkeypair", "-alias", "server", "-keyalg", "EC",
            "-groupname", "secp256r1", "-dname", "CN=$cn", "-validity", "2", "-keystore", f.path, "-storepass", PASS, "-storetype", "PKCS12") +
            (san?.let { listOf("-ext", "SAN=dns:$it") } ?: emptyList())).redirectErrorStream(true).start()
        val out = p.inputStream.readAllBytes().decodeToString()
        assertEquals(out, 0, p.waitFor())
        return KeyStore.getInstance("PKCS12").apply { f.inputStream().use { load(it, PASS.toCharArray()) } }
    }

    private fun serving(ks: KeyStore) = SSLContext.getInstance("TLS").apply {
        init(KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(ks, PASS.toCharArray()) }.keyManagers, null, null)
    }

    private fun trusting(ks: KeyStore): SSLSocketFactory = SSLContext.getInstance("TLS").apply {
        init(null, TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(ks) }.trustManagers, null)
    }.socketFactory

    /** The app's way into an exit ([Probe]): a server's certificate counts for its own name, and only for it. */
    @Test fun probeChecksTheServersName() {
        val ks = keys("unbraid.test", "unbraid.test")
        val tls = serving(ks)
        // Stands in for the engine's probe proxy: it answers CONNECT, then is the server itself.
        val proxy = ServerSocket(0, 8, InetAddress.getLoopbackAddress())
        thread(isDaemon = true) {
            while (true) {
                val s = runCatching { proxy.accept() }.getOrNull() ?: break
                thread(isDaemon = true) {
                    runCatching {
                        Probe.head(s.getInputStream())
                        s.getOutputStream().write("HTTP/1.1 200 Connection established\r\n\r\n".toByteArray())
                        (tls.socketFactory.createSocket(s, null, true) as SSLSocket).use { it.startHandshake(); it.inputStream.read() }
                    }
                    s.close()
                }
            }
        }
        UnbraidVpn.probe = proxy.localPort to "test"
        try {
            Probe.open("direct", "unbraid.test", tls = trusting(ks)).close()
            val e = runCatching { Probe.open("direct", "other.test", tls = trusting(ks)) }.exceptionOrNull()
            assertTrue("$e", e is SSLHandshakeException)
        } finally {
            UnbraidVpn.probe = null
            proxy.close()
        }
    }

    /**
     * A server reached by its address, its certificate checked against a name the caller gives (PIA's, whose
     * certificates name the server in CN only): that name passes, another doesn't, and the address never counts.
     */
    @Test fun httpChecksTheGivenName() {
        val ks = keys("unbraid-test", null)
        val server = HttpsServer.create(InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0).apply {
            httpsConfigurator = HttpsConfigurator(serving(ks))
            createContext("/") { x -> val b = "{}".toByteArray(); x.sendResponseHeaders(200, b.size.toLong()); x.responseBody.use { it.write(b) } }
            start()
        }
        try {
            val url = "https://127.0.0.1:${server.address.port}/addKey"
            assertEquals("{}", Http.get(url, tls = trusting(ks), verifyHost = "unbraid-test"))
            val e = runCatching { Http.get(url, tls = trusting(ks), verifyHost = "other-test") }.exceptionOrNull()
            assertTrue("$e", e is SSLHandshakeException)
        } finally {
            server.stop(0)
        }
    }

    private companion object { const val PASS = "unbraid-test" }
}
