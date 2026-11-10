package app.unbraid.vpn

import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * Tracks the computer's own default network (the main routing table's IPv4 default route, which the engine's routes
 * leave alone) as "interface gateway". The engine follows the interface by itself; the app only needs to know when the
 * network changed, to retry blocked routes and to stop judging servers by checks made on another network.
 */
class NetMonitor(private val routes: File = File("/proc/net/route")) {
    @Volatile var network: String? = null
        private set
    /** Called when the computer moves to another network (not on the first one). */
    @Volatile var onChange: (() -> Unit)? = null
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var job: Job? = null

    @Synchronized fun start() {
        network = read()
        job?.cancel()
        job = scope.launch {
            var lostAt = 0L
            while (isActive) {
                delay(3_000)
                val now = read()
                when {
                    now == network -> lostAt = 0
                    // A loss waits briefly for the network to come back, as Android's monitor does.
                    now == null -> if (lostAt == 0L) lostAt = System.nanoTime() else if (System.nanoTime() - lostAt > 3_000_000_000) network = null
                    else -> { val had = network; network = now; lostAt = 0; if (had != null) onChange?.invoke() }
                }
            }
        }
    }

    @Synchronized fun stop() { job?.cancel(); job = null }

    /** The default route with the lowest metric, tunnels aside: "interface gateway", or null without one. */
    fun read(): String? = runCatching {
        routes.readLines().drop(1).map { it.trim().split(Regex("\\s+")) }
            .filter { it.size >= 8 && it[1] == "00000000" && it[7] == "00000000" && !it[0].startsWith("tun") }
            .minByOrNull { it[6].toIntOrNull() ?: Int.MAX_VALUE }
            ?.let { "${it[0]} ${gateway(it[2])}" }
    }.getOrNull()

    /** /proc/net/route's gateway: an IPv4 address in little-endian hex. */
    private fun gateway(hex: String) = hex.toLong(16).let { v -> (0..3).joinToString(".") { "${v shr (it * 8) and 255}" } }
}
