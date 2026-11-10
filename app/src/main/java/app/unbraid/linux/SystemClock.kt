package app.unbraid.linux

import java.io.File

/** Android's SystemClock: [elapsedRealtime] counts suspend (as the health checks and timed pauses expect), [uptimeMillis] doesn't. */
object SystemClock {
    private val uptime = File("/proc/uptime")

    /** Milliseconds since boot, suspend included (CLOCK_BOOTTIME, which /proc/uptime reports to 10 ms). */
    fun elapsedRealtime(): Long = runCatching { (uptime.readText().substringBefore(' ').toDouble() * 1000).toLong() }.getOrElse { uptimeMillis() }

    /** Milliseconds since boot without suspend: the JVM's System.nanoTime() is CLOCK_MONOTONIC on Linux. */
    fun uptimeMillis(): Long = System.nanoTime() / 1_000_000
}
