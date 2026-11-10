package app.unbraid

import app.unbraid.vpn.Engine
import app.unbraid.vpn.Linux
import app.unbraid.vpn.Matchers
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * The real engine (engine/build.sh) checks every config the other tests compiled, made Linux configs: what the app
 * would run must be what the engine accepts. Run by `./gradlew engineTest`, after `test` wrote them.
 */
class EngineCheckTest {
    private fun apps(k: String) = if (k.startsWith('/')) Matchers(paths = listOf(k)) else Matchers(dirs = listOf("/opt/$k/"), names = listOf(k.substringAfterLast('.')))

    @Test fun engineAcceptsEveryLinuxConfig() {
        assumeTrue("engine not built", File(System.getenv("UNBRAID_ENGINE_BIN") ?: "").canExecute())
        val android = File("build/compiled").listFiles().orEmpty().map { it.name to Linux.config(it.readText(), ::apps, "/usr/lib/unbraid/bin/unbraid") }
        val linux = File("build/compiled-linux").listFiles().orEmpty().map { it.name to it.readText() }
        assertTrue("run the other tests first", android.size > 50 && linux.isNotEmpty())
        val refused = (android + linux).mapNotNull { (name, c) -> runCatching { Engine.check(c) }.exceptionOrNull()?.let { "$name: ${it.message}" } }
        assertEquals(emptyList<String>(), refused)
        // And it really checks: an unknown option is refused, as Android's libbox refuses it.
        assertTrue(runCatching { Engine.check(linux.first().second.replace("\"find_process\"", "\"find_processes\"")) }.isFailure)
    }
}
