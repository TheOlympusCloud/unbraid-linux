package app.unbraid.linux

import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions

/** Where the app keeps its files (XDG base directories) and where it finds the engine. */
object Paths {
    /** The setup, sealed secrets, caches and statistics: $XDG_DATA_HOME/unbraid, which only this user may open. */
    val data: File by lazy { private(File(env("XDG_DATA_HOME") ?: "${System.getProperty("user.home")}/.local/share", "unbraid")) }

    /** The running app's socket, one instance per user: $XDG_RUNTIME_DIR/unbraid (the data folder without one). */
    val runtime: File by lazy { env("XDG_RUNTIME_DIR")?.let { private(File(it, "unbraid")) } ?: data }

    /** The engine's socket, which the system service (unbraid-engine.service) listens on. */
    val engine: String get() = env("UNBRAID_ENGINE_SOCKET") ?: "/run/unbraid-engine/engine.sock"

    /** The engine's program, which also runs the app's own unprivileged worker. */
    val engineBinary: String get() = env("UNBRAID_ENGINE_BIN") ?: "/usr/lib/unbraid/unbraid-engine"

    private fun env(name: String) = System.getenv(name)?.takeIf { it.isNotEmpty() }

    private fun private(dir: File) = dir.apply {
        mkdirs()
        Files.setPosixFilePermissions(toPath(), PosixFilePermissions.fromString("rwx------"))
    }
}
