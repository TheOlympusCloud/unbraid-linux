package app.unbraid.linux

import java.io.File

/**
 * Starting and connecting at login (an XDG autostart entry), as Android's Always-on VPN starts the app at boot. It
 * connects once the user has logged in, as Android does after the first unlock.
 */
object Autostart {
    private val file get() = File(System.getenv("XDG_CONFIG_HOME")?.takeIf { it.isNotEmpty() } ?: "${System.getProperty("user.home")}/.config", "autostart/unbraid.desktop")

    val enabled: Boolean get() = file.isFile && Apps.parse(file.readText()).let { it["Hidden"] != "true" && it["X-GNOME-Autostart-enabled"] != "false" }

    private val exec get() = runCatching { Apps.parse(file.readText())["Exec"] }.getOrNull()
    /** Started at login, it connects (as it always did before these were choices). */
    val connects: Boolean get() = exec?.let { "--connect" in it } ?: true
    /** Started at login, it stays in the tray, without a window. */
    val minimised: Boolean get() = exec?.let { "--background" in it } ?: true

    fun set(on: Boolean, connect: Boolean = connects, minimised: Boolean = this.minimised) {
        if (!on) { file.delete(); return }
        file.parentFile.mkdirs()
        val exec = "unbraid" + (if (minimised) " --background" else "") + (if (connect) " --connect" else "")
        file.writeText("[Desktop Entry]\nType=Application\nName=unbraid\nComment=Starts unbraid at login\nExec=$exec\nIcon=unbraid\nNoDisplay=true\nX-GNOME-Autostart-enabled=true\n")
    }
}
