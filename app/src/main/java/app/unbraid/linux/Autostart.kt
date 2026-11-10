package app.unbraid.linux

import java.io.File

/**
 * Starting and connecting at login (an XDG autostart entry), as Android's Always-on VPN starts the app at boot. It
 * connects once the user has logged in, as Android does after the first unlock.
 */
object Autostart {
    private val file get() = File(System.getenv("XDG_CONFIG_HOME")?.takeIf { it.isNotEmpty() } ?: "${System.getProperty("user.home")}/.config", "autostart/unbraid.desktop")

    val enabled: Boolean get() = file.isFile && Apps.parse(file.readText()).let { it["Hidden"] != "true" && it["X-GNOME-Autostart-enabled"] != "false" }

    fun set(on: Boolean) {
        if (!on) { file.delete(); return }
        file.parentFile.mkdirs()
        file.writeText("[Desktop Entry]\nType=Application\nName=unbraid\nComment=Connects unbraid at login\nExec=unbraid --background --connect\nIcon=unbraid\nNoDisplay=true\nX-GNOME-Autostart-enabled=true\n")
    }
}
