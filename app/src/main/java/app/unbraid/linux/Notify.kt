package app.unbraid.linux

/** Desktop notifications (freedesktop.org), as Android's: through notify-send when it is installed; nothing otherwise. */
object Notify {
    fun send(title: String, text: String) {
        runCatching { ProcessBuilder("notify-send", "--app-name=unbraid", "--icon=unbraid", title, text).redirectErrorStream(true).start() }
    }
}
