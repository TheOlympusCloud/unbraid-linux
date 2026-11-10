package app.unbraid.linux

/** Android's Log, as the ported code calls it: one line per entry on stderr, which the session's journal keeps. */
object Log {
    fun d(tag: String, msg: String) { if (app.unbraid.BuildConfig.DEBUG) line("D", tag, msg, null) }
    fun i(tag: String, msg: String) = line("I", tag, msg, null)
    fun w(tag: String, msg: String, tr: Throwable? = null) = line("W", tag, msg, tr)
    fun e(tag: String, msg: String, tr: Throwable? = null) = line("E", tag, msg, tr)

    // Only the throwable's type: its message can hold addresses or keys, which callers redact themselves.
    private fun line(level: String, tag: String, msg: String, tr: Throwable?) =
        System.err.println("$level/$tag: $msg" + (tr?.let { " (${it.javaClass.simpleName})" } ?: ""))
}
