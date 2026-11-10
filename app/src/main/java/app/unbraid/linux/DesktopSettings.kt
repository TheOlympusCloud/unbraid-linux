package app.unbraid.linux

import kotlinx.coroutines.flow.MutableStateFlow

/** The desktop version's own settings (Settings › Desktop): the theme, the tray and the window. */
object DesktopSettings {
    private val prefs by lazy { SharedPreferences.named("desktop") }

    enum class Theme { System, Dark, Light }

    val theme by lazy { MutableStateFlow(Theme.entries.getOrElse(prefs.getInt("theme", 0)) { Theme.System }) }
    /** Closing the window leaves unbraid in the tray; off, closing quits and the connection ends. */
    val closeToTray by lazy { MutableStateFlow(prefs.getBoolean("close_to_tray", true)) }
    val rememberWindow by lazy { MutableStateFlow(prefs.getBoolean("remember_window", true)) }

    fun setTheme(t: Theme) { theme.value = t; prefs.edit { putInt("theme", t.ordinal) } }
    fun setCloseToTray(on: Boolean) { closeToTray.value = on; prefs.edit { putBoolean("close_to_tray", on) } }
    fun setRememberWindow(on: Boolean) { rememberWindow.value = on; prefs.edit { putBoolean("remember_window", on) } }

    /** Dark or light for [t], [systemDark] being the desktop's own preference (null: it states none, so the app's dark). */
    fun dark(t: Theme, systemDark: Boolean?) = when (t) { Theme.Dark -> true; Theme.Light -> false; Theme.System -> systemDark ?: true }

    /** The window's size and place when it last closed, in dp. */
    data class Placement(val x: Int, val y: Int, val width: Int, val height: Int, val maximized: Boolean)

    fun placement(): Placement? = if (!rememberWindow.value || !prefs.contains("width")) null else
        Placement(prefs.getInt("x", 0), prefs.getInt("y", 0), prefs.getInt("width", 1280), prefs.getInt("height", 800), prefs.getBoolean("maximized", false))

    fun save(p: Placement) = prefs.edit {
        putInt("x", p.x); putInt("y", p.y); putInt("width", p.width); putInt("height", p.height); putBoolean("maximized", p.maximized)
    }
}
