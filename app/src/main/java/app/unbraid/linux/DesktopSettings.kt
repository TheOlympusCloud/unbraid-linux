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

    /**
     * What closing the window does: hide it (true) or quit. Hidden, unbraid needs a way back: the tray, or, without one,
     * a connection still running (the launcher or the command line brings the window back).
     */
    fun closeHides(closeToTray: Boolean, tray: Boolean, connected: Boolean) = closeToTray && (tray || connected)

    /**
     * Whether unbraid quits once its window is hidden and nothing runs any more ([wasOn]: it was connected, then was
     * disconnected from the tray or the command line). With a tray there's a way back, whatever closing the window does.
     */
    fun quitsWhenHidden(visible: Boolean, wasOn: Boolean, tray: Boolean) = !visible && wasOn && !tray

    /**
     * The place to remember for a window at [x], [y] (null until the desktop has placed it) and of this size: maximized
     * keeps the size it had before, to come back to; full screen and a place not set yet aren't remembered.
     */
    fun toSave(was: Placement?, x: Int?, y: Int?, width: Int, height: Int, maximized: Boolean, floating: Boolean): Placement? = when {
        maximized -> (was ?: Placement(0, 0, 1280, 800, false)).copy(maximized = true)
        floating && x != null && y != null -> Placement(x, y, width, height, false)
        else -> null
    }

    /**
     * Whether a start shows the window: not for the background ([background], at login) or to connect. Without a tray,
     * a background start that doesn't connect would be nothing at all, so it shows the window instead.
     */
    fun showsAtStart(background: Boolean, connect: Boolean, command: String, tray: Boolean) =
        !background && command != "connect" || background && !connect && !tray

    /** A remembered place still on one of [screens] (one may have gone since). */
    fun onScreen(p: Placement, screens: List<java.awt.Rectangle>) = screens.any { it.intersects(java.awt.Rectangle(p.x, p.y, p.width, p.height)) }
}
