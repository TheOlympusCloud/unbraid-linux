package app.unbraid.linux

import java.awt.FileDialog
import java.awt.Frame
import java.awt.Toolkit
import java.awt.datatransfer.DataFlavor
import java.awt.datatransfer.StringSelection
import java.io.File
import java.util.concurrent.TimeUnit

/** What Android gives an app through its Context and intents, from the Linux desktop. */
object Desktop {
    /** The app's window, so dialogs open over it. */
    @Volatile var window: Frame? = null

    /** Opens [url] in the user's browser, as Android's ACTION_VIEW. */
    fun open(url: String) {
        if (runCatching { ProcessBuilder("xdg-open", url).redirectErrorStream(true).start() }.isFailure)
            runCatching { java.awt.Desktop.getDesktop().browse(java.net.URI(url)) }
    }

    /** The desktop's file chooser (GTK's, through AWT), as Android's document picker; null when cancelled. Blocks: call off the main thread. */
    fun pickFile(title: String, images: Boolean = false): File? {
        val d = FileDialog(window, title, FileDialog.LOAD)
        if (images) d.setFilenameFilter { _, name -> name.substringAfterLast('.').lowercase() in setOf("png", "jpg", "jpeg", "gif", "bmp") }
        d.isVisible = true
        return d.files.firstOrNull()
    }

    /** Animations, unless the desktop asks for reduced motion (GNOME's or KDE's setting), as Android's animator scale 0. */
    val animations: Boolean by lazy {
        val gnome = run("gsettings", "get", "org.gnome.desktop.interface", "enable-animations")?.trim()
        val kde = File(System.getProperty("user.home"), ".config/kdeglobals").takeIf { it.isFile }?.readLines()
            ?.firstOrNull { it.startsWith("AnimationDurationFactor=") }?.substringAfter('=')?.toDoubleOrNull()
        gnome != "false" && kde != 0.0
    }

    /** The clipboard's text, if any. */
    fun clipText(): String? = runCatching { Toolkit.getDefaultToolkit().systemClipboard.getData(DataFlavor.stringFlavor) as String }.getOrNull()

    /** Empties the clipboard (a secret must not stay there for the next app to read). */
    fun clearClip() { runCatching { Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(""), null) } }

    private fun run(vararg cmd: String): String? = runCatching {
        val p = ProcessBuilder(*cmd).redirectError(ProcessBuilder.Redirect.DISCARD).start()
        val out = p.inputStream.bufferedReader().readText()
        if (p.waitFor(3, TimeUnit.SECONDS) && p.exitValue() == 0) out else null
    }.getOrNull()
}
