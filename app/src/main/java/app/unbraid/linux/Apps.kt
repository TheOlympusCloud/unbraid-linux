package app.unbraid.linux

import app.unbraid.vpn.Matchers
import java.io.File

/** An app the Apps page lists: [key] is what the setup routes (a desktop entry's id, or a program's path). */
data class DesktopApp(val key: String, val label: String, val system: Boolean, val icon: File?, val matchers: Matchers)

/**
 * The installed apps, from their desktop entries (XDG), and how the engine knows each one's processes. A program
 * without an entry (something seen connecting, a command-line tool) is routed by its own path, which is then its key.
 */
object Apps {
    private val home = System.getProperty("user.home")
    private val env = System.getenv()

    /** Data folders, most important first: XDG_DATA_HOME, XDG_DATA_DIRS, then Flatpak and Snap exports some sessions leave out. */
    fun dataDirs(): List<File> = (listOf(env["XDG_DATA_HOME"]?.takeIf { it.isNotEmpty() } ?: "$home/.local/share") +
        (env["XDG_DATA_DIRS"]?.takeIf { it.isNotEmpty() } ?: "/usr/local/share:/usr/share").split(':') +
        listOf("$home/.local/share/flatpak/exports/share", "/var/lib/flatpak/exports/share", "/var/lib/snapd/desktop"))
        .filter { it.isNotEmpty() }.distinct().map(::File)

    @Volatile private var cache: List<DesktopApp> = emptyList()
    @Volatile private var scannedAt = 0L

    /** Every app with a desktop entry, read afresh. Entries earlier in [dirs] hide later ones with the same id. */
    fun scan(dirs: List<File> = dataDirs(), path: List<File> = searchPath()): List<DesktopApp> {
        val seen = HashSet<String>()
        val out = ArrayList<DesktopApp>()
        for (d in dirs) {
            val root = File(d, "applications").takeIf { it.isDirectory } ?: continue
            root.walkTopDown().filter { it.isFile && it.name.endsWith(".desktop") }.sortedBy { it.path }.forEach { f ->
                val id = f.relativeTo(root).path.replace('/', '-').removeSuffix(".desktop")
                if (!seen.add(id)) return@forEach
                entry(id, f.readText(), dirs, path)?.let(out::add)
            }
        }
        return out.sortedBy { it.label.lowercase() }.also { cache = it; scannedAt = System.nanoTime() }
    }

    /** How the engine knows [key]: a program path is itself; an entry's processes come from its Exec line. */
    fun matchers(key: String): Matchers {
        if (key.startsWith('/')) return Matchers(paths = listOf(key))
        // An app installed since the last scan is found by reading the entries again, at most every 10 s (an uninstalled one never is).
        val fresh = System.nanoTime() - scannedAt < 10_000_000_000L && scannedAt != 0L
        return (cache.firstOrNull { it.key == key } ?: if (fresh) null else scan().firstOrNull { it.key == key })?.matchers ?: Matchers()
    }

    /** The app [processPath] belongs to, for statistics: one of [routed] first, then any entry, else the path itself. */
    fun keyOf(processPath: String, routed: Collection<String>): String {
        if (processPath.isEmpty()) return "?"
        routed.firstOrNull { matches(matchers(it), processPath) }?.let { return it }
        return cache.firstOrNull { matches(it.matchers, processPath) }?.key ?: processPath
    }

    /** What the engine does with [m] ([app.unbraid.vpn.Linux]): an exact path, a folder prefix or a program name. */
    fun matches(m: Matchers, path: String) = path in m.paths || m.dirs.any { path.startsWith(it) } || File(path).name in m.names

    /** A desktop entry's app, or null for one that isn't a launchable application. */
    internal fun entry(id: String, text: String, dirs: List<File> = dataDirs(), path: List<File> = searchPath()): DesktopApp? {
        val e = parse(text)
        if (e["Type"] != "Application" || e["Hidden"] == "true" || id == "unbraid") return null
        val exec = e["Exec"]?.let(::exec)?.takeIf { it.isNotEmpty() } ?: return null
        e["TryExec"]?.let { t -> if (which(t, path) == null) return null }
        val flatpak = e["X-Flatpak"] ?: exec.takeIf { File(it[0]).name == "flatpak" }?.let { a -> a.drop(a.indexOf("run") + 1).firstOrNull { !it.startsWith("-") } }
        val m = if (flatpak == null) resolve(exec, path)
            else Matchers(names = listOfNotNull(exec.firstOrNull { it.startsWith("--command=") }?.removePrefix("--command=")?.let { File(it).name } ?: flatpakCommand(flatpak)))
        return DesktopApp(id, e["Name"] ?: id, e["NoDisplay"] == "true", e["Icon"]?.let { icon(it, dirs) }, m)
    }

    /** The [Desktop Entry] group's keys (unlocalized: the app is English only). */
    internal fun parse(text: String): Map<String, String> {
        val out = HashMap<String, String>()
        var inEntry = false
        for (raw in text.lineSequence()) {
            val line = raw.trim()
            if (line.startsWith('[')) { inEntry = line == "[Desktop Entry]"; continue }
            if (!inEntry || line.startsWith('#')) continue
            val i = line.indexOf('=').takeIf { it > 0 } ?: continue
            val k = line.substring(0, i).trim()
            if ('[' !in k) out.putIfAbsent(k, line.substring(i + 1).trim())
        }
        return out
    }

    /** An Exec line's arguments, as the desktop entry spec quotes them, without field codes (%f, %U…). */
    internal fun exec(line: String): List<String> {
        val args = ArrayList<String>()
        val cur = StringBuilder()
        var quoted = false
        var any = false
        var i = 0
        while (i < line.length) {
            val c = line[i]
            when {
                c == '"' -> { quoted = !quoted; any = true }
                c == '\\' && quoted && i + 1 < line.length -> { cur.append(line[++i]) }
                c == ' ' && !quoted -> { if (cur.isNotEmpty() || any) args += cur.toString(); cur.clear(); any = false }
                else -> cur.append(c)
            }
            i++
        }
        if (cur.isNotEmpty() || any) args += cur.toString()
        return args.filterNot { Regex("%[a-zA-Z]").matches(it) }.map { it.replace("%%", "%") }
    }

    /** The processes [argv] starts, as far as can be known without running it. */
    internal fun resolve(argv: List<String>, path: List<File>): Matchers {
        // "env VAR=x program …" runs the program.
        val a = if (File(argv[0]).name == "env") argv.drop(1).dropWhile { '=' in it && !it.startsWith('/') } else argv
        val prog = a.firstOrNull() ?: return Matchers()
        // A snap runs from /snap/<name>/<revision>/…, whichever revision is installed.
        if (prog.startsWith("/snap/bin/")) return Matchers(dirs = listOf("/snap/${File(prog).name.substringBefore('.')}/"))
        if (prog == "snap" && a.getOrNull(1) == "run") a.getOrNull(2)?.let { return Matchers(dirs = listOf("/snap/${it.substringBefore('.')}/")) }
        val exe = which(prog, path) ?: return Matchers(names = listOf(File(prog).name))
        val real = exe.canonicalFile
        if (elf(real)) return Matchers(paths = listOf(real.path), dirs = listOfNotNull(installDir(real.parentFile)))
        // A launcher script: the programs it names in its own folders, its folder, and its name (often the program's too).
        val targets = scriptTargets(real)
        return Matchers(paths = targets.map { it.path }, dirs = (targets.mapNotNull { installDir(it.parentFile) } + listOfNotNull(installDir(real.parentFile))).distinct(), names = listOf(exe.name))
    }

    /** [prog] as the shell would find it on [path]. */
    internal fun which(prog: String, path: List<File>): File? =
        if ('/' in prog) File(prog).takeIf { it.isFile && it.canExecute() } else path.map { File(it, prog) }.firstOrNull { it.isFile && it.canExecute() }

    fun searchPath() = ((env["PATH"] ?: "").split(':') + listOf("/usr/local/bin", "/usr/bin", "/bin", "/usr/games", "/snap/bin")).filter { it.isNotEmpty() }.distinct().map(::File)

    private fun elf(f: File) = runCatching { f.inputStream().use { s -> ByteArray(4).also { s.read(it) } }.contentEquals(byteArrayOf(0x7f, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte())) }.getOrDefault(false)

    /** Programs a shell script starts by absolute path, outside the shared system folders (where /bin/sh and friends live). */
    private fun scriptTargets(f: File): List<File> {
        val text = runCatching { f.inputStream().use { String(it.readNBytes(65_536)) } }.getOrNull()?.takeIf { it.startsWith("#!") } ?: return emptyList()
        return Regex("""(/[A-Za-z0-9._+\-/]+)""").findAll(text).map { File(it.value) }.distinct()
            .filter { it.isFile && it.canExecute() && installDir(it.parentFile) != null && elf(it) }.map { it.canonicalFile }.distinct().toList()
    }

    /**
     * The folder an app is installed in, so its helper programs follow it too ("…/bin" counts as its parent); null for
     * folders many programs share, where only exact paths are safe.
     */
    internal fun installDir(d: File?): String? {
        d ?: return null
        val dir = if (d.name == "bin" && !shared(d.parentFile)) d.parentFile else d
        return if (shared(dir)) null else dir.path.trimEnd('/') + "/"
    }

    private fun shared(d: File?): Boolean {
        val p = d?.path?.trimEnd('/')?.ifEmpty { "/" } ?: return true
        return p in SHARED || p == home || p.startsWith("$home/") && p.removePrefix("$home/") in setOf("bin", ".local", ".local/bin", ".local/share", "Applications", "Downloads", "Desktop") ||
            Regex("/usr/lib(32|64)?/[a-z0-9_]+-linux-gnu[a-z0-9_]*").matches(p) || p.count { it == '/' } < 2
    }

    private val SHARED = setOf("/", "/bin", "/sbin", "/lib", "/lib64", "/usr", "/usr/bin", "/usr/sbin", "/usr/games", "/usr/lib", "/usr/lib32", "/usr/lib64",
        "/usr/libexec", "/usr/share", "/usr/local", "/usr/local/bin", "/usr/local/sbin", "/usr/local/games", "/usr/local/lib", "/usr/local/share", "/opt",
        "/snap", "/snap/bin", "/var/lib/flatpak/exports/bin", "/tmp", "/var/tmp")

    /** A Flatpak's command (inside its sandbox) from its metadata, as the engine sees its process name. */
    private fun flatpakCommand(appId: String): String? =
        listOf("$home/.local/share/flatpak", "/var/lib/flatpak").map { File(it, "app/$appId/current/active/metadata") }.firstOrNull { it.isFile }
            ?.readLines()?.firstOrNull { it.startsWith("command=") }?.removePrefix("command=")?.trim()?.let { File(it).name }
            ?: appId.substringAfterLast('.').lowercase().takeIf { it.isNotEmpty() }

    /** An entry's icon file: an absolute path, else the hicolor theme (the one every app installs into) or pixmaps. */
    internal fun icon(name: String, dirs: List<File>): File? {
        if (name.startsWith('/')) return File(name).takeIf { it.isFile }
        val sizes = listOf("128x128", "96x96", "64x64", "256x256", "48x48", "scalable", "512x512", "32x32")
        val roots = (listOf(File("$home/.icons")) + dirs.map { File(it, "icons") })
        for (s in sizes) for (r in roots) for (ext in listOf("png", "svg")) File(r, "hicolor/$s/apps/$name.$ext").takeIf { it.isFile }?.let { return it }
        return dirs.map { File(it, "pixmaps") }.flatMap { p -> listOf("png", "svg").map { File(p, "$name.$it") } }.firstOrNull { it.isFile }
    }
}
