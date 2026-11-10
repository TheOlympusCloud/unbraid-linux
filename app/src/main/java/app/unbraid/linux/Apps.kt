package app.unbraid.linux

import app.unbraid.APP
import app.unbraid.vpn.Matchers
import java.io.File

/**
 * An app the Apps page lists: [key] is what the setup routes (a desktop entry's id, or a program's path). An app the
 * engine can't tell from another one [follows] that app's key and takes its route ([Apps.shareRoutes]); [argc] is the
 * length of its Exec line.
 */
data class DesktopApp(val key: String, val label: String, val system: Boolean, val icon: File?, val matchers: Matchers, val follows: String? = null, val argc: Int = 0)

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
    fun scan(dirs: List<File> = dataDirs(), path: List<File> = searchPath(), installs: List<File> = flatpakInstalls()): List<DesktopApp> {
        val seen = HashSet<String>()
        val out = ArrayList<DesktopApp>()
        for (d in dirs) {
            val root = File(d, "applications").takeIf { it.isDirectory } ?: continue
            root.walkTopDown().filter { it.isFile && it.name.endsWith(".desktop") }.sortedBy { it.path }.forEach { f ->
                val id = f.relativeTo(root).path.replace('/', '-').removeSuffix(".desktop")
                if (!seen.add(id)) return@forEach
                entry(id, f.readText(), dirs, path, installs)?.let(out::add)
            }
        }
        return shareRoutes(out).sortedBy { it.label.lowercase() }.also { cache = it; scannedAt = System.nanoTime() }
    }

    /**
     * Apps the engine can't tell apart (LibreOffice's Writer and Calc, a browser and its web apps, two Firefoxes) are one
     * app to it: the plainest launcher among them (not a system one, the shortest Exec line) takes all their matchers, and
     * the others follow its route. Otherwise whichever rule came first would route them all, whatever their rows said.
     */
    internal fun shareRoutes(apps: List<DesktopApp>): List<DesktopApp> {
        val out = apps.associateByTo(LinkedHashMap()) { it.key }
        val left = apps.filterTo(ArrayList()) { !it.matchers.empty }
        while (left.isNotEmpty()) {
            val group = arrayListOf(left.removeAt(0))
            var i = 0
            while (i < group.size) { val g = group[i++]; left.filter { overlap(g.matchers, it.matchers) }.forEach { left.remove(it); group += it } }
            if (group.size == 1) continue
            val head = group.minWith(compareBy({ it.system }, { it.argc }, { it.label.lowercase() }, { it.key }))
            val all = Matchers(group.flatMap { it.matchers.paths }.distinct(), group.flatMap { it.matchers.dirs }.distinct(), group.flatMap { it.matchers.names }.distinct())
            group.forEach { out[it.key] = if (it === head) it.copy(matchers = all) else it.copy(matchers = Matchers(), follows = head.key) }
        }
        return out.values.toList()
    }

    /** Whether one process could match both [a] and [b]. A name is a program file's name; one in a matched folder counts too. */
    private fun overlap(a: Matchers, b: Matchers): Boolean {
        fun inDirs(n: String, m: Matchers) = m.dirs.any { File(it, n).isFile || File(it, "bin/$n").isFile }
        return a.paths.any { matches(b, it) } || b.paths.any { matches(a, it) } || a.dirs.any { d -> b.dirs.any { it.startsWith(d) || d.startsWith(it) } } ||
            a.names.any { it in b.names || inDirs(it, b) } || b.names.any { inDirs(it, a) }
    }

    /** How the engine knows [key]: a program path is itself; an entry's processes come from its Exec line. */
    fun matchers(key: String): Matchers {
        // A program an app runs (one added before that app was installed) takes the app's route, never a rule of its own.
        if (key.startsWith('/')) return if (cache.any { matches(it.matchers, key) }) Matchers() else Matchers(paths = listOf(key))
        // An app installed since the last scan is found by reading the entries again, at most every 10 s (an uninstalled one never is).
        val fresh = System.nanoTime() - scannedAt < 10_000_000_000L && scannedAt != 0L
        return (cache.firstOrNull { it.key == key } ?: if (fresh) null else scan().firstOrNull { it.key == key })?.matchers ?: Matchers()
    }

    /** [key]'s icon file, from the last scan. */
    fun iconFile(key: String): File? = cache.firstOrNull { it.key == key }?.icon

    /** The app [processPath] belongs to, for statistics: one of [routed] first, then any entry, else the path itself. */
    fun keyOf(processPath: String, routed: Collection<String>): String {
        if (processPath.isEmpty()) return "?"
        routed.firstOrNull { matches(matchers(it), processPath) }?.let { return it }
        return cache.firstOrNull { matches(it.matchers, processPath) }?.key ?: processPath
    }

    /** What the engine does with [m] ([app.unbraid.vpn.Linux]): an exact path, a folder prefix or a program name. */
    fun matches(m: Matchers, path: String) = path in m.paths || m.dirs.any { path.startsWith(it) } || File(path).name in m.names

    /** A desktop entry's app, or null for one that isn't a launchable application. */
    internal fun entry(id: String, text: String, dirs: List<File> = dataDirs(), path: List<File> = searchPath(), installs: List<File> = flatpakInstalls()): DesktopApp? {
        val e = parse(text)
        if (e["Type"] != "Application" || e["Hidden"] == "true" || id == "unbraid") return null
        val exec = e["Exec"]?.let(::exec)?.takeIf { it.isNotEmpty() } ?: return null
        e["TryExec"]?.let { t -> if (which(t, path) == null) return null }
        val flatpak = e["X-Flatpak"] ?: exec.takeIf { File(it[0]).name == "flatpak" }?.let { a -> a.drop(a.indexOf("run") + 1).firstOrNull { !it.startsWith("-") } }
        val m = if (flatpak == null) resolve(exec, path)
            else Matchers(names = flatpakNames(flatpak, exec.firstOrNull { it.startsWith("--command=") }?.removePrefix("--command="), installs))
        return DesktopApp(id, e["Name"] ?: id, e["NoDisplay"] == "true", e["Icon"]?.let { icon(it, dirs) }, m, argc = exec.size)
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

    /**
     * The processes [argv] starts, as far as the engine can tell them apart: it knows a process by its program file (its
     * /proc exe), which for a script is its interpreter, for a Windows program Wine and for an AppImage a program in a
     * mount of its own. Those give no matcher, so the app is shown following the default route rather than on one it
     * would never take, or one that would move every other program they run.
     */
    internal fun resolve(argv: List<String>, path: List<File>): Matchers {
        val prog = argv.firstOrNull() ?: return Matchers()
        // A snap runs from /snap/<name>/<revision>/…, whichever revision is installed.
        if (prog.startsWith("/snap/bin/")) return Matchers(dirs = listOf("/snap/${File(prog).name.substringBefore('.')}/"))
        if (prog == "snap" && argv.getOrNull(1) == "run") argv.getOrNull(2)?.let { return Matchers(dirs = listOf("/snap/${it.substringBefore('.')}/")) }
        val found = which(prog, path)
        val real = found?.canonicalFile
        if (wrapper(File(prog)) || real != null && wrapper(real)) {
            // firejail's links (firecfg): /usr/local/bin/firefox runs the next firefox on the PATH, in its sandbox.
            if (found != null && !wrapper(found)) return resolve(listOf(found.name) + argv.drop(1), path.dropWhile { it != found.parentFile }.drop(1))
            // "env A=1 prog", "nice -n 5 prog", "prime-run prog": the program they start; none for "gtk-launch app.desktop".
            val at = (1 until argv.size).firstOrNull { i -> argv[i].let { it.startsWith("/snap/bin/") || !it.startsWith("-") && '=' !in it && which(it, path) != null } }
            return at?.let { resolve(argv.drop(it), path) } ?: Matchers()
        }
        if (found == null || real == null) return Matchers()
        if (runtime(found) || runtime(real)) return Matchers()
        if (elf(real)) return program(real)
        // A launcher script: the programs it starts by path, and the folder it is installed in when its programs live there.
        val text = script(real) ?: return Matchers()
        val dir = installDir(real.parentFile)
        // One whose own work runs on an interpreter other apps share (#!/usr/bin/python3, "exec java -jar app.jar") is that
        // interpreter's traffic, whatever else its folder holds.
        if (runsShared(text, dir)) return Matchers()
        val targets = scriptTargets(text).filterNot { runtime(it) || wrapper(it) }.map { it.canonicalFile }.distinct().filter { program(it) != Matchers() }
        val own = dir?.takeIf { holdsPrograms(File(it)) }
        return Matchers(paths = targets.map { it.path }, dirs = (targets.mapNotNull { installDir(it.parentFile) } + listOfNotNull(own)).distinct())
    }

    /** A program file as the engine knows it: none for an interpreter or a wrapper (every program it runs would match) or an AppImage. */
    private fun program(f: File) = if (runtime(f) || wrapper(f) || appImage(f)) Matchers() else Matchers(paths = listOf(f.path), dirs = listOfNotNull(installDir(f.parentFile)))

    /** Why the engine couldn't tell [f]'s traffic apart from other programs', or null for a program file it can. */
    fun unroutable(f: File): String? {
        val real = runCatching { f.canonicalFile }.getOrNull()?.takeIf { it.isFile } ?: return "${f.name} isn't a program this computer can run."
        return when {
            appImage(real) -> "${f.name} is an AppImage: its programs run from a new folder each time, so $APP can't recognize them."
            head(real, 2).contentEquals("MZ".toByteArray()) -> "${f.name} is a Windows program: Wine runs it, as it runs every other one, so $APP can't tell them apart."
            !real.canExecute() -> "${f.name} isn't a program this computer can run."
            !elf(real) && script(real) != null -> "${f.name} is a script: its traffic comes from the interpreter that runs it, which other programs share."
            !elf(real) -> "${f.name} isn't a Linux program: what runs it runs other programs too, so $APP can't tell them apart."
            runtime(f) || runtime(real) -> "${f.name} runs other programs too: routing it would move them all."
            wrapper(f) || wrapper(real) -> "${f.name} only starts other programs: add the program it starts instead."
            else -> null
        }
    }

    /**
     * Interpreters and runtimes, whose processes are every program they run: scripts, Windows programs (Wine, whose loader
     * is the process on Arch), .NET and Mono programs, Electron apps on a shared Electron, guests of qemu, programs started
     * through the dynamic loader. A version may follow the name (python3.13, guile-3.0, electron37).
     */
    private val RUNTIMES = Regex("(python|pypy|perl|ruby|lua|luajit|php|tclsh|wish|node|nodejs|deno|bun|java|pwsh|gjs|gjs-console|cjs|cjs-console|R|Rscript|julia|guile|" +
        "wine|wine64|wine-preloader|wine64-preloader|mono|mono-sgen|dotnet|electron|qemu-[a-z0-9_-]+|ld-linux[a-z0-9_-]*\\.so|ld-musl-[a-z0-9_]+\\.so)[0-9.-]*")

    /** Shells and awk: interpreters too, but also the tools launcher scripts are written in, so only their own files count. */
    private val SHELLS = Regex("(sh|bash|dash|zsh|fish|ksh|mksh|tcsh|csh|busybox|gawk|mawk|awk)[0-9.-]*")

    /**
     * Programs that start another one and carry none of its traffic: the environment, priority, GPU, game, sandbox and
     * proxy wrappers, and launchers that hand the start to the desktop (gtk-launch, kioclient, xdg-open).
     */
    private val WRAPPERS = Regex("env|nice|ionice|taskset|chrt|nohup|setsid|stdbuf|timeout|sudo|pkexec|doas|firejail|bwrap|flatpak|flatpak-spawn|zypak-wrapper|" +
        "systemd-run|systemd-inhibit|dbus-run-session|dbus-launch|xvfb-run|prime-run|optirun|primusrun|pvkrun|gamemoderun|mangohud|obs-gamecapture|gamescope|" +
        "strace|ltrace|torsocks|proxychains4?|unshare|kstart[56]?|gtk-launch|kioclient[56]?|kde-open[56]?|gio|gapplication|dex|exo-open|xdg-open|" +
        "toolbox|distrobox-enter|podman|docker")

    private fun runtime(f: File) = RUNTIMES.matches(f.name) || SHELLS.matches(f.name)
    private fun wrapper(f: File) = WRAPPERS.matches(f.name)

    /**
     * Whether a launcher script's own work runs on an interpreter other apps share: its shebang's, or one it starts by
     * name, or by a path outside [dir], its own folder (an app's bundled Java is its own). Shells and awk don't count.
     */
    private fun runsShared(text: String, dir: String?): Boolean {
        val lines = text.lines()
        val bang = lines.first().removePrefix("#!").trim().split(WS)
        if (bang.drop(if (File(bang[0]).name == "env") 1 else 0).firstOrNull { !it.startsWith("-") }?.let { RUNTIMES.matches(File(it).name) } == true) return true
        return lines.drop(1).filterNot { it.trimStart().startsWith("#") }.flatMap { it.split(Regex("&&|\\|\\||[;|&]")) }.any { cmd ->
            val w = cmd.trim().split(WS).dropWhile { it in SKIP || ASSIGN.matches(it) }.firstOrNull() ?: return@any false
            RUNTIMES.matches(File(w).name) && ('/' !in w || w.startsWith('/') && (dir == null || !w.startsWith(dir)))
        }
    }

    private val WS = Regex("\\s+")
    private val ASSIGN = Regex("[A-Za-z_][A-Za-z0-9_]*=.*")
    private val SKIP = setOf("then", "do", "else", "exec", "env", "nohup", "command")

    /** An AppImage (types 1 and 2): an ELF file marked "AI" and its type at byte 8. */
    private fun appImage(f: File) = head(f, 11).let { it.size == 11 && it[8] == 'A'.code.toByte() && it[9] == 'I'.code.toByte() && it[10] in 1..2 }

    /** A folder with an app's own programs in it (or in its bin/), which a launcher script there starts. */
    private fun holdsPrograms(d: File) = (d.listFiles().orEmpty().asList() + File(d, "bin").listFiles().orEmpty()).take(500)
        .any { it.isFile && it.canExecute() && !runtime(it) && !wrapper(it) && elf(it) && program(it.canonicalFile) != Matchers() }

    /** [prog] as the shell would find it on [path]. */
    internal fun which(prog: String, path: List<File>): File? =
        if ('/' in prog) File(prog).takeIf { it.isFile && it.canExecute() } else path.map { File(it, prog) }.firstOrNull { it.isFile && it.canExecute() }

    fun searchPath() = ((env["PATH"] ?: "").split(':') + listOf("/usr/local/bin", "/usr/bin", "/bin", "/usr/games", "/snap/bin")).filter { it.isNotEmpty() }.distinct().map(::File)

    private fun elf(f: File) = head(f, 4).contentEquals(byteArrayOf(0x7f, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte()))

    private fun head(f: File, n: Int): ByteArray = runCatching { f.inputStream().use { it.readNBytes(n) } }.getOrDefault(ByteArray(0))

    /**
     * A script's text (its first 64 KB), or null for a file that isn't one. Its plain assignments are put in where they
     * are used (APPNAME=chromium, LIBDIR=/usr/lib/$APPNAME, then "exec $LIBDIR/$APPNAME"), the first of each name.
     */
    private fun script(f: File): String? {
        val text = runCatching { f.inputStream().use { String(it.readNBytes(65_536)) } }.getOrNull()?.takeIf { it.startsWith("#!") } ?: return null
        val vars = HashMap<String, String>()
        Regex("""^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=["']?([A-Za-z0-9._+/${'$'}{}-]*)["']?\s*$""", RegexOption.MULTILINE).findAll(text).forEach { vars.putIfAbsent(it.groupValues[1], it.groupValues[2]) }
        var out = text
        repeat(3) { out = Regex("""\$\{?([A-Za-z_][A-Za-z0-9_]*)}?""").replace(out) { m -> vars[m.groupValues[1]] ?: m.value } }
        return out
    }

    /** Programs a launcher script names by absolute path, outside the shared system folders (where /bin/sh and friends live). */
    private fun scriptTargets(text: String): List<File> = Regex("""(/[A-Za-z0-9._+\-/]+)""").findAll(text).map { File(it.value) }.distinct()
        .filter { it.isFile && it.canExecute() && installDir(it.parentFile) != null && elf(it) }.toList()

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

    fun flatpakInstalls() = listOf(File(home, ".local/share/flatpak"), File("/var/lib/flatpak"))

    /**
     * A Flatpak's programs as the engine sees their processes, by name (inside its sandbox they run from /app): its command
     * ([command], else its metadata's), or the programs a launcher script there starts by path (Discord's, Signal's). None
     * for a command on an interpreter, nor for an app whose command isn't known (no guessing from its id).
     * shortcut: matched by name only, so another program of that name matches too; match by app id once the engine can.
     */
    private fun flatpakNames(appId: String, command: String?, installs: List<File>): List<String> {
        val app = installs.map { File(it, "app/$appId/current/active") }.firstOrNull { File(it, "metadata").isFile }
        val cmd = command ?: app?.let { File(it, "metadata").readLines() }?.firstOrNull { it.startsWith("command=") }?.removePrefix("command=")?.trim() ?: return emptyList()
        val name = listOf(File(cmd).name).filterNot { runtime(File(it)) || wrapper(File(it)) }
        val files = File(app ?: return name, "files")
        fun host(p: String) = File(files, p.removePrefix("/app/"))
        val f = if (cmd.startsWith("/app/")) host(cmd) else File(files, "bin/$cmd")
        val text = f.takeIf { it.isFile && !elf(it) }?.let(::script) ?: return name
        // By name, even an interpreter inside /app is every other one of its name.
        if (runsShared(text, null)) return emptyList()
        val targets = Regex("""/app/[A-Za-z0-9._+\-/]+""").findAll(text).map { host(it.value) }
            .filter { it.isFile && elf(it) && !runtime(it) && !wrapper(it) && !appImage(it) }.map { it.name }.distinct().toList()
        return targets.ifEmpty { name }
    }

    /** An entry's icon file: an absolute path, else the hicolor theme (the one every app installs into) or pixmaps. */
    internal fun icon(name: String, dirs: List<File>): File? {
        if (name.startsWith('/')) return File(name).takeIf { it.isFile }
        val sizes = listOf("128x128", "96x96", "64x64", "256x256", "48x48", "scalable", "512x512", "32x32")
        val roots = (listOf(File("$home/.icons")) + dirs.map { File(it, "icons") })
        for (s in sizes) for (r in roots) for (ext in listOf("png", "svg")) File(r, "hicolor/$s/apps/$name.$ext").takeIf { it.isFile }?.let { return it }
        return dirs.map { File(it, "pixmaps") }.flatMap { p -> listOf("png", "svg").map { File(p, "$name.$it") } }.firstOrNull { it.isFile }
    }
}
