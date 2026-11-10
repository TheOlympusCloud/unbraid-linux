package app.unbraid

import app.unbraid.linux.Apps
import app.unbraid.vpn.Matchers
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.nio.file.Files

class AppsTest {
    @get:Rule val tmp = TemporaryFolder()

    private fun elf(f: File) = f.apply { parentFile.mkdirs(); writeBytes(byteArrayOf(0x7f, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte(), 2, 1)); setExecutable(true) }
    /** An AppImage (type 2): an ELF file with "AI" and 2 at byte 8. */
    private fun appImage(f: File) = f.apply { parentFile.mkdirs(); writeBytes(byteArrayOf(0x7f, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte(), 2, 1, 1, 0, 'A'.code.toByte(), 'I'.code.toByte(), 2, 0)); setExecutable(true) }
    private fun script(f: File, body: String) = f.apply { parentFile.mkdirs(); writeText("#!/bin/sh\n$body\n"); setExecutable(true) }
    private fun link(f: File, to: File) = f.apply { parentFile.mkdirs(); Files.createSymbolicLink(toPath(), to.toPath()) }
    private fun entry(exec: String, extra: String = "") = "[Desktop Entry]\nType=Application\nName=Thing\nName[de]=Ding\nExec=$exec\n$extra\n[Desktop Action new]\nExec=other\n"

    @Test fun parsesOnlyTheMainGroupUnlocalized() {
        val e = Apps.parse(entry("thing %U", "Icon=thing\n# Comment=x"))
        assertEquals("Thing", e["Name"]); assertEquals("thing %U", e["Exec"]); assertEquals("thing", e["Icon"])
    }

    @Test fun execLineAsTheSpecQuotesIt() {
        assertEquals(listOf("/opt/a b/run", "--flag", "x\"y", "100%"), Apps.exec("\"/opt/a b/run\" --flag \"x\\\"y\" %F 100%% %u"))
        assertEquals(listOf("env", "A=1", "prog", ""), Apps.exec("env A=1 prog \"\""))
    }

    /** A program in its own folder: its path, and the folder (its helpers run from there too). */
    @Test fun binaryInItsOwnFolder() {
        val bin = elf(File(tmp.root, "opt/game/bin/game"))
        val m = Apps.entry("game", entry(bin.path), path = emptyList())!!.matchers
        assertEquals(listOf(bin.canonicalPath), m.paths)
        assertEquals(listOf(File(tmp.root, "opt/game").canonicalPath + "/"), m.dirs) // ".../bin" counts as its parent
    }

    /** A launcher script on the PATH: the program it starts and that program's folder (the script itself runs as its shell). */
    @Test fun launcherScriptFollowsItsProgram() {
        val real = elf(File(tmp.root, "lib/firefox/firefox"))
        val bin = File(tmp.root, "bin").apply { mkdirs() }
        script(File(bin, "firefox"), "exec ${real.path} \"\$@\"")
        val m = Apps.entry("firefox", entry("env MOZ_X=1 firefox %u"), path = listOf(bin))!!.matchers
        assertEquals(listOf(real.canonicalPath), m.paths)
        assertTrue(File(real.parentFile.canonicalPath).path + "/" in m.dirs)
        assertEquals(emptyList<String>(), m.names)
    }

    /** Debian's Chromium starts its program through the launcher's own variables: "exec $LIBDIR/$APPNAME". */
    @Test fun launcherVariablesAreFollowed() {
        val real = elf(File(tmp.root, "usr/lib/chromium/chromium"))
        val launcher = script(File(tmp.root, "usr/bin/chromium"), "APPNAME=chromium\nLIBDIR=${tmp.root.path}/usr/lib/\$APPNAME\nexport CHROMIUM_FLAGS=\"\"\nexec \$LIBDIR/\$APPNAME \$CHROMIUM_FLAGS \"\$@\"")
        assertEquals(Matchers(listOf(real.canonicalPath), listOf(real.parentFile.canonicalPath + "/")), Apps.entry("c", entry("${launcher.path} %U"), path = emptyList())!!.matchers)
    }

    /**
     * The engine knows a process by its program file: a script's is its interpreter, shared with every other script it
     * runs. Such apps get no matcher, so they show as following the default route, never on one they wouldn't take.
     */
    @Test fun scriptsAndInterpretersMatchNothing() {
        val bin = File(tmp.root, "bin").apply { mkdirs() }
        elf(File(bin, "python3.13")).also { Files.createSymbolicLink(File(bin, "python3").toPath(), it.toPath()) }
        elf(File(bin, "dash")).also { Files.createSymbolicLink(File(bin, "sh").toPath(), it.toPath()) }
        script(File(bin, "yt-dlp"), "").writeText("#!/usr/bin/env python3\nimport yt_dlp\n")
        assertEquals(Matchers(), Apps.entry("a", entry("python3 /opt/foo/foo.py"), path = listOf(bin))!!.matchers)
        assertEquals(Matchers(), Apps.entry("b", entry("sh -c \"exec foo\""), path = listOf(bin))!!.matchers)
        assertEquals(Matchers(), Apps.entry("c", entry("yt-dlp %U"), path = listOf(bin))!!.matchers)
        assertEquals(Matchers(), Apps.entry("d", entry("env LANG=C python3 -m http.server"), path = listOf(bin))!!.matchers)
        assertEquals(Matchers(), Apps.entry("e", entry("missing-program"), path = listOf(bin))!!.matchers)
    }

    /** An AppImage's programs run from a mount of their own: no matcher either. */
    @Test fun appImagesMatchNothing() {
        val app = appImage(File(tmp.root, "Applications/Obsidian-1.6.AppImage"))
        assertEquals(Matchers(), Apps.entry("obsidian", entry(app.path), path = emptyList())!!.matchers)
    }

    /** A launcher script in the app's own folder (Chrome's, VS Code's) keeps that folder, where its programs live. */
    @Test fun launcherKeepsTheFolderItsProgramsLiveIn() {
        val dir = File(tmp.root, "opt/google/chrome")
        elf(File(dir, "chrome"))
        val launcher = script(File(dir, "google-chrome"), "HERE=\"\${0%/*}\"\nexec -a \"\$0\" \"\$HERE/chrome\" \"\$@\"")
        assertEquals(Matchers(dirs = listOf(dir.canonicalPath + "/")), Apps.entry("chrome", entry(launcher.path), path = emptyList())!!.matchers)
        // A script folder with only scripts (and interpreters) in it holds nothing the engine could match.
        val py = File(tmp.root, "opt/tool")
        elf(File(py, "bin/python3"))
        val tool = script(File(py, "tool"), "exec python3 -m tool")
        assertEquals(Matchers(), Apps.entry("tool", entry(tool.path), path = emptyList())!!.matchers)
    }

    /** Add a program says why it can't route a script, an interpreter, a wrapper or an AppImage, and takes an ordinary program. */
    @Test fun unroutableProgramsSayWhy() {
        assertNull(Apps.unroutable(elf(File(tmp.root, "opt/game/game"))))
        assertTrue(Apps.unroutable(script(File(tmp.root, "bin/tool"), "echo"))!!.contains("is a script"))
        assertTrue(Apps.unroutable(elf(File(tmp.root, "bin/python3.12")))!!.contains("runs other programs too"))
        assertTrue(Apps.unroutable(elf(File(tmp.root, "bin/nice")))!!.contains("only starts other programs"))
        assertTrue(Apps.unroutable(appImage(File(tmp.root, "App.AppImage")))!!.contains("is an AppImage"))
        assertTrue(Apps.unroutable(File(tmp.root, "Setup.exe").apply { writeBytes("MZ\u0090\u0000".toByteArray()) })!!.contains("Windows program"))
        assertTrue(Apps.unroutable(File(tmp.root, "nothing"))!!.contains("isn't a program"))
    }

    /**
     * Runtimes that run other programs as their own process: one app's route on them would move every program they run.
     * On Arch, every Windows program under Wine is /usr/bin/wine; Debian's gjs and guile are links to gjs-console and
     * guile-3.0; Arch's Electron apps share electron37.
     */
    @Test fun sharedRuntimesMatchNothing() {
        val bin = File(tmp.root, "bin").apply { mkdirs() }
        elf(File(bin, "wine"))
        link(File(bin, "gjs"), elf(File(bin, "gjs-console")))
        link(File(bin, "guile"), elf(File(bin, "guile-3.0")))
        elf(File(bin, "mono")); elf(File(bin, "dotnet")); elf(File(bin, "R")); elf(File(bin, "pwsh")); elf(File(bin, "wine64-preloader"))
        link(File(bin, "electron37"), elf(File(tmp.root, "lib/electron37/electron")))
        elf(File(bin, "qemu-x86_64-static")); elf(File(bin, "ld-linux-x86-64.so.2"))
        listOf("env WINEPREFIX=/x wine C:/a.lnk", "gjs /usr/share/org.gnome.Maps/main.js", "guile -s tool.scm", "mono x.exe", "dotnet app.dll",
            "electron37 /usr/lib/signal-desktop/app.asar %U", "R", "pwsh -File x.ps1", "wine64-preloader x.exe", "qemu-x86_64-static ./arm-app",
            "ld-linux-x86-64.so.2 /opt/app/app")
            .forEach { assertEquals(it, Matchers(), Apps.entry("x", entry(it), path = listOf(bin))!!.matchers) }
        listOf("wine", "gjs", "guile", "mono", "dotnet", "electron37", "R", "pwsh", "wine64-preloader", "qemu-x86_64-static", "ld-linux-x86-64.so.2")
            .forEach { assertTrue(it, Apps.unroutable(File(bin, it))!!.contains("runs other programs too")) }
    }

    /** A wrapper runs the program after it, which is what the engine sees; one that hands the start to the desktop gives none. */
    @Test fun wrappersRunTheProgramTheyStart() {
        val bin = File(tmp.root, "bin").apply { mkdirs() }
        val game = elf(File(tmp.root, "opt/game/game"))
        elf(File(bin, "nice")); elf(File(bin, "gtk-launch")); elf(File(bin, "firejail"))
        script(File(bin, "prime-run"), "__NV_PRIME_RENDER_OFFLOAD=1 exec \"\$@\"")
        script(File(bin, "xdg-open"), "exec /usr/bin/gio open \"\$1\"")
        val own = Apps.entry("g", entry(game.path), path = listOf(bin))!!.matchers
        listOf("nice -n 10 ${game.path}", "prime-run ${game.path} %U", "env A=1 nice ${game.path}", "firejail --private ${game.path}")
            .forEach { assertEquals(it, own, Apps.entry("x", entry(it), path = listOf(bin))!!.matchers) }
        listOf("gtk-launch org.example.App", "xdg-open https://example.org", "nice")
            .forEach { assertEquals(it, Matchers(), Apps.entry("x", entry(it), path = listOf(bin))!!.matchers) }
        // firejail's links (firecfg): firefox on the PATH is firejail, which runs the next firefox there.
        val ff = elf(File(tmp.root, "usr/bin/firefox"))
        link(File(tmp.root, "local/bin/firefox"), File(bin, "firejail"))
        assertEquals(listOf(ff.canonicalPath), Apps.entry("f", entry("firefox %u"), path = listOf(File(tmp.root, "local/bin"), File(tmp.root, "usr/bin")))!!.matchers.paths)
    }

    /**
     * A launcher whose own work runs on a shared interpreter is that interpreter's traffic, even in a folder with programs
     * of its own: its shebang's, one it runs by name, or one by a path outside its folder. A bundled Java is the app's own.
     */
    @Test fun launchersOnASharedInterpreterMatchNothing() {
        val python = elf(File(tmp.root, "usr/bin/python3"))
        val dir = File(tmp.root, "opt/foo").apply { elf(File(this, "helper")) }
        listOf("exec ${python.path} ${dir.path}/main.py \"\$@\"", "cd \"\${0%/*}\" && exec python3 main.py", "LANG=C python3 -m foo")
            .forEach { assertEquals(it, Matchers(), Apps.entry("x", entry(script(File(dir, "run.sh"), it).path), path = emptyList())!!.matchers) }
        File(dir, "run.py").apply { writeText("#!/usr/bin/env python3\nimport foo\n"); setExecutable(true) }
            .let { assertEquals(Matchers(), Apps.entry("p", entry(it.path), path = emptyList())!!.matchers) }
        val app = File(tmp.root, "opt/app").apply { elf(File(this, "jre/bin/java")); elf(File(this, "bin/helper")) }
        val launcher = script(File(app, "app.sh"), "exec ${app.path}/jre/bin/java -jar ${app.path}/app.jar \"\$@\"")
        assertEquals(Matchers(dirs = listOf(app.canonicalPath + "/")), Apps.entry("a", entry(launcher.path), path = emptyList())!!.matchers)
        // JetBrains' and VS Code's launchers start the app's own programs through variables, and stay routed.
        val idea = File(tmp.root, "opt/idea").apply { elf(File(this, "bin/fsnotifier")) }
        val ideaSh = script(File(idea, "bin/idea.sh"), "# Try \$IDEA_JDK, then \"java\" in \$PATH.\nJAVA_BIN=\$(command -v java)\n[ -x \"\$IDE_HOME/jbr/bin/java\" ] && JAVA_BIN=\"\$IDE_HOME/jbr/bin/java\"\nexec \"\$JAVA_BIN\" -classpath \"\$CLASS_PATH\" com.intellij.idea.Main \"\$@\"")
        assertEquals(Matchers(dirs = listOf(idea.canonicalPath + "/")), Apps.entry("i", entry(ideaSh.path), path = emptyList())!!.matchers)
        val code = File(tmp.root, "opt/code").apply { elf(File(this, "code")) }
        val codeSh = script(File(code, "bin/code"), "ELECTRON=\"\$VSCODE_PATH/code\"\nELECTRON_RUN_AS_NODE=1 \"\$ELECTRON\" \"\$CLI\" --ms-enable-electron-run-as-node \"\$@\"\nexit \$?")
        assertEquals(Matchers(dirs = listOf(code.canonicalPath + "/")), Apps.entry("c", entry(codeSh.path), path = emptyList())!!.matchers)
    }

    /**
     * Apps that run as one program (LibreOffice's Writer and Calc, a browser's web apps, a Flatpak of the same name) are one
     * app to the engine: the plainest launcher leads with all their matchers, the others follow it, and so do statistics.
     */
    @Test fun appsOnOneProgramShareARoute() {
        val office = elf(File(tmp.root, "opt/office/program/soffice"))
        val chrome = elf(File(tmp.root, "opt/chrome/chrome"))
        val other = elf(File(tmp.root, "opt/other/other"))
        val apps = File(tmp.root, "share/applications").apply { mkdirs() }
        fun add(id: String, name: String, exec: String, extra: String = "") = File(apps, "$id.desktop").writeText(entry(exec, extra).replace("Name=Thing", "Name=$name"))
        add("office", "Office", "${office.path} %U"); add("writer", "Writer", "${office.path} --writer %U"); add("calc", "Calc", "${office.path} --calc %U")
        add("chrome", "Chrome", "${chrome.path} %U"); add("chrome-yt", "YouTube", "${chrome.path} --profile-directory=Default --app-id=abc")
        add("chrome-flatpak", "Chrome Flatpak", "flatpak run --command=chrome com.google.Chrome")
        add("other", "Other", other.path); add("helper", "Office helper", "${office.path} --headless", "NoDisplay=true")
        val all = Apps.scan(listOf(File(tmp.root, "share")), path = emptyList(), installs = emptyList()).associateBy { it.key }
        assertEquals(mapOf("writer" to "office", "calc" to "office", "helper" to "office", "chrome-yt" to "chrome", "chrome-flatpak" to "chrome"),
            all.values.filter { it.follows != null }.associate { it.key to it.follows })
        assertEquals(Matchers(), all.getValue("writer").matchers)
        assertEquals(Matchers(listOf(chrome.canonicalPath), listOf(chrome.parentFile.canonicalPath + "/"), listOf("chrome")), all.getValue("chrome").matchers)
        assertEquals(listOf(other.canonicalPath), all.getValue("other").matchers.paths)
        assertEquals(Matchers(), Apps.matchers("writer"))
        assertEquals("office", Apps.keyOf(office.canonicalPath, emptyList()))
        // A program an app runs takes that app's route, never a rule of its own.
        assertEquals(Matchers(), Apps.matchers(chrome.canonicalPath))
        val lone = File(tmp.root, "elsewhere/tool").path
        assertEquals(listOf(lone), Apps.matchers(lone).paths)
    }

    /**
     * A Flatpak is known by its command's name inside its sandbox, or by the programs its launcher script starts there;
     * one on an interpreter, or whose command can't be known, has none.
     */
    @Test fun flatpakCommandsAsTheEngineSeesThem() {
        val inst = File(tmp.root, "flatpak")
        /** An installed Flatpak's files folder, its /app. */
        fun app(id: String, command: String) = File(inst, "app/$id/current/active").let { a ->
            a.mkdirs(); File(a, "metadata").writeText("[Application]\nname=$id\ncommand=$command\n"); File(a, "files")
        }
        app("com.discordapp.Discord", "com.discordapp.Discord").let { script(File(it, "bin/com.discordapp.Discord"), "exec zypak-wrapper /app/discord/Discord \"\$@\""); elf(File(it, "discord/Discord")) }
        app("org.example.Tool", "tool").let { File(it, "bin/tool").apply { parentFile.mkdirs(); writeText("#!/usr/bin/python3\nimport tool\n") } }
        app("org.example.Java", "jtool").let { script(File(it, "bin/jtool"), "exec /app/jre/bin/java -jar /app/jtool.jar"); elf(File(it, "jre/bin/java")) }
        app("org.telegram.desktop", "telegram-desktop").let { elf(File(it, "bin/telegram-desktop")) }
        fun names(id: String, extra: String = "") = Apps.entry("x", entry("/usr/bin/flatpak run $extra$id", "X-Flatpak=$id"), path = emptyList(), installs = listOf(inst))!!.matchers.names
        assertEquals(listOf("Discord"), names("com.discordapp.Discord"))
        assertEquals(emptyList<String>(), names("org.example.Tool"))
        assertEquals(emptyList<String>(), names("org.example.Java"))
        assertEquals(listOf("telegram-desktop"), names("org.telegram.desktop"))
        // Not installed where it can be read: its explicit command, never a guess from its id.
        assertEquals(listOf("firefox"), names("org.mozilla.firefox", "--command=firefox "))
        assertEquals(emptyList<String>(), names("com.spotify.Client"))
    }

    @Test fun snapAndFlatpak() {
        assertEquals(Matchers(dirs = listOf("/snap/spotify/")), Apps.entry("s", entry("env BAMF_DESKTOP_FILE_HINT=/var/lib/snapd/desktop/applications/spotify_spotify.desktop /snap/bin/spotify %U"))!!.matchers)
        assertEquals(Matchers(names = listOf("firefox")), Apps.entry("f", entry("/usr/bin/flatpak run --branch=stable --arch=x86_64 --command=firefox --file-forwarding org.mozilla.firefox @@u %u @@"), installs = emptyList())!!.matchers)
    }

    @Test fun hiddenOnesAndHelpers() {
        assertNull(Apps.entry("x", entry("thing", "Hidden=true")))
        assertNull(Apps.entry("x", entry("thing", "TryExec=/nonexistent/thing")))
        assertNull(Apps.entry("x", "[Desktop Entry]\nType=Link\nURL=https://example.org\n"))
        assertNull(Apps.entry("unbraid", entry("unbraid")))
        assertTrue(Apps.entry("x", entry("thing", "NoDisplay=true"), path = emptyList())!!.system)
    }

    /** Shared system folders never become a folder match: only exact programs there. */
    @Test fun sharedFoldersAreNeverMatchedWhole() {
        listOf("/usr/bin", "/usr/lib", "/usr/lib/x86_64-linux-gnu", "/opt", "/usr/share", "/snap/bin", "/tmp", System.getProperty("user.home") + "/.local/bin")
            .forEach { assertNull(it, Apps.installDir(File(it))) }
        assertEquals("/opt/spotify/", Apps.installDir(File("/opt/spotify")))
        assertEquals("/usr/share/code/", Apps.installDir(File("/usr/share/code/bin")))
    }

    /** Statistics name a connection by the routed app its process belongs to, else by its program. */
    @Test fun processesNameTheirApp() {
        assertEquals("/usr/bin/curl", Apps.keyOf("/usr/bin/curl", listOf("/usr/bin/wget")))
        assertEquals("/usr/bin/wget", Apps.keyOf("/usr/bin/wget", listOf("/usr/bin/wget")))
        assertEquals("?", Apps.keyOf("", emptyList()))
        assertTrue(Apps.matches(Matchers(dirs = listOf("/opt/game/")), "/opt/game/lib/helper"))
        assertTrue(Apps.matches(Matchers(names = listOf("firefox")), "/app/lib/firefox/firefox"))
    }

    @Test fun scanFindsEntriesOnceByPriority() {
        val hi = File(tmp.root, "hi/applications/sub").apply { mkdirs() }
        val lo = File(tmp.root, "lo/applications").apply { mkdirs() }
        File(hi, "a.desktop").writeText(entry("/bin/true").replace("Name=Thing", "Name=High"))
        File(lo, "sub-a.desktop").writeText(entry("/bin/true").replace("Name=Thing", "Name=Low"))
        File(lo, "b.desktop").writeText(entry("/bin/true").replace("Name=Thing", "Name=Beta"))
        val apps = Apps.scan(listOf(File(tmp.root, "hi"), File(tmp.root, "lo"), File(tmp.root, "missing")), path = emptyList())
        assertEquals(listOf("sub-a" to "High", "b" to "Beta").sortedBy { it.second.lowercase() }, apps.map { it.key to it.label })
    }
}
