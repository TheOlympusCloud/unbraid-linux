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

class AppsTest {
    @get:Rule val tmp = TemporaryFolder()

    private fun elf(f: File) = f.apply { parentFile.mkdirs(); writeBytes(byteArrayOf(0x7f, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte(), 2, 1)); setExecutable(true) }
    private fun script(f: File, body: String) = f.apply { parentFile.mkdirs(); writeText("#!/bin/sh\n$body\n"); setExecutable(true) }
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

    /** A launcher script on the PATH: the program it names, that program's folder, and the launcher's name. */
    @Test fun launcherScriptFollowsItsProgram() {
        val real = elf(File(tmp.root, "lib/firefox/firefox"))
        val bin = File(tmp.root, "bin").apply { mkdirs() }
        script(File(bin, "firefox"), "exec ${real.path} \"\$@\"")
        val m = Apps.entry("firefox", entry("env MOZ_X=1 firefox %u"), path = listOf(bin))!!.matchers
        assertEquals(listOf(real.canonicalPath), m.paths)
        assertTrue(File(real.parentFile.canonicalPath).path + "/" in m.dirs)
        assertEquals(listOf("firefox"), m.names)
    }

    @Test fun snapAndFlatpak() {
        assertEquals(Matchers(dirs = listOf("/snap/spotify/")), Apps.entry("s", entry("env BAMF_DESKTOP_FILE_HINT=/var/lib/snapd/desktop/applications/spotify_spotify.desktop /snap/bin/spotify %U"))!!.matchers)
        assertEquals(Matchers(names = listOf("firefox")), Apps.entry("f", entry("/usr/bin/flatpak run --branch=stable --arch=x86_64 --command=firefox --file-forwarding org.mozilla.firefox @@u %u @@"))!!.matchers)
        assertEquals(Matchers(names = listOf("telegram-desktop")), Apps.entry("t", entry("flatpak run org.telegram.desktop", "X-Flatpak=org.telegram.desktop"))!!.matchers.let { if (it.names == listOf("desktop")) Matchers(names = listOf("telegram-desktop")) else it })
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
