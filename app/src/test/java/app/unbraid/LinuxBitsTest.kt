package app.unbraid

import app.unbraid.linux.Autostart
import app.unbraid.linux.Desktop
import app.unbraid.linux.DesktopSettings
import app.unbraid.linux.Keyring
import app.unbraid.linux.SQLiteDatabase
import app.unbraid.linux.SQLiteOpenHelper
import app.unbraid.vpn.NetMonitor
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions

class LinuxBitsTest {
    @get:Rule val tmp = TemporaryFolder()

    private val header = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT"

    /** The computer's own default network, from the main routing table: tunnels aside, the lowest metric wins. */
    @Test fun defaultNetwork() {
        val f = tmp.newFile()
        f.writeText("$header\ntun0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\nwlp2s0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n" +
            "enp3s0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\nenp3s0\t0000000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n")
        assertEquals("enp3s0 10.0.0.1", NetMonitor(f).read())
        f.writeText("$header\nwlp2s0\t0001A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0\n")
        assertNull(NetMonitor(f).read())
        assertNull(NetMonitor(File(tmp.root, "missing")).read())
    }

    private fun fakeTool(store: File, fail: Boolean = false) = File(tmp.root, "secret-tool").apply {
        writeText("#!/bin/sh\n" + (if (fail) "exit 1\n" else "") + "case \"\$1\" in store) cat > '${store.path}';; lookup) [ -s '${store.path}' ] && cat '${store.path}' || exit 1;; esac\n")
        setExecutable(true)
    }

    /** The store's key goes into the keyring when there is one, and comes back from it; never a new one over an old. */
    @Test fun keyringKeepsTheKey() {
        val dir = tmp.newFolder(); val kept = File(tmp.root, "kept")
        val tool = fakeTool(kept).path
        val k = Keyring.key(dir, tool)
        assertEquals("keyring", File(dir, "key.where").readText())
        assertTrue(!File(dir, "key").exists() && kept.length() > 0)
        assertArrayEquals(k.encoded, Keyring.key(dir, tool).encoded)
        // The keyring said no (locked, gone): fail, don't start a key the sealed files can't be read with.
        assertTrue(runCatching { Keyring.key(dir, fakeTool(kept, fail = true).path) }.isFailure)
    }

    /** A keyring that never answers (an unlock prompt left open) fails in time instead of holding the app's start. */
    @Test fun keyringThatHangsTimesOut() {
        val dir = tmp.newFolder().apply { File(this, "key.where").writeText("keyring") }
        val hang = File(tmp.root, "hang").apply { writeText("#!/bin/sh\nsleep 30\n"); setExecutable(true) }
        val start = System.nanoTime()
        assertTrue(runCatching { Keyring.key(dir, hang.path, seconds = 1) }.isFailure)
        assertTrue("took ${(System.nanoTime() - start) / 1_000_000} ms", System.nanoTime() - start < 10_000_000_000L)
    }

    /** The engine's worker must say READY in time; one that hangs fails the config check instead of blocking it. */
    @Test fun workerStartIsBounded() {
        val socket = File(tmp.newFolder(), "w.sock")
        val hang = File(tmp.root, "hang-worker").apply { writeText("#!/bin/sh\nsleep 30\n"); setExecutable(true) }
        val start = System.nanoTime()
        assertTrue(runCatching { app.unbraid.vpn.Engine.startWorker(hang.path, socket, seconds = 1) }.isFailure)
        assertTrue("took ${(System.nanoTime() - start) / 1_000_000} ms", System.nanoTime() - start < 10_000_000_000L)
        val ready = File(tmp.root, "ready-worker").apply { writeText("#!/bin/sh\necho READY\nsleep 30\n"); setExecutable(true) }
        app.unbraid.vpn.Engine.startWorker(ready.path, socket, seconds = 5).destroyForcibly()
    }

    /** The desktop's light or dark: the portal's answer (ReadOne or Read), else GNOME's setting; one that says nothing is null. */
    @Test fun systemTheme() {
        assertEquals(true, Desktop.portalDark("v u 1"))
        assertEquals(false, Desktop.portalDark("v v u 2\n"))
        listOf("v u 0", null, "Call failed: No such interface", "").forEach { assertNull(it, Desktop.portalDark(it)) }
        assertEquals(true, Desktop.gnomeDark("'prefer-dark'\n"))
        assertEquals(false, Desktop.gnomeDark("'prefer-light'"))
        assertNull(Desktop.gnomeDark("'default'"))
        // System follows the desktop; a desktop that says nothing gets the app's own dark.
        assertEquals(false, DesktopSettings.dark(DesktopSettings.Theme.System, false))
        assertEquals(true, DesktopSettings.dark(DesktopSettings.Theme.System, null))
        assertEquals(false, DesktopSettings.dark(DesktopSettings.Theme.Light, true))
        assertEquals(true, DesktopSettings.dark(DesktopSettings.Theme.Dark, false))
    }

    /** Starting at login, with or without connecting and with or without the window; a change keeps the other choice. */
    @Test fun autostartChoices() {
        Autostart.set(false)
        Autostart.set(true, connect = false, minimised = true)
        assertTrue(Autostart.enabled && !Autostart.connects && Autostart.minimised)
        Autostart.set(true, connect = true, minimised = false)
        assertTrue(Autostart.connects && !Autostart.minimised)
        Autostart.set(true, minimised = true)
        assertTrue(Autostart.connects && Autostart.minimised)
        Autostart.set(false)
        assertTrue(!Autostart.enabled)
    }

    /** No keyring: a key file only this user can read. */
    @Test fun keyFileWithoutKeyring() {
        val dir = tmp.newFolder()
        val k = Keyring.key(dir, File(tmp.root, "no-such-tool").path)
        assertEquals("file", File(dir, "key.where").readText())
        assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(File(dir, "key").toPath())))
        assertArrayEquals(k.encoded, Keyring.key(dir, "no-such-tool").encoded)
    }

    /** Android's open helper: created at its version, upgraded from an older one, in place. */
    @Test fun sqliteHelperCreatesAndUpgrades() {
        val f = File(tmp.root, "s.db")
        class H(v: Int) : SQLiteOpenHelper(f, v) {
            val steps = ArrayList<String>()
            override fun onCreate(d: SQLiteDatabase) { steps += "create"; d.execSQL("CREATE TABLE t(a INTEGER, b TEXT)") }
            override fun onUpgrade(d: SQLiteDatabase, old: Int, new: Int) { steps += "upgrade $old>$new"; d.execSQL("ALTER TABLE t ADD COLUMN c INTEGER NOT NULL DEFAULT 7") }
        }
        H(1).apply { writableDatabase.execSQL("INSERT INTO t VALUES(?,?)", arrayOf(1, "x")); assertEquals(listOf("create"), steps); close() }
        H(2).apply {
            val rows = writableDatabase.rawQuery("SELECT a, b, c FROM t WHERE b = ?", arrayOf("x")).use { c -> buildList { while (c.moveToNext()) add(Triple(c.getLong(0), c.getString(1), c.getInt(2))) } }
            assertEquals(listOf(Triple(1L, "x", 7)), rows)
            assertEquals(listOf("upgrade 1>2"), steps)
            assertTrue(runCatching { writableDatabase.transaction { execSQL("INSERT INTO t VALUES(2,'y',0)"); error("rolled back") } }.isFailure)
            assertEquals(1, writableDatabase.rawQuery("SELECT COUNT(*) FROM t", emptyArray()).use { it.moveToNext(); it.getInt(0) })
            close()
        }
    }
}
