package app.unbraid

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.onNodeWithContentDescription
import app.unbraid.stats.Stats
import org.junit.Assert.assertTrue
import app.unbraid.ui.Ink
import app.unbraid.ui.Tab
import app.unbraid.ui.Desk
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.toAwtImage
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.test.ExperimentalTestApi
import androidx.compose.ui.test.SemanticsNodeInteractionsProvider
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.captureToImage
import androidx.compose.ui.test.filterToOne
import androidx.compose.ui.test.hasClickAction
import androidx.compose.ui.test.hasScrollToNodeAction
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.hasContentDescription
import androidx.compose.ui.test.performScrollToNode
import androidx.compose.ui.test.isPopup
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.rightClick
import androidx.compose.ui.test.moveTo
import androidx.compose.ui.test.performMouseInput
import androidx.compose.ui.test.ComposeUiTest
import androidx.compose.ui.test.runDesktopComposeUiTest
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.unit.dp
import app.unbraid.data.DIRECT
import app.unbraid.data.City
import app.unbraid.data.Country
import app.unbraid.data.Location
import app.unbraid.data.Profile
import app.unbraid.data.Route
import app.unbraid.data.VERSION
import app.unbraid.data.WgPeer
import app.unbraid.linux.Paths
import app.unbraid.ui.Onboarding
import app.unbraid.ui.Ui
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.BeforeClass
import org.junit.FixMethodOrder
import org.junit.Test
import org.junit.runners.MethodSorters
import java.io.File
import javax.imageio.ImageIO

/**
 * The screens as a person first meets them, composed headless and clicked through: the welcome and terms, sign-in,
 * then Routes, Apps, Stats, Settings and the location picker of a set-up app. Each step leaves a screenshot in
 * build/screenshots, to set beside the Android app's.
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
class UiFlowTest {

    companion object {
        private val key = "5p4RkybdRU5uaDi90eu4KZPTFif0lKCg4Qp6t1c4F30="

        /** One app per test JVM, as on Android: the store and onboarding are the process's. Fake desktop apps to route. */
        /** The apps' stand-in programs: an /opt of their own, which the screenshots show (never this computer's paths). */
        val programs = File(System.getProperty("java.io.tmpdir"), "unbraid-ui-test/opt")

        @BeforeClass @JvmStatic fun app() {
            Paths.data.listFiles()?.forEach { it.deleteRecursively() }
            val apps = File(Paths.data.parentFile, "applications").apply { deleteRecursively(); mkdirs() }
            // Each app its own program in its own folder (stand-ins, never run): apps on one program share its route.
            programs.deleteRecursively()
            fun program(id: String) = File(programs, "$id/$id").apply { parentFile.mkdirs(); writeBytes(byteArrayOf(0x7f, 69, 76, 70, 2, 1)); setExecutable(true) }
            listOf("firefox" to "Firefox", "spotify" to "Spotify", "org.gnome.Terminal" to "Terminal", "chromium" to "Chromium", "thunderbird" to "Thunderbird",
                "signal-desktop" to "Signal", "discord" to "Discord", "code" to "Visual Studio Code", "libreoffice-startcenter" to "LibreOffice", "org.gimp.GIMP" to "GIMP").forEach { (id, name) ->
                File(apps, "$id.desktop").writeText("[Desktop Entry]\nType=Application\nName=$name\nExec=${program(id).path} %u\n")
            }
            // Runs as LibreOffice: Writer is the same program.
            File(apps, "libreoffice-writer.desktop").writeText("[Desktop Entry]\nType=Application\nName=LibreOffice Writer\nExec=${File(programs, "libreoffice-startcenter/libreoffice-startcenter").path} --writer %U\n")
            // A launcher script that starts its program through a variable it can't see into: the default route only.
            val steam = File(programs, "steam/steam").apply { parentFile.mkdirs(); writeText("#!/bin/sh\nexec \"\$HOME/.steam/steam.sh\" \"\$@\"\n"); setExecutable(true) }
            File(apps, "steam.desktop").writeText("[Desktop Entry]\nType=Application\nName=Steam\nExec=${steam.path} %U\n")
            // Runs as Firefox: it takes Firefox's route.
            File(apps, "firefox-private.desktop").writeText("[Desktop Entry]\nType=Application\nName=Private Browsing\nExec=${File(programs, "firefox/firefox").path} --private-window %u\n")
            // Runs as python3, like every other Python program: the engine can't tell it apart.
            File(apps, "org.example.Tool.desktop").writeText("[Desktop Entry]\nType=Application\nName=Tool\nExec=python3 /opt/tool/tool.py\n")
            Unbraid.init()
            Onboarding.init()
        }
    }

    private fun ComposeUiTest.shot(name: String) {
        waitForIdle()
        val img = onNodeWithTag("app").captureToImage().toAwtImage()
        ImageIO.write(img, "png", File("build/screenshots").apply { mkdirs() }.resolve("$name.png"))
    }

    /** A desktop window's size, as a person first sees the app: the sidebar, wide. */
    @OptIn(ExperimentalTestApi::class)
    private fun desktop(block: ComposeUiTest.() -> Unit) = runDesktopComposeUiTest(1280, 800) { block() }

    private fun SemanticsNodeInteractionsProvider.click(text: String) = onAllNodesWithText(text).filterToOne(hasClickAction()).performClick()

    @OptIn(ExperimentalTestApi::class)
    @Test fun a_welcomeTermsAndSignIn() = desktop {
        setContent { Box(Modifier.size(1280.dp, 800.dp).testTag("app")) { App(Ui()) } }
        onNodeWithText("EVERY APP, ITS OWN", substring = true).assertIsDisplayed()
        shot("1-welcome")
        onNodeWithText("Next").performClick()
        shot("2-welcome-routes")
        onNodeWithText("Next").performClick()
        onNodeWithText("I accept the Terms of use", substring = true).performClick()
        shot("3-terms")
        onNodeWithText("Accept and continue").performClick()
        onNodeWithText("Choose your VPN").assertIsDisplayed()
        onNodeWithText("NordVPN").assertIsDisplayed()
        shot("4-sign-in")
    }

    /** A set-up app: provider routes, an imported WireGuard server, and desktop apps on routes and Direct. */
    @OptIn(ExperimentalTestApi::class)
    @Test fun b_screensOfASetUpApp() = desktop {
        val lab = WgPeer("Home lab", key, listOf("10.8.0.2/32"), key, endpoint = "203.0.113.7:51820", allowedIps = listOf("0.0.0.0/0"))
        Unbraid.store.update { s ->
            s.copy(
                routes = listOf(Route("nl", Location("nord", 153, "NL", "Netherlands")), Route("us", Location("nord", 228, "US", "United States"), hue = 1),
                    Route("it", Location("nord", 106, "IT", "Italy"), hue = 2), Route("lab", wg = lab, hue = 3)),
                defaultRoute = "nl", apps = mapOf("firefox" to "us", "spotify" to "it", "org.gnome.Terminal" to DIRECT, "org.example.Tool" to "us", "firefox-private" to "it",
                    "thunderbird" to "us", "discord" to "it", "code" to DIRECT), version = VERSION,
                // Here Private Browsing is the one of its group with a route: it leads, and keeps it.
                // In Home both have one: the first keeps it, and the notice names the profile.
                profiles = listOf(Profile("Work", "nl", mapOf("firefox-private" to "it")), Profile("Home", "nl", mapOf("firefox" to "us", "firefox-private" to "it"))),
            )
        }
        Onboarding.tourSeen()
        // A week of recorded traffic, so Stats and the Apps table's Today column have something to show.
        Unbraid.store.update { it.copy(prefs = it.prefs.copy(stats = true)) }
        val routes = Unbraid.store.setup.value.routes.associateBy { it.id }
        val exit = { id: String -> Stats.idOf(routes.getValue(id)) }
        val written = java.util.concurrent.CountDownLatch(1)
        Stats.post {
            val hour = 3_600_000L
            val now = System.currentTimeMillis()
            for (h in 0 until 24 * 7) {
                val at = now - h * hour
                val w = 0.4 + 0.6 * kotlin.math.sin(h / 4.0).let { it * it } * if ((at / hour) % 24 in 1..6) 0.1 else 1.0
                Stats.add(at, "firefox", exit("us"), null, (3e6 * w).toLong(), (60e6 * w).toLong())
                Stats.add(at, "spotify", exit("it"), null, (1e6 * w).toLong(), (24e6 * w).toLong())
                Stats.add(at, "chromium", exit("nl"), null, (2e6 * w).toLong(), (38e6 * w).toLong())
                Stats.add(at, "thunderbird", exit("us"), null, (1e6 * w).toLong(), (6e6 * w).toLong())
                Stats.add(at, "discord", exit("it"), null, (2e6 * w).toLong(), (9e6 * w).toLong())
                Stats.add(at, "signal-desktop", exit("nl"), null, (1e6 * w).toLong(), (3e6 * w).toLong())
            }
            Stats.flushNow(force = true)
            written.countDown()
        }
        written.await(10, java.util.concurrent.TimeUnit.SECONDS)
        // Signed in to NordVPN, with its countries, so the location picker lists them (nothing is fetched: the list is new).
        Unbraid.store.account("nord", "test")
        Unbraid.store.countries("nord", listOf(
            Country(81, "Germany", "DE", 322, listOf(City(2, "Frankfurt"), City(3, "Berlin"), City(4, "Hamburg"))),
            Country(74, "France", "FR", 176, listOf(City(5, "Paris"), City(6, "Marseille"))),
            Country(106, "Italy", "IT", 120, listOf(City(15, "Milan"), City(16, "Rome"))),
            Country(108, "Japan", "JP", 113, listOf(City(14, "Tokyo"))),
            Country(153, "Netherlands", "NL", 214, listOf(City(1, "Amsterdam"))),
            Country(208, "Sweden", "SE", 98, listOf(City(8, "Stockholm"))),
            Country(209, "Switzerland", "CH", 131, listOf(City(7, "Zurich"))),
            Country(227, "United Kingdom", "GB", 440, listOf(City(9, "London"), City(10, "Manchester"))),
            Country(228, "United States", "US", 1960, listOf(City(11, "New York"), City(12, "Los Angeles"), City(13, "Chicago"))),
        ))
        val ui = Ui()
        setContent { Box(Modifier.size(1280.dp, 800.dp).testTag("app")) { App(ui) } }
        onNodeWithText("DEFAULT ROUTE").assertIsDisplayed()
        // The default route's card (the exits list names it too).
        onAllNodesWithText("Netherlands").filterToOne(hasClickAction()).assertIsDisplayed()
        shot("5-routes")
        click("Apps")
        onNodeWithText("Show my apps").performClick()
        onNodeWithText("Agree and continue").performClick()
        waitUntil(timeoutMillis = 10_000) { ui.apps.value.any { it.pkg == "spotify" } }
        // Two of a group with routes (Firefox's own and its private window's): the first keeps its route, and the other's is said.
        waitUntil(timeoutMillis = 10_000) { Unbraid.store.setup.value.apps["firefox-private"] == null }
        assertEquals(true, ui.notice.value?.contains("Private Browsing runs as Firefox, so it takes Firefox's route now."))
        assertEquals(true, ui.notice.value?.contains("Private Browsing runs as Firefox, so it takes Firefox's route now in Home."))
        ui.notice.value = null
        assertEquals(mapOf("firefox-private" to "it"), Unbraid.store.setup.value.profiles.first { it.name == "Work" }.apps)
        assertEquals(mapOf("firefox" to "us"), Unbraid.store.setup.value.profiles.first { it.name == "Home" }.apps)
        shot("6-apps")
        // An app that runs as a script loses the route it could never take, and its panel says it follows the default.
        waitUntil(timeoutMillis = 10_000) { Unbraid.store.setup.value.apps["org.example.Tool"] == null }
        onNodeWithTag("apps").performScrollToNode(hasText("Tool"))
        onNodeWithText("Tool").performClick()
        onNodeWithText("Follows the default route", substring = true).assertIsDisplayed()
        // A new entry for Firefox's program, whose label sorts first, doesn't take Firefox's route: it takes the route too.
        File(Paths.data.parentFile, "applications/alacarte-made-1.desktop").writeText("[Desktop Entry]\nType=Application\nName=Browser\nExec=${File(programs, "firefox/firefox").path}\n")
        ui.refreshApps()
        waitUntil(timeoutMillis = 10_000) { ui.apps.value.any { it.pkg == "alacarte-made-1" } }
        waitForIdle()
        assertEquals("us", Unbraid.store.setup.value.apps["firefox"])
        assertEquals(mapOf("firefox-private" to "it"), Unbraid.store.setup.value.profiles.first { it.name == "Work" }.apps)
        onNodeWithTag("apps").performScrollToNode(hasText("Browser"))
        onNodeWithText("Browser").performClick()
        onNodeWithText("Takes Firefox's route", substring = true).assertIsDisplayed()
        // So does one that runs as another app and has no route of its own here.
        onNodeWithTag("apps").performScrollToNode(hasText("Private Browsing"))
        onNodeWithText("Private Browsing").performClick()
        onNodeWithText("Takes Firefox's route", substring = true).assertIsDisplayed()
        shot("6-apps-runs-as-another")
        // A right click offers the routes at once.
        onNodeWithTag("apps").performScrollToNode(hasText("Spotify"))
        onAllNodesWithText("Spotify").filterToOne(hasClickAction()).performMouseInput { rightClick() }
        onAllNodesWithText("Italy").filterToOne(hasAnyAncestor(isPopup())).assertIsDisplayed()
        shot("6-apps-menu")
        onAllNodesWithText("United States").filterToOne(hasAnyAncestor(isPopup())).performClick()
        waitUntil(timeoutMillis = 5_000) { Unbraid.store.setup.value.apps["spotify"] == "us" }
        onAllNodesWithText("Spotify").filterToOne(hasClickAction()).performMouseInput { rightClick() }
        onAllNodesWithText("Italy").filterToOne(hasAnyAncestor(isPopup())).performClick()
        waitUntil(timeoutMillis = 5_000) { Unbraid.store.setup.value.apps["spotify"] == "it" }
        // A program the launcher doesn't list is added by its file (the chooser is the desktop's own), keyed by its real path.
        onNodeWithText("Add a program").assertIsDisplayed()
        runOnIdle {
            assertEquals(File("/bin/true").canonicalPath, ui.addProgram(File("/bin/true")))
            assertNull(ui.addProgram(File(Paths.data, "unbraid_ui.properties")))
            // A script runs as its interpreter, an AppImage from a mount of its own: neither can have a route of its own.
            val script = File(Paths.data, "tool.sh").apply { writeText("#!/bin/sh\necho hi\n"); setExecutable(true) }
            assertNull(ui.addProgram(script))
            val appImage = File(Paths.data, "App.AppImage").apply { writeBytes(byteArrayOf(0x7f, 69, 76, 70, 2, 1, 1, 0, 65, 73, 2, 0)); setExecutable(true) }
            assertNull(ui.addProgram(appImage))
            assertEquals(true, ui.notice.value?.contains("AppImage"))
            // A program an app runs takes that app's route: it can't have one of its own.
            assertNull(ui.addProgram(File(programs, "spotify/spotify")))
            assertEquals(true, ui.notice.value?.contains("part of Spotify"))
            ui.notice.value = null // the refusal's notice, which would show on the next screens
        }
        click("Stats")
        waitUntil(timeoutMillis = 10_000) { onAllNodesWithText("APPS · BY DATA").fetchSemanticsNodes().isNotEmpty() }
        shot("7-stats")
        // A tile opens its section, at a reading width; Back returns to the overview.
        onNodeWithText("Usage").performClick()
        waitUntil(timeoutMillis = 5_000) { onAllNodesWithText("by provider", substring = true, ignoreCase = true).fetchSemanticsNodes().isNotEmpty() }
        shot("7-stats-usage")
        onNodeWithContentDescription("Back").performClick()
        click("Settings")
        shot("8-settings")
        // Settings › Desktop: login, the tray, the window and the theme. Light turns the whole window at once.
        onNodeWithText("Desktop").performClick()
        onNodeWithText("Start minimised to the tray").assertIsDisplayed()
        shot("8-settings-desktop")
        onNodeWithText("Light").performClick()
        runOnIdle { assertEquals(app.unbraid.linux.DesktopSettings.Theme.Light, app.unbraid.linux.DesktopSettings.theme.value) }
        waitUntil(timeoutMillis = 5_000) { Ink.light }
        shot("8-settings-desktop-light")
        click("Apps")
        shot("6-apps-light")
        click("Routes")
        shot("5-routes-light")
        click("Settings")
        onNodeWithText("Dark").performClick()
        waitUntil(timeoutMillis = 5_000) { !Ink.light }
        // The window's keys: the pages, search, and the list of every shortcut (Esc closes it).
        fun key(k: Key, ctrl: Boolean = true) = keys(k, ctrl, shift = false, alt = false, ui, {}, {})
        runOnIdle { assertTrue(key(Key.Two)); assertEquals(Tab.Apps, Desk.tab.value) }
        runOnIdle { assertTrue(key(Key.Comma)); assertEquals(Tab.Settings, Desk.tab.value) }
        runOnIdle { assertTrue(key(Key.F)); assertEquals(Tab.Apps, Desk.tab.value) }
        waitUntil(timeoutMillis = 5_000) { Desk.pending.value == null } // the Apps page took the search
        runOnIdle { assertTrue(key(Key.Slash)) }
        onNodeWithText("KEYBOARD SHORTCUTS").assertIsDisplayed()
        shot("shortcuts")
        runOnIdle { assertTrue(key(Key.Escape, ctrl = false)) }
        waitUntil(timeoutMillis = 5_000) { onAllNodesWithText("KEYBOARD SHORTCUTS").fetchSemanticsNodes().isEmpty() }
        runOnIdle { assertTrue(!key(Key.Z)); Desk.tab.value = Tab.Settings }
        // A new route (Ctrl+N): the location picker, a dialog over the page; a country's cities open beside the list.
        runOnIdle { assertTrue(keys(Key.N, ctrl = true, shift = false, alt = false, ui, {}, {})) }
        waitUntil(timeoutMillis = 5_000) { onAllNodesWithText("CHOOSE A LOCATION").fetchSemanticsNodes().isNotEmpty() }
        shot("10-picker")
        onNodeWithTag("picker").performScrollToNode(hasText("All countries"))
        onNodeWithText("All countries").performClick()
        onNodeWithTag("picker").performScrollToNode(hasContentDescription("Cities and servers in Germany"))
        onNodeWithContentDescription("Cities and servers in Germany").performClick()
        waitUntil(timeoutMillis = 5_000) { onAllNodesWithText("in Germany", substring = true).fetchSemanticsNodes().isNotEmpty() }
        shot("10-picker-country")
        runOnIdle { assertTrue(keys(Key.Escape, ctrl = false, shift = false, alt = false, ui, {}, {})) }
        waitUntil(timeoutMillis = 5_000) { onAllNodesWithText("CHOOSE A LOCATION").fetchSemanticsNodes().isEmpty() }
        click("Routes")
        // Routes with the apps known: their names, and the default's share.
        waitUntil(timeoutMillis = 5_000) { onAllNodesWithText("Thunderbird", substring = true).fetchSemanticsNodes().isNotEmpty() }
        shot("5-routes-set-up")
        // A right click on a route offers what its sheet does.
        onAllNodesWithText("Netherlands").filterToOne(hasClickAction()).performMouseInput { rightClick() }
        onNodeWithText("Change location…").assertIsDisplayed()
        shot("9-route-menu")
        onNodeWithText("Change location…").performMouseInput { moveTo(Offset(-50f, -50f)) }
        onAllNodesWithText("Netherlands").filterToOne(hasClickAction()).performClick()
        shot("9-route-sheet")
    }

    /** The smallest window: the sidebar folds to a rail of icons whose names show on hover; the pages keep their layout. */
    @OptIn(ExperimentalTestApi::class)
    @Test fun c_smallestWindow() = runDesktopComposeUiTest(880, 600) {
        Desk.tab.value = Tab.Routes
        setContent { Box(Modifier.size(880.dp, 600.dp).testTag("app")) { App(Ui()) } }
        waitUntil(timeoutMillis = 5_000) { onAllNodesWithText("DEFAULT ROUTE").fetchSemanticsNodes().isNotEmpty() }
        onNodeWithContentDescription("Apps").assertIsDisplayed()
        assertTrue(onAllNodesWithText("Ctrl+2").fetchSemanticsNodes().isEmpty()) // no names, no keys: only icons
        shot("11-smallest-window")
    }
}
