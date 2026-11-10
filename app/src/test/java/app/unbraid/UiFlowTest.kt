package app.unbraid

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.ui.Modifier
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
import androidx.compose.ui.test.performScrollToNode
import androidx.compose.ui.test.isPopup
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.rightClick
import androidx.compose.ui.test.performMouseInput
import androidx.compose.ui.test.ComposeUiTest
import androidx.compose.ui.test.runDesktopComposeUiTest
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.unit.dp
import app.unbraid.data.DIRECT
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
        @BeforeClass @JvmStatic fun app() {
            Paths.data.listFiles()?.forEach { it.deleteRecursively() }
            val apps = File(Paths.data.parentFile, "applications").apply { deleteRecursively(); mkdirs() }
            // Each app its own program in its own folder (stand-ins, never run): apps on one program share its route.
            val programs = File(Paths.data.parentFile, "programs").apply { deleteRecursively() }
            fun program(id: String) = File(programs, "$id/$id").apply { parentFile.mkdirs(); writeBytes(byteArrayOf(0x7f, 69, 76, 70, 2, 1)); setExecutable(true) }
            listOf("firefox" to "Firefox", "spotify" to "Spotify", "org.gnome.Terminal" to "Terminal").forEach { (id, name) ->
                File(apps, "$id.desktop").writeText("[Desktop Entry]\nType=Application\nName=$name\nExec=${program(id).path} %u\n")
            }
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
                defaultRoute = "nl", apps = mapOf("firefox" to "us", "spotify" to "it", "org.gnome.Terminal" to DIRECT, "org.example.Tool" to "us", "firefox-private" to "it"), version = VERSION,
                // Here Private Browsing is the one of its group with a route: it leads, and keeps it.
                profiles = listOf(Profile("Work", "nl", mapOf("firefox-private" to "it"))),
            )
        }
        Onboarding.tourSeen()
        val ui = Ui()
        setContent { Box(Modifier.size(1280.dp, 800.dp).testTag("app")) { App(ui) } }
        onNodeWithText("DEFAULT ROUTE").assertIsDisplayed()
        onNodeWithText("Netherlands").assertIsDisplayed()
        shot("5-routes")
        click("Apps")
        onNodeWithText("Show my apps").performClick()
        onNodeWithText("Agree and continue").performClick()
        waitUntil(timeoutMillis = 10_000) { ui.apps.value.any { it.pkg == "spotify" } }
        // Two of a group with routes (Firefox's own and its private window's): the first keeps its route, and the other's is said.
        waitUntil(timeoutMillis = 10_000) { Unbraid.store.setup.value.apps["firefox-private"] == null }
        assertEquals(true, ui.notice.value?.contains("Private Browsing runs as Firefox, so it takes Firefox's route now."))
        ui.notice.value = null
        assertEquals(mapOf("firefox-private" to "it"), Unbraid.store.setup.value.profiles.single().apps)
        shot("6-apps")
        // An app that runs as a script loses the route it could never take, and its panel says it follows the default.
        waitUntil(timeoutMillis = 10_000) { Unbraid.store.setup.value.apps["org.example.Tool"] == null }
        onNodeWithTag("apps").performScrollToNode(hasText("Tool"))
        onNodeWithText("Tool").performClick()
        onNodeWithText("Follows the default route", substring = true).assertIsDisplayed()
        // A new entry for Firefox's program, whose label sorts first, doesn't take Firefox's route: it takes the route too.
        File(Paths.data.parentFile, "applications/alacarte-made-1.desktop").writeText("[Desktop Entry]\nType=Application\nName=Browser\nExec=${File(Paths.data.parentFile, "programs/firefox/firefox").path}\n")
        ui.refreshApps()
        waitUntil(timeoutMillis = 10_000) { ui.apps.value.any { it.pkg == "alacarte-made-1" } }
        waitForIdle()
        assertEquals("us", Unbraid.store.setup.value.apps["firefox"])
        assertEquals(mapOf("firefox-private" to "it"), Unbraid.store.setup.value.profiles.single().apps)
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
            assertNull(ui.addProgram(File(Paths.data.parentFile, "programs/spotify/spotify")))
            assertEquals(true, ui.notice.value?.contains("part of Spotify"))
            ui.notice.value = null // the refusal's notice, which would show on the next screens
        }
        click("Stats")
        shot("7-stats")
        click("Settings")
        shot("8-settings")
        click("Routes")
        onNodeWithText("Netherlands").performClick()
        shot("9-route-sheet")
    }
}
