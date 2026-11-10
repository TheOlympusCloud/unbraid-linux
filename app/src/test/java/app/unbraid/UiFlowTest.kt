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
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.unit.dp
import app.unbraid.data.DIRECT
import app.unbraid.data.Location
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
import org.junit.Rule
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
    @get:Rule val compose = createComposeRule()

    companion object {
        private val key = "5p4RkybdRU5uaDi90eu4KZPTFif0lKCg4Qp6t1c4F30="

        /** One app per test JVM, as on Android: the store and onboarding are the process's. Fake desktop apps to route. */
        @BeforeClass @JvmStatic fun app() {
            Paths.data.listFiles()?.forEach { it.deleteRecursively() }
            val apps = File(Paths.data.parentFile, "applications").apply { deleteRecursively(); mkdirs() }
            listOf("firefox" to "Firefox", "spotify" to "Spotify", "org.gnome.Terminal" to "Terminal").forEach { (id, name) ->
                File(apps, "$id.desktop").writeText("[Desktop Entry]\nType=Application\nName=$name\nExec=/bin/true %u\n")
            }
            Unbraid.init()
            Onboarding.init()
        }
    }

    private fun shot(name: String) {
        compose.waitForIdle()
        val img = compose.onNodeWithTag("app").captureToImage().toAwtImage()
        ImageIO.write(img, "png", File("build/screenshots").apply { mkdirs() }.resolve("$name.png"))
    }

    private fun SemanticsNodeInteractionsProvider.click(text: String) = onAllNodesWithText(text).filterToOne(hasClickAction()).performClick()

    @Test fun a_welcomeTermsAndSignIn() {
        compose.setContent { Box(Modifier.size(440.dp, 900.dp).testTag("app")) { App(Ui()) } }
        compose.onNodeWithText("EVERY APP, ITS OWN", substring = true).assertIsDisplayed()
        shot("1-welcome")
        compose.onNodeWithText("Next").performClick()
        shot("2-welcome-routes")
        compose.onNodeWithText("Next").performClick()
        compose.onNodeWithText("I accept the Terms of use", substring = true).performClick()
        shot("3-terms")
        compose.onNodeWithText("Accept and continue").performClick()
        compose.onNodeWithText("Choose your VPN").assertIsDisplayed()
        compose.onNodeWithText("NordVPN").assertIsDisplayed()
        shot("4-sign-in")
    }

    /** A set-up app: provider routes, an imported WireGuard server, and desktop apps on routes and Direct. */
    @OptIn(ExperimentalTestApi::class)
    @Test fun b_screensOfASetUpApp() {
        val lab = WgPeer("Home lab", key, listOf("10.8.0.2/32"), key, endpoint = "203.0.113.7:51820", allowedIps = listOf("0.0.0.0/0"))
        Unbraid.store.update { s ->
            s.copy(
                routes = listOf(Route("nl", Location("nord", 153, "NL", "Netherlands")), Route("us", Location("nord", 228, "US", "United States"), hue = 1),
                    Route("it", Location("nord", 106, "IT", "Italy"), hue = 2), Route("lab", wg = lab, hue = 3)),
                defaultRoute = "nl", apps = mapOf("firefox" to "us", "spotify" to "it", "org.gnome.Terminal" to DIRECT), version = VERSION,
            )
        }
        Onboarding.tourSeen()
        val ui = Ui()
        compose.setContent { Box(Modifier.size(440.dp, 900.dp).testTag("app")) { App(ui) } }
        compose.onNodeWithText("DEFAULT ROUTE").assertIsDisplayed()
        compose.onNodeWithText("Netherlands").assertIsDisplayed()
        shot("5-routes")
        compose.click("Apps")
        compose.onNodeWithText("Show my apps").performClick()
        compose.onNodeWithText("Agree and continue").performClick()
        compose.waitUntil(10_000) { compose.onAllNodesWithText("Spotify").fetchSemanticsNodes().isNotEmpty() }
        shot("6-apps")
        // A program the launcher doesn't list is added by its file (the chooser is the desktop's own), keyed by its real path.
        compose.onNode(hasScrollToNodeAction()).performScrollToNode(hasText("Add a program"))
        compose.onNodeWithText("Add a program").assertIsDisplayed()
        compose.runOnIdle {
            assertEquals(File("/bin/true").canonicalPath, ui.addProgram(File("/bin/true")))
            assertNull(ui.addProgram(File(Paths.data, "unbraid_ui.properties")))
        }
        compose.click("Stats")
        shot("7-stats")
        compose.click("Settings")
        shot("8-settings")
        compose.click("Routes")
        compose.onNodeWithText("Netherlands").performClick()
        shot("9-route-sheet")
    }
}
