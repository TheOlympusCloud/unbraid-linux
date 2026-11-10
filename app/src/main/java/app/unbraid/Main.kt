package app.unbraid

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.SharedTransitionLayout
import androidx.compose.animation.core.SeekableTransitionState
import androidx.compose.animation.core.rememberTransition
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.backhandler.BackHandler
import androidx.compose.ui.backhandler.PredictiveBackHandler
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.input.key.key
import androidx.compose.ui.input.key.type
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.unit.DpSize
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Tray
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import androidx.compose.ui.window.isTraySupported
import androidx.compose.ui.window.rememberWindowState
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.unbraid.linux.Desktop
import app.unbraid.linux.Paths
import app.unbraid.stats.Stats
import app.unbraid.ui.AppsDisclosure
import app.unbraid.ui.AppsScreen
import app.unbraid.ui.Caption
import app.unbraid.ui.Ink
import app.unbraid.ui.LimitSheet
import app.unbraid.ui.LocalScreen
import app.unbraid.ui.LocalShared
import app.unbraid.ui.NavBar
import app.unbraid.ui.Onboarding
import app.unbraid.ui.PickerScreen
import app.unbraid.ui.RoutesScreen
import app.unbraid.ui.SettingsScreen
import app.unbraid.ui.SignInScreen
import app.unbraid.ui.StatsScreen
import app.unbraid.ui.Tab
import app.unbraid.ui.TourOverlay
import app.unbraid.ui.TourStop
import app.unbraid.ui.Ui
import app.unbraid.ui.UnbraidTheme
import app.unbraid.ui.VpnDisclosure
import app.unbraid.ui.Welcome
import app.unbraid.ui.reselected
import app.unbraid.ui.settingsHub
import app.unbraid.ui.sharedRoute
import app.unbraid.ui.tap
import app.unbraid.vpn.UnbraidVpn
import app.unbraid.vpn.VpnState
import java.io.File
import java.net.StandardProtocolFamily
import java.net.UnixDomainSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.Channels
import java.nio.channels.ServerSocketChannel
import java.nio.channels.SocketChannel
import kotlin.concurrent.thread
import kotlin.coroutines.cancellation.CancellationException
import kotlin.system.exitProcess
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch

private const val USAGE = """Usage: unbraid [command]

  (none)            open the window (or bring the running one to the front)
  connect           connect, starting unbraid in the background if needed
  disconnect        end the connection
  pause [minutes]   pause for 5 to 60 minutes (15 by default; 0 = until resumed)
  profile <name>    open Routes on a saved profile (switching needs Use there)
  status            print the connection state
  quit              disconnect and close unbraid
  --background      start without a window (for starting at login); with --connect, connect too
  --version"""

/**
 * The running app's socket in the user's runtime folder: one instance per user (it alone drives the engine), and the
 * way later starts, the launcher's actions and the command line reach it. A line in, a line out.
 */
private object Instance {
    private val path get() = File(Paths.runtime, "app.sock").toPath()

    /** [line]'s answer from the running app, or null when none runs. */
    fun send(line: String): String? = runCatching {
        SocketChannel.open(StandardProtocolFamily.UNIX).use { ch ->
            ch.connect(UnixDomainSocketAddress.of(path))
            ch.write(ByteBuffer.wrap("$line\n".toByteArray()))
            ch.shutdownOutput()
            Channels.newInputStream(ch).bufferedReader().readText().trim()
        }
    }.getOrNull()

    /** Serves later starts; false if another instance already does. */
    fun serve(handle: (String) -> String): Boolean {
        if (send("ping") != null) return false
        java.nio.file.Files.deleteIfExists(path) // left by one that was killed
        val server = ServerSocketChannel.open(StandardProtocolFamily.UNIX).bind(UnixDomainSocketAddress.of(path))
        thread(isDaemon = true, name = "instance") {
            while (true) runCatching {
                server.accept().use { ch ->
                    val line = Channels.newInputStream(ch).bufferedReader().readLine().orEmpty()
                    ch.write(ByteBuffer.wrap((runCatching { handle(line) }.getOrElse { "error" } + "\n").toByteArray()))
                }
            }
        }
        return true
    }
}

/** What later starts and the tray ask the window for. */
private val wanted = MutableStateFlow<String?>(null)
private val shown = MutableStateFlow(false)

fun main(args: Array<String>) {
    val a = args.toList()
    if ("--help" in a || "-h" in a) { println(USAGE); return }
    if ("--version" in a) { println("$APP ${BuildConfig.VERSION_NAME}"); return }
    val command = a.filterNot { it.startsWith("--") }.joinToString(" ").ifEmpty { if ("--background" in a) "" else "show" }
    val known = command.substringBefore(' ') in setOf("", "show", "connect", "disconnect", "pause", "profile", "status", "quit", "ping")
    if (!known) { System.err.println(USAGE); exitProcess(2) }
    // Another instance runs: it does what was asked.
    Instance.send(command.ifEmpty { "ping" })?.let { answer -> if (answer.isNotEmpty() && answer != "ok") println(answer); return }
    if (command.substringBefore(' ') in setOf("disconnect", "pause", "quit", "status")) { println(if (command == "status") "off" else "$APP isn't running"); return }

    Unbraid.init()
    Onboarding.init()
    if (!Instance.serve(::handle)) return // lost a race with another start
    // The engine's worker and statistics end with the app; the tunnels end with it too, as with the Android app.
    Runtime.getRuntime().addShutdownHook(Thread { UnbraidVpn.quit() })
    // Shown unless started for the background; a connect that can't happen yet (setup unfinished) shows it too.
    if ("--background" !in a && command != "connect") shown.value = true
    if ("--connect" in a || command == "connect") handle("connect")
    window()
}

/** One command from a later start, the launcher or the command line. */
private fun handle(line: String): String {
    val (cmd, arg) = line.trim().split(' ', limit = 2).let { it[0] to it.getOrNull(1)?.trim().orEmpty() }
    val ready = Onboarding.termsOk && Onboarding.vpnOk && (Unbraid.store.accounts.value.isNotEmpty() || Unbraid.store.setup.value.let { s -> s.routes.any { it.imported } || s.servers.isNotEmpty() || s.home.tailscale })
    return when (cmd) {
        "ping" -> "ok"
        "show", "" -> { shown.value = true; "ok" }
        "connect" -> if (ready) { UnbraidVpn.start(); "ok" } else { shown.value = true; "Finish setting up $APP in its window first." }
        "disconnect" -> { UnbraidVpn.stop(); "ok" }
        "pause" -> { UnbraidVpn.pause(arg.toIntOrNull()?.coerceIn(0, 60) ?: 15); "ok" }
        "profile" -> { wanted.value = "profile:$arg"; shown.value = true; "ok" }
        "status" -> UnbraidVpn.state.value.let { v -> v.phase.name.lowercase() + (UnbraidVpn.summary.value.takeIf { it.isNotEmpty() }?.let { " · $it" } ?: "") + (v.error?.let { "\n$it" } ?: "") }
        "quit" -> { thread { UnbraidVpn.quit(); exitProcess(0) }; "ok" }
        else -> "unknown command"
    }
}

private fun window() = application {
    val ui = remember { Ui() }
    // Out here, around the window, there is no lifecycle (only windows have one): plain collection.
    val visible by shown.collectAsState()
    val vpn by ui.vpn.collectAsState()
    val summary by UnbraidVpn.summary.collectAsState()
    val quit = { thread { UnbraidVpn.quit(); exitProcess(0) }; Unit }
    // Hidden with nothing running (disconnected from the tray or the command line): nothing left to do.
    var wasOn by remember { mutableStateOf(false) }
    LaunchedEffect(vpn.phase, visible) {
        if (vpn.phase != VpnState.Phase.Off) wasOn = true
        else if (!visible && wasOn) quit()
    }
    val icon = painterResource("unbraid.svg")
    if (isTraySupported) Tray(icon, tooltip = listOf(APP, summary).filter { it.isNotEmpty() }.joinToString(" · "), onAction = { shown.value = true }) {
        Item("Open $APP", onClick = { shown.value = true })
        if (vpn.phase == VpnState.Phase.Off) Item("Connect", onClick = { handle("connect") })
        else {
            if (vpn.phase == VpnState.Phase.On) Item("Pause 15 minutes", onClick = { ui.pause(15) })
            if (vpn.phase == VpnState.Phase.Paused) Item("Resume", onClick = { ui.connect() })
            Item("Disconnect", onClick = { ui.disconnect() })
        }
        Separator()
        Item("Quit", onClick = quit)
    }
    val state = rememberWindowState(size = DpSize(440.dp, 860.dp))
    // A hidden window leaves the composition: in the background only the connection and the tray keep running.
    if (visible) Window(
        // Closing the window keeps a connection running, as leaving the Android app keeps its VPN: the tray, the launcher or
        // `unbraid` brings it back. With nothing running, closing quits.
        onCloseRequest = { if (UnbraidVpn.state.value.phase == VpnState.Phase.Off) quit() else shown.value = false },
        state = state, title = APP, icon = icon,
        onPreviewKeyEvent = { e -> e.key == Key.Escape && e.type == KeyEventType.KeyDown && run { back.value?.invoke(); back.value != null } },
    ) {
        // Android's onResume: the installed apps can change while unbraid is in the background.
        DisposableEffect(Unit) {
            Desktop.window = window; window.minimumSize = java.awt.Dimension(360, 560); window.toFront()
            ui.refreshApps(); Stats.maintain()
            onDispose { Desktop.window = null }
        }
        App(ui)
    }
}

/** What Escape does: Android's back, for the screen on top. */
private val back = MutableStateFlow<(() -> Unit)?>(null)

/** The screens, as MainActivity composes them on Android. */
@Composable
internal fun App(ui: Ui) = UnbraidTheme {
    var sheet by rememberSaveable { mutableStateOf<String?>(null) }
    var connectAfter by rememberSaveable { mutableStateOf(false) }
    /** Connect. Until the VPN disclosure is accepted it comes first. */
    fun connect() { if (!Onboarding.vpnOk) { connectAfter = true; sheet = "vpn" } else ui.connect() }

    // Wide windows keep the phone's column, centred.
    Box(Modifier.fillMaxSize().background(Ink.ground), contentAlignment = Alignment.TopCenter) {
      Box(Modifier.widthIn(max = 640.dp).fillMaxHeight()) {
        if (!Onboarding.termsOk) {
            // A new install gets the whole welcome; someone updating from before the terms only the terms.
            val fresh = remember { !ui.signedIn.value && !ui.disclosed.value }
            Welcome(fresh) { Onboarding.acceptTerms(fresh) }
        } else {
            val signedIn by ui.signedIn.collectAsStateWithLifecycle()
            var tab by rememberSaveable { mutableStateOf(Tab.Routes) }
            // Picker target: null = closed, "" = new route, otherwise a route id. Prefixed "app:" = new route for that app.
            var picker by rememberSaveable { mutableStateOf<String?>(null) }
            var adding by rememberSaveable { mutableStateOf(false) }
            val disclosed by ui.disclosed.collectAsStateWithLifecycle()
            val routesWanted by ui.routesWanted.collectAsStateWithLifecycle()
            val asked by wanted.collectAsStateWithLifecycle()
            LaunchedEffect(routesWanted) {
                if (!routesWanted) return@LaunchedEffect
                ui.routesWanted.value = false
                picker = null; adding = false; tab = Tab.Routes
            }
            // A profile asked for from the command line opens Routes on it: it switches only on Use, as Android's shortcuts.
            LaunchedEffect(asked) {
                val name = asked?.removePrefix("profile:")?.takeIf { asked?.startsWith("profile:") == true } ?: return@LaunchedEffect
                wanted.value = null
                if (ui.setup.value.profiles.any { it.name == name }) { ui.view(name); ui.routesWanted.value = true }
            }

            // The tour: a stop index, -1 = off. A new install gets it once it is set up; Settings replays it.
            var tour by rememberSaveable { mutableStateOf(-1) }
            LaunchedEffect(signedIn) { if (signedIn && Onboarding.tourPending && tour < 0) tour = 0 }
            LaunchedEffect(tour) {
                if (tour < 0) return@LaunchedEffect
                picker = null; adding = false
                TourStop.entries[tour].tab.let { if (it == Tab.Settings && tab != Tab.Settings) settingsHub(); tab = it }
            }
            val endTour = { tour = -1; Onboarding.tourSeen(); tab = Tab.Routes }

            // The screen shown; the picker's carries its route, so a closing picker keeps its identity while it leaves.
            val screenNow = when {
                !signedIn -> "signin"
                adding -> "add"
                picker != null -> "picker:$picker"
                else -> tab.name
            }
            // Seekable, so a back gesture can drive the real transition (the picker shrinking back into its route).
            val screens = remember { SeekableTransitionState(screenNow) }
            LaunchedEffect(screenNow) { screens.animateTo(screenNow) }
            val scope = rememberCoroutineScope()
            val motion = MaterialTheme.motionScheme
            PredictiveBackHandler(adding || picker != null) { events ->
                try {
                    events.collect { screens.seekTo(it.progress, targetState = tab.name) }
                    if (adding) adding = false else picker = null
                } catch (e: CancellationException) {
                    scope.launch { screens.animateTo(screens.currentState) }
                    throw e
                }
            }
            BackHandler(picker == null && !adding && tab != Tab.Routes) { tab = Tab.Routes }
            // Escape closes what Android's back closes; the screens' own handlers (pages, sheets) come first.
            back.value = when { adding -> { { adding = false } }; picker != null -> { { picker = null } }; else -> null }

            Box(Modifier.fillMaxSize()) {
                // While touring the app is looked at, not used: screen readers read the tour's note only.
                Column(Modifier.fillMaxSize().background(Ink.ground).then(if (tour >= 0) Modifier.clearAndSetSemantics {} else Modifier)) {
                    SharedTransitionLayout(Modifier.weight(1f)) {
                        CompositionLocalProvider(LocalShared provides this) {
                            rememberTransition(screens, label = "screen").AnimatedContent(
                                transitionSpec = { fadeIn(motion.fastEffectsSpec()) togetherWith fadeOut(motion.fastEffectsSpec()) },
                            ) { screen ->
                                CompositionLocalProvider(LocalScreen provides this) {
                                    when {
                                        screen == "signin" -> SignInScreen(ui)
                                        screen == "add" -> SignInScreen(ui) { adding = false }
                                        // The route that was clicked grows into its picker (container transform).
                                        screen.startsWith("picker:") -> screen.removePrefix("picker:").let { target ->
                                            Box(Modifier.fillMaxSize().then(sharedRoute(target, RoundedCornerShape(28.dp)))) {
                                                PickerScreen(
                                                    ui, target, close = { picker = null },
                                                    settings = { picker = null; tab = Tab.Settings }, addProvider = { picker = null; adding = true },
                                                )
                                            }
                                        }
                                        screen == Tab.Routes.name -> RoutesScreen(ui, ::connect) { picker = it }
                                        screen == Tab.Apps.name -> AppsScreen(ui, disclose = { sheet = "apps" }) { picker = it }
                                        screen == Tab.Stats.name -> StatsScreen(ui)
                                        else -> SettingsScreen(ui, addProvider = { adding = true }, tour = { tour = 0 })
                                    }
                                }
                            }
                        }
                    }
                    // A change that applied but couldn't be written, wherever it was made: it would be gone after a restart.
                    val unsaved by Unbraid.store.unsaved.collectAsStateWithLifecycle()
                    if (unsaved) Caption("Some of your changes couldn't be saved and would be lost when $APP restarts. Click to try saving again.",
                        Modifier.fillMaxWidth().tap({ thread { Unbraid.store.saveAgain() } }).padding(horizontal = 24.dp, vertical = 12.dp), color = Ink.bad)
                    if (signedIn && picker == null && !adding) NavBar(tab) { if (it == tab) reselected.tryEmit(it) else tab = it }
                }
                if (tour >= 0) TourOverlay(
                    tour, disclosed, back = { tour-- }, close = endTour,
                    next = { if (tour == TourStop.entries.lastIndex) endTour() else tour++ },
                )
            }
            // Asked before a route change goes over a provider's connection limit, wherever it was made.
            LimitSheet(ui)
            when (sheet) {
                "vpn" -> VpnDisclosure(
                    agree = { Onboarding.acceptVpn(); sheet = null; if (connectAfter) { connectAfter = false; ui.connect() } },
                    dismiss = { sheet = null; connectAfter = false },
                )
                "apps" -> AppsDisclosure(agree = { ui.acceptDisclosure(); sheet = null }, dismiss = { sheet = null })
            }
        }
      }
    }
}
