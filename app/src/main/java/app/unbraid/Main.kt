package app.unbraid

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.SharedTransitionLayout
import androidx.compose.animation.core.SeekableTransitionState
import androidx.compose.animation.core.rememberTransition
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.heightIn
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
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Row
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.draw.clip
import androidx.compose.ui.input.key.KeyEvent
import androidx.compose.ui.input.key.isAltPressed
import androidx.compose.ui.input.key.isCtrlPressed
import androidx.compose.ui.input.key.isShiftPressed
import androidx.compose.ui.platform.LocalWindowInfo
import androidx.compose.ui.unit.isSpecified
import androidx.compose.ui.window.WindowPlacement
import androidx.compose.ui.window.WindowPosition
import app.unbraid.linux.DesktopSettings
import app.unbraid.ui.Desk
import app.unbraid.ui.ShortcutsDialog
import app.unbraid.ui.Sidebar
import app.unbraid.ui.WIDE
import java.awt.GraphicsEnvironment
import java.awt.Rectangle
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.withContext

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
    // The theme before the first frame, so the window doesn't open in the other one.
    systemDark.value = Desktop.systemDark()
    Ink.light = !DesktopSettings.dark(DesktopSettings.theme.value, systemDark.value)
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
    val setup by ui.setup.collectAsState()
    val summary by UnbraidVpn.summary.collectAsState()
    val closeToTray by DesktopSettings.closeToTray.collectAsState()
    val quit = { thread { UnbraidVpn.quit(); exitProcess(0) }; Unit }
    // Closing leaves unbraid in the tray, or running in the background while connected where there's no tray; off, it quits.
    val close = { if (closeToTray && (isTraySupported || UnbraidVpn.state.value.phase != VpnState.Phase.Off)) shown.value = false else quit() }
    // Hidden with nothing running and no tray to come back from (disconnected from the command line): nothing left to do.
    var wasOn by remember { mutableStateOf(false) }
    LaunchedEffect(vpn.phase, visible, closeToTray) {
        if (vpn.phase != VpnState.Phase.Off) wasOn = true
        else if (!visible && wasOn && !(isTraySupported && closeToTray)) quit()
    }
    ReadSystemTheme()
    val icon = painterResource("unbraid.svg")
    if (isTraySupported) Tray(painterResource(if (vpn.phase == VpnState.Phase.On) "unbraid.svg" else "unbraid-off.svg"),
        tooltip = listOf(APP, summary).filter { it.isNotEmpty() }.joinToString(" · "), onAction = { shown.value = true }) {
        Item(when (vpn.phase) {
            VpnState.Phase.On -> "Protected · ${setup.route(setup.defaultRoute)?.name ?: "Direct"}"
            VpnState.Phase.Paused -> summary.ifEmpty { "Paused" }; VpnState.Phase.Connecting -> "Connecting…"; VpnState.Phase.Off -> "Not connected"
        }, enabled = false, onClick = {})
        Separator()
        if (vpn.phase == VpnState.Phase.Off) Item("Connect", onClick = { handle("connect") }) else Item("Disconnect", onClick = { ui.disconnect() })
        if (vpn.phase == VpnState.Phase.On) Item("Pause 15 minutes", onClick = { ui.pause(15) })
        if (vpn.phase == VpnState.Phase.Paused) Item("Resume", onClick = { ui.connect() })
        if (setup.profiles.isNotEmpty()) Menu("Profile") {
            setup.profiles.forEach { p -> RadioButtonItem(p.name, selected = p.name == setup.profile, onClick = { if (p.name != setup.profile) ui.useProfile(p.name) }) }
        }
        Separator()
        Item("Open $APP", onClick = { shown.value = true })
        Item("Quit", onClick = quit)
    }
    val placement = remember { DesktopSettings.placement()?.takeIf(::onScreen) }
    val state = rememberWindowState(
        placement = if (placement?.maximized == true) WindowPlacement.Maximized else WindowPlacement.Floating,
        position = placement?.let { WindowPosition(it.x.dp, it.y.dp) } ?: WindowPosition.PlatformDefault,
        size = placement?.let { DpSize(it.width.dp, it.height.dp) } ?: DpSize(1280.dp, 800.dp),
    )
    // Noted as it changes, so a logout or a crash keeps it too; maximized keeps the size to come back to.
    LaunchedEffect(state) {
        snapshotFlow { Triple(state.position, state.size, state.placement) }.collectLatest { (pos, size, how) ->
            delay(800)
            if (!DesktopSettings.rememberWindow.value) return@collectLatest
            val was = DesktopSettings.placement()
            if (how == WindowPlacement.Maximized) DesktopSettings.save((was ?: DesktopSettings.Placement(0, 0, 1280, 800, false)).copy(maximized = true))
            else if (pos.isSpecified && how == WindowPlacement.Floating)
                DesktopSettings.save(DesktopSettings.Placement(pos.x.value.toInt(), pos.y.value.toInt(), size.width.value.toInt(), size.height.value.toInt(), false))
        }
    }
    // A hidden window leaves the composition: in the background only the connection and the tray keep running.
    if (visible) Window(
        onCloseRequest = close, state = state, title = APP, icon = icon,
        onPreviewKeyEvent = { e -> e.type == KeyEventType.KeyDown && keys(e.key, e.isCtrlPressed, e.isShiftPressed, e.isAltPressed, ui, close, quit) },
    ) {
        // Android's onResume: the installed apps can change while unbraid is in the background.
        DisposableEffect(Unit) {
            Desktop.window = window; window.minimumSize = java.awt.Dimension(880, 600); window.toFront()
            ui.refreshApps(); Stats.maintain()
            onDispose { Desktop.window = null }
        }
        // The desktop's light or dark again whenever the window comes to the front: it may have changed meanwhile.
        val focused = LocalWindowInfo.current.isWindowFocused
        LaunchedEffect(focused) { if (focused) systemDark.value = withContext(Dispatchers.IO) { Desktop.systemDark() } }
        App(ui)
    }
}

/** A remembered place still on one of the screens (one may have gone since). */
private fun onScreen(p: DesktopSettings.Placement) = runCatching {
    GraphicsEnvironment.getLocalGraphicsEnvironment().screenDevices.any { it.defaultConfiguration.bounds.intersects(Rectangle(p.x, p.y, p.width, p.height)) }
}.getOrDefault(false)

/** The desktop's own light or dark, while the theme follows it: read at start, every 30 s and when the window comes to the front. */
private val systemDark = MutableStateFlow<Boolean?>(null)

@Composable
private fun ReadSystemTheme() {
    val theme by DesktopSettings.theme.collectAsState()
    LaunchedEffect(theme) { while (theme == DesktopSettings.Theme.System) { systemDark.value = withContext(Dispatchers.IO) { Desktop.systemDark() }; delay(30_000) } }
}

/** The theme in force: Settings › Desktop's choice, or the desktop's own. */
@Composable
private fun FollowTheme() {
    val theme by DesktopSettings.theme.collectAsState()
    val dark by systemDark.collectAsState()
    // Read here, in composition, so a change composes again; the effect only hands it on.
    val light = !DesktopSettings.dark(theme, dark)
    SideEffect { Ink.light = light }
}

/** The window's keyboard shortcuts ([Desk.shortcuts]); true for a key it used. */
internal fun keys(key: Key, ctrl: Boolean, shift: Boolean, alt: Boolean, ui: Ui, close: () -> Unit, quit: () -> Unit): Boolean {
    if (key == Key.Escape) return run { back.value?.invoke(); back.value != null }
    if (key == Key.F1) return Desk.asks.tryEmit(Desk.Ask.Shortcuts)
    if (!ctrl || alt) return false
    if (shift) return when (key) {
        Key.C -> Desk.asks.tryEmit(Desk.Ask.Connect)
        Key.P -> { when (ui.vpn.value.phase) { VpnState.Phase.On -> ui.pause(15); VpnState.Phase.Paused -> ui.connect(); else -> Unit }; true }
        else -> false
    }
    when (key) {
        Key.One -> Desk.tab.value = Tab.Routes
        Key.Two -> Desk.tab.value = Tab.Apps
        Key.Three -> Desk.tab.value = Tab.Stats
        Key.Comma -> Desk.tab.value = Tab.Settings
        Key.F -> { Desk.tab.value = Tab.Apps; Desk.pending.value = Desk.Ask.Search }
        Key.N -> Desk.asks.tryEmit(Desk.Ask.NewRoute)
        Key.W -> close()
        Key.Q -> quit()
        Key.Slash -> Desk.asks.tryEmit(Desk.Ask.Shortcuts)
        else -> return false
    }
    return true
}

/** What Escape does: Android's back, for the screen on top. */
private val back = MutableStateFlow<(() -> Unit)?>(null)

/** The screens, as MainActivity composes them on Android, around the desktop's sidebar ([Sidebar]). */
@Composable
internal fun App(ui: Ui) = UnbraidTheme {
    FollowTheme()
    var sheet by rememberSaveable { mutableStateOf<String?>(null) }
    var connectAfter by rememberSaveable { mutableStateOf(false) }
    var shortcuts by remember { mutableStateOf(false) }
    /** Connect. Until the VPN disclosure is accepted it comes first. */
    fun connect() { if (!Onboarding.vpnOk) { connectAfter = true; sheet = "vpn" } else ui.connect() }

    BoxWithConstraints(Modifier.fillMaxSize().background(Ink.ground)) {
      val wide = maxWidth >= WIDE
        if (!Onboarding.termsOk) {
            // A new install gets the whole welcome; someone updating from before the terms only the terms.
            val fresh = remember { !ui.signedIn.value && !ui.disclosed.value }
            Card { Welcome(fresh) { Onboarding.acceptTerms(fresh) } }
        } else {
            val signedIn by ui.signedIn.collectAsStateWithLifecycle()
            val tab by Desk.tab.collectAsStateWithLifecycle()
            // Picker target: null = closed, "" = new route, otherwise a route id. Prefixed "app:" = new route for that app.
            var picker by rememberSaveable { mutableStateOf<String?>(null) }
            var adding by rememberSaveable { mutableStateOf(false) }
            val disclosed by ui.disclosed.collectAsStateWithLifecycle()
            val routesWanted by ui.routesWanted.collectAsStateWithLifecycle()
            val asked by wanted.collectAsStateWithLifecycle()
            LaunchedEffect(routesWanted) {
                if (!routesWanted) return@LaunchedEffect
                ui.routesWanted.value = false
                picker = null; adding = false; Desk.tab.value = Tab.Routes
            }
            // Another page from the sidebar or the keys closes what was open over the last one.
            LaunchedEffect(tab) { picker = null; adding = false }
            // A profile asked for from the command line opens Routes on it: it switches only on Use, as Android's shortcuts.
            LaunchedEffect(asked) {
                val name = asked?.removePrefix("profile:")?.takeIf { asked?.startsWith("profile:") == true } ?: return@LaunchedEffect
                wanted.value = null
                if (ui.setup.value.profiles.any { it.name == name }) { ui.view(name); ui.routesWanted.value = true }
            }
            // What the keys and the tray ask for that the window itself answers.
            LaunchedEffect(signedIn) {
                Desk.asks.collect { a ->
                    when (a) {
                        Desk.Ask.Shortcuts -> shortcuts = true
                        // A dialog: it opens over whichever page is shown.
                        Desk.Ask.NewRoute -> if (signedIn) picker = ""
                        Desk.Ask.Connect -> if (signedIn) when (ui.vpn.value.phase) { VpnState.Phase.Off, VpnState.Phase.Paused -> connect(); else -> ui.disconnect() }
                        else -> Unit
                    }
                }
            }

            // The tour: a stop index, -1 = off. A new install gets it once it is set up; Settings replays it.
            var tour by rememberSaveable { mutableStateOf(-1) }
            LaunchedEffect(signedIn) { if (signedIn && Onboarding.tourPending && tour < 0) tour = 0 }
            LaunchedEffect(tour) {
                if (tour < 0) return@LaunchedEffect
                picker = null; adding = false
                TourStop.entries[tour].tab.let { if (it == Tab.Settings && tab != Tab.Settings) settingsHub(); Desk.tab.value = it }
            }
            val endTour = { tour = -1; Onboarding.tourSeen(); Desk.tab.value = Tab.Routes }

            // The screen shown; the location picker is a dialog over it.
            val screenNow = when {
                !signedIn -> "signin"
                adding -> "add"
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
            BackHandler(picker == null && !adding && tab != Tab.Routes) { Desk.tab.value = Tab.Routes }
            // Escape closes what Android's back closes; the screens' own handlers (pages, sheets) come first.
            back.value = when { shortcuts -> { { shortcuts = false } }; adding -> { { adding = false } }; picker != null -> { { picker = null } }; else -> null }

            Box(Modifier.fillMaxSize()) {
                // While touring the app is looked at, not used: screen readers read the tour's note only.
                Row(Modifier.fillMaxSize().background(Ink.ground).then(if (tour >= 0) Modifier.clearAndSetSemantics {} else Modifier)) {
                    if (signedIn) Sidebar(ui, tab, wide, onTab = { if (it == tab && picker == null && !adding) reselected.tryEmit(it) else Desk.tab.value = it; picker = null; adding = false }, connect = ::connect)
                    Column(Modifier.weight(1f).fillMaxHeight()) {
                        SharedTransitionLayout(Modifier.weight(1f)) {
                            CompositionLocalProvider(LocalShared provides this) {
                                rememberTransition(screens, label = "screen").AnimatedContent(
                                    transitionSpec = { fadeIn(motion.fastEffectsSpec()) togetherWith fadeOut(motion.fastEffectsSpec()) },
                                ) { screen ->
                                    CompositionLocalProvider(LocalScreen provides this) {
                                        when {
                                            screen == "signin" -> Card { SignInScreen(ui) }
                                            screen == "add" -> Card { SignInScreen(ui) { adding = false } }
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
                    }
                }
                // The location picker: a dialog over the page it came from; a click beside it closes it, as Esc does.
                picker?.let { target ->
                    // Taps, not clicks: a clickable would merge the whole dialog into one node for screen readers.
                    Box(Modifier.fillMaxSize().background(Ink.scrim).pointerInput(Unit) { detectTapGestures { picker = null } }, contentAlignment = Alignment.Center) {
                        Box(
                            Modifier.padding(24.dp).widthIn(max = 1040.dp).heightIn(max = 720.dp).fillMaxSize().clip(RoundedCornerShape(28.dp)).background(Ink.ground)
                                .border(1.dp, Ink.line, RoundedCornerShape(28.dp)).pointerInput(Unit) { detectTapGestures { } },
                        ) {
                            PickerScreen(
                                ui, target, close = { picker = null },
                                settings = { picker = null; Desk.tab.value = Tab.Settings }, addProvider = { picker = null; adding = true },
                            )
                        }
                    }
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
            if (shortcuts) ShortcutsDialog { shortcuts = false }
        }
    }
}

/** A step before the app proper (the welcome, signing in): a card in the middle of the window, as wide as reading wants. */
@Composable
private fun Card(content: @Composable () -> Unit) = Box(Modifier.fillMaxSize().background(Ink.ground).padding(24.dp), contentAlignment = Alignment.Center) {
    Box(Modifier.widthIn(max = 600.dp).fillMaxHeight().clip(RoundedCornerShape(28.dp)).background(Ink.ground).border(1.dp, Ink.surfaceHigh, RoundedCornerShape(28.dp))) { content() }
}
