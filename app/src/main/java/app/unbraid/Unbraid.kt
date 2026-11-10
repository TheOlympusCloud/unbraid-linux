package app.unbraid

import app.unbraid.data.Store
import app.unbraid.linux.Paths
import app.unbraid.stats.Stats
import app.unbraid.vpn.Profiles
import app.unbraid.vpn.UnbraidVpn
import app.unbraid.vpn.VpnState.Phase
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.onEach
import java.io.File

/** The app's name, always lowercase: launcher label (unbraid.desktop), tray, notifications, running text. Change them together. */
const val APP = "unbraid"

/** The logo, only inside the app (Settings header, About, sign-in), its slash always in the accent: see [app.unbraid.ui.wordmarked]. */
const val WORDMARK = "un/braid"

/** What Android's Application held for the whole process: the store, and what follows the connection. */
object Unbraid {
    lateinit var store: Store
        private set

    fun init(dir: File = Paths.data) {
        store = Store(dir)
        app.unbraid.data.Catalog.published = store::catalogDate
        app.unbraid.data.Providers.opt = { p, k -> store.setup.value.opt(p, k) }
        app.unbraid.data.Snapshot.dir = dir
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        Profiles.watch(scope)
        // Statistics follow the connection while they're on: sessions from the phase, traffic from the running engine.
        Stats.init(dir)
        combine(UnbraidVpn.state.map { it.phase }, store.setup.map { it.prefs.stats }) { p, on -> p to on }.distinctUntilChanged().onEach { (p, on) ->
            Stats.phase(if (on) p else Phase.Off)
            if (on && p == Phase.On) Stats.start() else Stats.stop()
        }.launchIn(scope)
    }
}
