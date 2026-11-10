package app.unbraid.vpn

import app.unbraid.Unbraid
import app.unbraid.vpn.VpnState.Phase
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach

/** For a profile switch to the setup hashed [h]: true once the engine runs it (or runs nothing), false if it refused it, null meanwhile. */
fun switchDone(v: VpnState, h: Int) = when { v.phase != Phase.On || v.applied == h -> true; v.refused == h -> false; else -> null }

/** Profile switches, from the app, the tray or the command line alike. Linux has no quick-settings tiles or launcher shortcuts. */
object Profiles {
    const val SLOTS = 3
    const val ACTION = "app.unbraid.PROFILE"

    /** A switch to profile [to] the engine refused; [kept] is the profile still in use. */
    class Refused(val to: String, val kept: String?)
    /** The profile being switched to, until the engine runs it. */
    val switching = MutableStateFlow<String?>(null)
    val refused = MutableStateFlow<Refused?>(null)

    /** A switch to [to] was saved: followed while the engine runs. */
    fun started(to: String) {
        refused.value = null
        if (UnbraidVpn.state.value.phase == Phase.On) switching.value = to
    }

    /** Done once the engine runs the saved setup; refused, the setup it still runs comes back into the app. */
    fun watch(scope: CoroutineScope) = combine(UnbraidVpn.state, Unbraid.store.setup, switching) { v, s, to -> Triple(v, s, to) }.onEach { (v, s, to) ->
        to ?: return@onEach
        val done = switchDone(v, s.hashCode()) ?: return@onEach
        switching.value = null
        if (done) return@onEach
        UnbraidVpn.running?.let { ran -> Unbraid.store.update { it.back(ran) } }
        refused.value = Refused(to, Unbraid.store.setup.value.profile)
    }.launchIn(scope)
}
