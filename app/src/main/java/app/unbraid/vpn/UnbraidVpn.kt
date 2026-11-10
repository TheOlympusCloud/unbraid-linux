package app.unbraid.vpn

import app.unbraid.APP
import app.unbraid.Unbraid
import app.unbraid.data.AuthException
import app.unbraid.data.Link
import app.unbraid.data.Providers
import app.unbraid.data.Server
import app.unbraid.data.Setup
import app.unbraid.linux.Apps
import app.unbraid.linux.Log
import app.unbraid.linux.Notify
import app.unbraid.linux.SystemClock
import app.unbraid.stats.SpeedTest
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.FlowPreview
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.debounce
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.sync.withPermit

data class TsNode(val name: String, val ip: String, val online: Boolean, val id: String = "")

/** What the UI shows. Lives in-process; the service is the only writer. */
data class VpnState(
    val phase: Phase = Phase.Off,
    val since: Long = 0,
    val servers: Map<String, Server> = emptyMap(),
    val error: String? = null,
    val tsLoginUrl: String? = null,
    val tsState: String? = null,
    /** The DNS suffix the tailnet reports (usable form); whether apps may use it is [app.unbraid.data.Home.tsSuffixAllowed]. */
    val tsSuffix: String? = null,
    /** Tailnet peers that offer themselves as exit nodes. */
    val tsExitNodes: List<TsNode> = emptyList(),
    /** While paused: when the connection comes back (epoch ms), 0 = only when resumed by hand. */
    val pausedUntil: Long = 0,
    /** While paused: when the pause began (epoch ms), for the countdown ring. */
    val pausedAt: Long = 0,
    /** While paused: it may resume somewhat after [pausedUntil]. Always false on Linux, where the timer is exact. */
    val pausedAbout: Boolean = false,
    /** Android's "Block connections without VPN"; Linux has none, so apps simply go out directly while paused. */
    val lockdown: Boolean = false,
    /** Android's "Always-on VPN"; on Linux the app starts at login instead ([app.unbraid.linux.Autostart]). */
    val alwaysOn: Boolean = false,
    /** Providers whose routes have no tunnel right now: provider id → whether it refused the account (the user must sign in again). */
    val stuck: Map<String, Boolean> = emptyMap(),
    /** Routes whose tunnel keeps dropping ([app.unbraid.vpn.Health.dropping]). */
    val dropping: Set<String> = emptySet(),
    /** Counts engine starts, each of which restarts every tunnel: what was observed of an earlier one no longer holds. */
    val engine: Int = 0,
    /** [Setup.hashCode] of the setup the engine runs in full (no route still waiting for a server): a profile switch is done. */
    val applied: Int = 0,
    /** [Setup.hashCode] of the last setup the engine refused (the one before it still runs): a profile switch is undone. */
    val refused: Int = 0,
) {
    enum class Phase { Off, Connecting, On, Paused }
}

/**
 * The connection: Android's VpnService, as one object in the app. Starts, stops and pauses are handled one at a time,
 * in the order asked, and drive the engine ([Engine]); the engine keeps the tunnels while the app's window is closed.
 */
object UnbraidVpn {
    /** Starts, stops and pauses in arrival order, as Android's start commands reach the service. */
    private sealed class Cmd(val ask: Int) {
        class Start(ask: Int, val resumes: Int = 0) : Cmd(ask)
        class Stop(ask: Int) : Cmd(ask)
        class Pause(ask: Int, val minutes: Int) : Cmd(ask)
    }

    val state = MutableStateFlow(VpnState())
    /** Route id → engine tunnel tag of the running setup (speed tests dial through it). */
    @Volatile var tags: Map<String, String> = emptyMap()
    /** Tunnel tag → the DNS server that tunnel's own lookups use (health checks look their servers up there). */
    @Volatile var tunnelDns: Map<String, String> = emptyMap()
    /** The setup the engine runs (not the one being edited): stats attribute traffic against it. */
    @Volatile var running: Setup? = null
    /** Loopback port and password of the app's own way into each exit ([Compiler.PROBE]); see [Probe]. */
    @Volatile var probe: Pair<Int, String>? = null
    /** The computer's own network is metered; Linux doesn't say so to the app, so a combined speed test never asks first. */
    @Volatile var metered = false
    /** Servers ("provider|ip") that failed the last health check: the next connect, even a manual one, avoids them. */
    @Volatile var failing: Set<String> = emptySet()
    /**
     * Android keeps the engine's domain table (fake IP → domain) in a cache file and deletes it after every
     * connection, since it names every site looked up. On Linux the engine keeps it in memory only ([Linux]): there
     * is nothing to delete, and each engine start is a new table.
     */
    fun forgetLookups() = true
    /** An engine runs a domain table: a reload that doesn't restart it keeps its fake-IP block ([fakeBlock]). */
    private var tableOpen = false
    /** The fake-IP block of the open or last table; the store only carries it across process restarts. */
    private var lastBlock: Int? = null
    private fun openTable(open: Boolean) = synchronized(this) { tableOpen = open }
    /** Pauses in this process; a timed resume for an older one, or after a disconnect, does nothing. */
    @Volatile private var pauses = 0
    private const val TAG = "Unbraid"

    /** Connects, or resumes a pause. */
    fun start() = ask(true) { send(Cmd.Start(it)) }
    fun stop() = ask(false) { send(Cmd.Stop(it)) }
    /** Drops the tunnel for [minutes] (0 = until resumed); a start while paused resumes. */
    fun pause(minutes: Int) = ask(false) { send(Cmd.Pause(it, minutes)) }

    /** The newest start, stop or pause the service hasn't handled yet; see [vpnOn]. */
    val asked = MutableStateFlow<Ask?>(null)
    private val asks = java.util.concurrent.atomic.AtomicInteger()
    private fun ask(on: Boolean, send: (Int) -> Unit) {
        val a = Ask(asks.incrementAndGet(), on)
        asked.value = a
        try { send(a.n) } catch (e: RuntimeException) { asked.compareAndSet(a, null); throw e }
    }
    /** The service handled request [n] (or turned it away), and with it every earlier one. */
    private fun handled(n: Int) = n.takeIf { it != 0 }?.let { asked.update { a -> a?.takeIf { it.n > n } } }

    private val bg = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /**
     * Counts engine starts in this process, across service instances: each restarts every tunnel, so health checks
     * and exit checks about an earlier one no longer hold ([VpnState.engine]).
     */
    @Volatile private var starts = 0

    /** Serializes connect, reload, pause and teardown, across service instances too (an old one may still be stopping). */
    private val lock = Mutex()

    /** Runs [f] only while the VPN is off with no command waiting, holding the lifecycle lock so none can start meanwhile. */
    suspend fun <T> whileStopped(f: () -> T): T? = lock.withLock {
        if (state.value.phase == VpnState.Phase.Off && waiting.get() == 0) f() else null
    }

    /** Logs this device out of its tailnet, which needs the engine running. False if it isn't, or the control server didn't confirm. */
    suspend fun tailscaleLogout(): Boolean {
        if (state.value.phase != VpnState.Phase.On) return false
        val call = bg.async { runCatching { Engine.tailscaleLogout(Compiler.TS_TAG) }.isSuccess }
        return withTimeoutOrNull(8_000) { call.await() } == true
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val inbox = kotlinx.coroutines.channels.Channel<Cmd>(kotlinx.coroutines.channels.Channel.UNLIMITED)
    /** Commands not yet started (they wait for [lock]); see [whileStopped]. */
    private val waiting = java.util.concurrent.atomic.AtomicInteger()
    private val store get() = Unbraid.store
    private val net = NetMonitor()
    private var watch: Job? = null
    private var ts: Job? = null
    private var resume: Job? = null
    private var engineWatch: Job? = null
    /** The engine reports its service running; kept by [watchEngine]. */
    @Volatile private var engineUp = false
    /** This process, as the engine sees it ([Linux]): its own connections leave directly, as Android leaves the app out. */
    private val self: String? = ProcessHandle.current().info().command().orElse(null)
    /** What the tray and the command line show of the running connection. */
    val summary = MutableStateFlow("")

    init {
        scope.launch {
            for (cmd in inbox) {
                lock.withLock { waiting.decrementAndGet(); handle(cmd) }
                handled(cmd.ask)
            }
        }
    }

    private fun send(cmd: Cmd) { waiting.incrementAndGet(); inbox.trySend(cmd) }

    /** One command, in arrival order; caller holds [lock]. */
    private fun handle(cmd: Cmd) {
        when (cmd) {
            is Cmd.Stop -> teardown(null)
            // Nothing to pause (a stale tray menu): nothing to do.
            is Cmd.Pause -> if (state.value.phase != VpnState.Phase.Off) pauseNow(cmd.minutes)
            is Cmd.Start -> {
                // A timed resume only ends its own pause.
                if (cmd.resumes != 0 && (cmd.resumes != pauses || state.value.phase != VpnState.Phase.Paused)) return
                connect()
            }
        }
    }

    /** Counts installs and stops: a reload's provider answers apply only if none happened since it asked ([reload]). */
    private var generation = 0

    /** Setup and config the engine is running right now. */
    private var applied: Setup? = null
    private var appliedAccounts: Map<String, String> = emptyMap()
    /** A setup + accounts pair the engine refused: not retried until either changes, so a sign-out is never skipped. */
    private var rejected: Pair<Setup, Map<String, String>>? = null
    /** True between stopping the old engine and the new one running: only then is there something to restore. */
    private var restarting = false
    private var lastGood: String? = null
    /** What [lastGood] was compiled from, so a failed reload can bring exactly that back with a new probe pair. */
    @Volatile private var lastInput: Compiler.Input? = null

    @OptIn(FlowPreview::class)
    private fun connect() {
        if (state.value.phase == VpnState.Phase.On) { notify(store.setup.value); return } // a repeated start (tray, command line)
        cancelResume()
        state.value = VpnState(VpnState.Phase.Connecting)
        try {
            net.start()
            val setup = store.setup.value
            val accounts = store.accounts.value
            // The app's own tests get a fresh way in with each engine start (see apply); none until it runs.
            probe = null
            val picked = pickLinks(setup, emptyMap(), accounts)
            apply(setup, picked, accounts)
            state.value = VpnState(VpnState.Phase.On, System.currentTimeMillis(), picked.links.mapValues { it.value.server }, blockedText(setup, picked.blocked), stuck = stuck(setup, picked.blocked), engine = starts,
                applied = if (picked.blocked.values.none { it is LinkPicker.Waiting }) setup.hashCode() else 0)
            notify(setup)
            watchEngine()
            if (setup.tailscale) watchTailscale()
            // Anything edited while connecting is picked up here: only the applied setup is skipped.
            // Setup edits and sign-ins/outs both change what the engine must run.
            health = scope.launch { watchHealth() }
            watch = combine(store.setup, store.accounts) { s, a -> s to a }.debounce(400).onEach { (s, a) ->
                // Not awaited: a slow provider must never hold up the next edit (which may have to block an app at once).
                if (lock.withLock {
                    // Moved on from a refused setup (a switch put back): trying that one again later is a fresh attempt.
                    if (rejected != null && rejected?.first != s) { rejected = null; state.update { it.copy(refused = 0) } }
                    (s != applied || a != appliedAccounts) && (s to a) != rejected
                }) scope.launch { reload() }
            }.launchIn(scope)
        } catch (e: Exception) {
            Log.e(TAG, "connect: ${Redact.log(e)}")
            teardown(Redact.message(e, "Could not connect"))
        }
    }

    /** Validates first, so a bad config never replaces a working engine. */
    /** [accounts] is the snapshot [links] were picked with: a sign-out after it differs, so the watcher reloads again. */
    private fun apply(setup: Setup, picked: LinkPicker.Result, accounts: Map<String, String>) {
        generation++
        val links = picked.links
        val blocked = picked.blocked.keys
        var input = input(setup, links, blocked)
        var json = compile(input)
        // A favourite, a rename or a second sign-in changes the setup but not what the engine runs: keep every tunnel up.
        val fresh = json != lastGood
        if (fresh) {
            // Every engine start gets a new loopback port and password: while an old engine lets go of its port, a local
            // app could take it over and see that engine's password, which no later engine accepts. The app's own tests
            // get the new pair only once the new engine runs.
            val next = newProbe()
            // The engine keeps its domain table in memory: a restart is a new table, in the next block ([fakeBlock]).
            input = input(setup, links, blocked, next, newTable = true)
            json = compile(input)
            engine("The connection engine rejected this setup.") { Engine.check(json) }
            // The block is spent before the engine can hand out any of it, also if the start fails or the app dies now:
            // a new table that couldn't be noted down doesn't start, or the next process would hand it out again.
            if (input.fakeBlock != lastBlock) engine("$APP couldn't save its state. Try again.") { store.fakeBlock = input.fakeBlock }
            lastBlock = input.fakeBlock
            restarting = true
            openTable(true)
            // A node is kept in the engine from now on: Settings offers to sign it out even once Tailscale is off.
            if (setup.tailscale && !store.tsStored) store.tsStored = true
            engine("The connection engine couldn't start.") { Engine.start(json) }
            restarting = false
            starts++
            probe = next
            lastInput = input
        }
        lastGood = json
        tunnelDns = runCatching { Compiler.probeDns(json) }.getOrDefault(emptyMap())
        tags = Compiler.shared(setup, LinkPicker.ported(setup, links, portStep), blocked) + setup.activeRoutes.filter { it.tsExit != null }.associate { it.id to Compiler.TS_TAG }
        val was = running
        running = setup
        // Published after tags and running: whoever sees this engine number also sees the tunnels it runs. The new
        // engine numbers its connections afresh; stats read the new servers when they first see them.
        if (fresh) state.update { it.copy(servers = links.mapValues { l -> l.value.server }, engine = starts) }
        // After tags and running, which stats label new connections by; also when only the setup changed (a city that
        // resolves to the same server is still another place in the history).
        if (fresh || was != setup) app.unbraid.stats.Stats.post { app.unbraid.stats.Collector.retimeNow() }
        applied = setup
        appliedAccounts = accounts
        // A refusal is over once a setup runs again: a retry of the same one is judged afresh.
        state.update { it.copy(applied = if (picked.blocked.values.none { it is LinkPicker.Waiting }) setup.hashCode() else it.applied, refused = 0) }
        rejected = null
        this.links = links
        retryBlocked(picked.blocked)
    }

    private var retry: Job? = null
    private var retries = 0
    /** The running setup's blocked routes, which [retry] tries again. */
    private var retrying: Map<String, Exception> = emptyMap()

    /**
     * Routes blocked for a passing reason (no network, provider unreachable) try again after 5 s, 15 s, 30 s, 1 min,
     * then every 5 min; signed-out or refused ones wait for a sign-in, which reloads by itself.
     */
    private fun retryBlocked(blocked: Map<String, Exception>) {
        retry?.cancel(); retry = null
        retrying = blocked
        if (blocked.values.all { it is AuthException }) { retries = 0; net.onChange = null; return }
        val wait = listOf(5, 15, 30, 60, 300)[minOf(retries++, 4)] * 1000L
        retry = scope.launch {
            kotlinx.coroutines.delay(wait)
            reload()
        }
        // A new network is the likeliest fix: try at once, with the backoff kept for what follows.
        net.onChange = { scope.launch { lock.withLock { retry?.cancel(); retry = null }; reload() } }
    }

    /** Providers of [blocked] routes, and whether one refused its account. */
    private fun stuck(setup: Setup, blocked: Map<String, Exception>) = blocked.entries.mapNotNull { (id, e) -> setup.route(id)?.takeIf { !it.imported }?.let { it.loc.provider to (e is AuthException) } }
        .groupBy({ it.first }, { it.second }).mapValues { (_, v) -> v.any { it } }

    /** One line for Routes: which routes' apps are blocked and why. */
    private fun blockedText(setup: Setup, blocked: Map<String, Exception>): String? = blocked.entries.firstOrNull()?.let { (_, e) ->
        "Apps on ${blocked.keys.joinToString { setup.route(it)?.name ?: it }} are blocked: ${Redact.message(e, "no connection")}"
    }

    /**
     * What ran before a failed reload, back on the engine exactly as it was compiled, with a fresh probe pair; false if it
     * won't start. Until then the app's own tests have no way in.
     */
    private fun restoreLastGood(): Boolean = runCatching {
        probe = null
        val last = lastInput ?: return false
        val next = newProbe()
        // What ran, but never with tailnet DNS authority or a sign-in way around the exit that was taken back since.
        val now = store.setup.value.home
        // A restarted engine is a new domain table: the next block after the failed start's (which may have answered
        // lookups before it failed), noted down before the engine can hand any of it out.
        val input = Compiler.Input(last.setup.copy(home = last.setup.home.copy(tsSuffixAllowed = now.tsSuffixAllowed)), last.links, last.selfPackage, last.lockdown,
            last.tsDir, last.cacheFile, store.tsSuffix, next, Compiler.nextBlock(lastBlock ?: last.fakeBlock, false), last.blocked, last.tsLoginPending && tsLoginPending)
        val json = compile(input)
        store.fakeBlock = input.fakeBlock
        Engine.start(json)
        starts++
        state.update { it.copy(engine = starts) }
        lastBlock = input.fakeBlock
        probe = next
        lastGood = json
        lastInput = input
        true
    }.getOrDefault(false)

    /** Engine errors can quote the config, keys included: log them cleaned, show a fixed text, and drop the cause. */
    private inline fun engine(failure: String, f: () -> Unit) {
        try { f() } catch (e: Exception) {
            Log.e(TAG, "engine: ${Redact.log(e)}")
            throw Fail(if (Engine.missing(e)) Engine.MISSING else failure)
        }
    }

    /**
     * Applies the newest setup without dropping the tunnel; routes whose location is unchanged keep their server. Takes
     * [lock] itself and lets go of it while providers are asked for servers, so a newer change (one that must block an
     * app at once) never waits for them; what they answer is applied only if nothing changed meanwhile.
     */
    private suspend fun reload(keep: Map<String, Link>? = null, avoid: Set<String> = emptySet(), keepFrom: Int = generation) {
        class Ask(val setup: Setup, val accounts: Map<String, String>, val ready: LinkPicker.Result, val applied: Setup?,
                  val appliedAccounts: Map<String, String>, val refused: Map<String, Exception>, val last: Map<String, Link>, val generation: Int)
        val ask = lock.withLock {
            if (state.value.phase != VpnState.Phase.On) return
            val setup = store.setup.value
            val accounts = store.accounts.value
            // [keep] was taken without the lock: only valid if nothing was installed since ([keepFrom]).
            val ready = pickLinks(setup, keep?.takeIf { keepFrom == generation } ?: links, accounts, avoid, offline = true)
            if (ready.blocked.values.none { it is LinkPicker.Waiting }) { install(setup, ready, accounts); return }
            // While a provider is asked for a server, apps moving off Direct already leave through their new route, or
            // wait blocked if that is the one still waiting: never on their real address for the time it takes. A tunnel
            // whose account was signed out or refused stops now too, not once the others are found.
            val stopNow = ready.blocked.any { (id, e) -> e is AuthException && id in links }
            if ((stopNow || LinkPicker.leavesDirect(applied, setup, setup.activeRoutes.mapTo(HashSet()) { it.id })) && !install(setup, ready, accounts)) return
            Ask(setup, accounts, ready, applied, appliedAccounts, refusedFor(setup, accounts), store.lastLinks, generation)
        }
        // A route without a tunnel (signed out, refused, unreachable) is blocked; the others keep running. Tunnels come
        // from the offline pass, which already dropped any a changed location or account can't keep.
        val picked = LinkPicker.pick(ask.setup, ask.ready.links, ask.applied, ask.appliedAccounts, ask.accounts, ask.last, avoid + failing, ask.refused, false, Providers::get)
        lock.withLock {
            // Stopped, reloaded or edited during the provider calls: the newer state wins (the watcher reloads an edit).
            if (state.value.phase != VpnState.Phase.On || generation != ask.generation || store.setup.value != ask.setup || store.accounts.value != ask.accounts) return
            noteRefusals(ask.setup, ask.accounts, picked)
            runCatching { store.rememberLinks(picked.remember) }.onFailure { Log.w(TAG, "last servers not saved") }
            install(ask.setup, picked, ask.accounts)
        }
    }

    /** Runs [picked] on the engine and shows it; on failure brings back what ran. False if it didn't apply. Caller holds [lock]. */
    private fun install(setup: Setup, picked: LinkPicker.Result, accounts: Map<String, String>): Boolean = try {
        apply(setup, picked, accounts)
        state.update { it.copy(servers = picked.links.mapValues { l -> l.value.server }, error = blockedText(setup, picked.blocked), stuck = stuck(setup, picked.blocked)) }
        notify(setup)
        if (setup.tailscale && ts == null) watchTailscale()
        true
    } catch (e: Exception) {
        Log.e(TAG, "reload: ${Redact.log(e)}")
        rejected = setup to accounts // don't retry the same broken pair in a loop; [applied] stays what runs
        // The engine stops the old service before starting the new one: only then bring the last good config back. It comes
        // back with a new probe pair too: the old password may have been seen while the old engine's port was free.
        val restarted = restarting
        val restored = !restarted || restoreLastGood()
        restarting = false
        // A retry of the running setup that failed before any engine restart is tried again later; one that restarted
        // every tunnel isn't, so a failing server never takes all apps offline every few minutes (a network change
        // still tries again). A refused edit is never retried this way: it waits for the next edit.
        if (restored && restarted) { retry?.cancel(); retry = null }
        else if (restored && setup == applied && accounts == appliedAccounts) retryBlocked(retrying)
        if (restored) app.unbraid.stats.Stats.post { app.unbraid.stats.Collector.retimeNow() } // a new engine, numbered afresh
        if (restored) state.update { it.copy(error = Redact.message(e, "Change not applied"), refused = setup.hashCode()) } else teardown(Redact.message(e, "Connection lost"))
        false
    }

    private var health: Job? = null

    /**
     * Checks each provider tunnel the app can move ([Health]) about once a minute. One that fails is checked again 10 s
     * and 20 s later, then once more a minute after its first failure: WireGuard and OpenVPN usually come back on their
     * own server within that minute. Still failing, it gets another server of its location. A round where every tunnel
     * fails while the phone's own network does too is most likely that network: no server is blamed, and checks slow
     * down (up to every ~8 min) until one works again. Nothing is judged for a while after a new network, an engine
     * start or a sleep.
     */
    private suspend fun watchHealth() {
        val streaks = HashMap<String, Health.Streak>() // tag → its failed checks; tags that answered have none
        val history = HashMap<String, List<Boolean>>() // tag → its latest regular checks, for routes that keep dropping
        val holds = HashMap<String, Long>() // tag → when a dead tunnel there may be handled again; survives restarts
        var slow = 1
        var grace = SystemClock.elapsedRealtime() + Health.GRACE // no check before this
        var round = SystemClock.elapsedRealtime() + jitter() // the next regular round
        var basis: Pair<Int, String?>? = null // the engine start and network the streaks are about
        fun restart(now: Long) { streaks.clear(); history.clear(); undrop(); failing = emptySet(); grace = now + Health.GRACE; round = grace }
        while (true) {
            val wake = maxOf(grace, streaks.entries.mapNotNull { (t, s) -> Health.due(s, holds[t] ?: 0) }.fold(round, ::minOf))
            val slept = asleep()
            // At least 5 s, then in slices: waits don't count deep sleep, and a sleep, an engine start or a new network
            // ends one early.
            kotlinx.coroutines.delay(5_000)
            while (SystemClock.elapsedRealtime() < wake && asleep() - slept < Health.SLEPT && basis == (starts to net.network))
                kotlinx.coroutines.delay((wake - SystemClock.elapsedRealtime()).coerceIn(1, 15_000))
            var now = SystemClock.elapsedRealtime()
            holds.values.removeIf { it <= now }
            // A sleep in between (Doze, screen off) says nothing about the servers.
            if (asleep() - slept >= Health.SLEPT) { restart(now); continue }
            if (state.value.phase != VpnState.Phase.On || net.network == null || SpeedTest.testing) { if (now >= round) round = now + jitter(); continue }
            val network = net.network
            // Ports Automatic learned on another network don't hold here: back to each provider's first port.
            if (network != portNet) { portNet = network; if (portStep.isNotEmpty()) { portStep = emptyMap(); reload(); continue } }
            var servers = emptyMap<String?, List<String>>() // tag → its servers as checked, before a reload can swap them
            var engine = 0
            val byTag = lock.withLock {
                engine = starts
                val s = running ?: return@withLock emptyMap()
                // Pinned and Dedicated IP routes are checked too (to notice a removed device), but never moved.
                links.keys.filter { id -> s.route(id)?.imported == false }
                    .groupBy { tags[it] }.filterKeys { it != null && it != Compiler.TS_TAG }
                    .also { m -> servers = m.mapValues { (_, ids) -> ids.mapNotNull { id -> s.route(id)?.let { r -> links[id]?.let { LinkPicker.serverKey(r, it) } } } } }
            }
            // Restarted tunnels or another network: earlier checks don't carry over, and the new ones get time to settle.
            if (basis != (engine to network)) { val first = basis == null; basis = engine to network; if (!first) { slow = 1; restart(now); continue } }
            if (now < grace) continue
            val regular = now >= round
            // A provider whose new key is still reaching its servers isn't judged yet.
            val settingUp = Providers.settingUp()
            val eligible = byTag.filter { (_, ids) -> ids.none { running?.route(it)?.loc?.provider in settingUp } }.keys.filterNotNull()
            // A regular round checks every tunnel, a quick one only those due again.
            val checked = if (regular) eligible.toSet() else eligible.filterTo(HashSet()) { t -> streaks[t]?.let { Health.due(it, holds[t] ?: 0) }?.let { it <= now } == true }
            if (checked.isEmpty()) { if (regular) round = now + jitter() * slow; continue }
            val gate = Semaphore(4)
            val answered = coroutineScope { checked.map { t -> async { gate.withPermit { t to Health.reachable(t) } } }.awaitAll() }.toMap()
            val down = Health.blame(checked.filterTo(HashSet()) { answered[it] != true }, checked) { Health.direct(network) }
            now = SystemClock.elapsedRealtime()
            if (asleep() - slept >= Health.SLEPT) { restart(now); continue }
            val move = lock.withLock {
                // Stopped, restarted or moved to another network meanwhile: this round says nothing (the next starts afresh).
                if (state.value.phase != VpnState.Phase.On || starts != engine || net.network != network) return@withLock null
                if (down == null) {
                    // Most likely the phone's own network: no server is blamed for these checks.
                    if (regular) { streaks.clear(); slow = minOf(slow * 2, 8) } else checked.forEach { streaks.remove(it) }
                    failing = streaks.keys.flatMap { servers[it].orEmpty() }.toSet()
                    return@withLock null
                }
                if (regular) slow = 1
                checked.forEach { t ->
                    val s = Health.next(streaks[t] ?: Health.Streak(), t !in down, now)
                    if (s.fails == 0) streaks.remove(t) else { streaks[t] = s; Log.i(TAG, "health: $t failed ${s.fails}x, ${(now - s.since) / 1000} s") }
                    // Quick re-checks don't count here: one outage would look like a tunnel that keeps dropping.
                    if (regular) history[t] = Health.record(history[t].orEmpty(), t !in down)
                }
                // The next connect, even a manual one, avoids them.
                failing = streaks.keys.flatMap { servers[it].orEmpty() }.toSet()
                val dropping = byTag.filterKeys { it != null && Health.dropping(history[it].orEmpty()) }.values.flatten().toSet()
                if (dropping != state.value.dropping) state.update { it.copy(dropping = dropping) }
                val deadTags = checked.filter { t -> streaks[t]?.let { Health.dead(it, now, holds[t] ?: 0) } == true }
                if (deadTags.isEmpty()) return@withLock null
                deadTags.forEach { holds[it] = now + Health.COOLDOWN }
                val dead = byTag.filterKeys { it in deadTags }.values.flatten()
                val s = running ?: return@withLock null
                // A dead tunnel on Automatic also tries its provider's next port: a failed check can't tell a blocked port from a dead server.
                val stepped = dead.mapNotNull { id -> s.route(id)?.loc?.provider?.takeIf { p -> (links[id] as? app.unbraid.data.WgLink)?.ports.orEmpty().size > 1 && s.opt(p, app.unbraid.data.PORT_OPT) == app.unbraid.data.AUTO } }.toSet()
                portStep = portStep + stepped.associateWith { (portStep[it] ?: 0) + 1 }
                val movable = dead.filter { id -> s.route(id)?.loc?.let { it.pinned == null && it.group != app.unbraid.data.Nord.DEDICATED_IP } == true }
                Log.w(TAG, "health: ${dead.size} route(s) stopped answering, ${movable.size} to move to another server")
                Move(links - movable.toSet(), movable.mapNotNull { id -> s.route(id)?.let { r -> links[id]?.let { LinkPicker.serverKey(r, it) } } }.toSet(), generation,
                    dead.mapNotNull { id -> s.route(id)?.loc?.provider }.toSet(), movable.isNotEmpty() || stepped.isNotEmpty())
            }
            if (regular) round = now + jitter() * slow
            if (move == null) continue
            // A dead tunnel can mean the provider dropped this phone (its device removed on the website): then its routes
            // wait blocked for a new sign-in instead of trying server after server.
            val accounts = store.accounts.value
            val dropped = move.providers.filter { p -> accounts[p]?.let { Providers.get(p)?.revoked(it) } == true }
            if (dropped.isNotEmpty()) lock.withLock {
                dropped.forEach { p -> refusals = refusals + (p to (accounts[p] to AuthException("${Providers.get(p)?.name ?: p} no longer has this computer (it was removed from your account). Sign in again"))) }
            }
            // The newest setup, not the running one: a change still waiting to apply must never be undone here.
            if (move.anyMovable || dropped.isNotEmpty()) reload(move.keep, move.avoid, move.generation)
        }
    }

    /** A regular round's wait: about a minute, spread so tunnels of many phones don't line up. */
    private fun jitter() = 48_000L + kotlin.random.Random.nextLong(24_000)

    /** How long the phone has slept since boot: it grows only while it sleeps. */
    private fun asleep() = SystemClock.elapsedRealtime() - SystemClock.uptimeMillis()

    /** Health history starts again: no route is flagged as dropping until new checks say so. */
    private fun undrop() { if (state.value.dropping.isNotEmpty()) state.update { it.copy(dropping = emptySet()) } }

    private class Move(val keep: Map<String, Link>, val avoid: Set<String>, val generation: Int, val providers: Set<String>, val anyMovable: Boolean)

    /** Tunnels the engine runs now, per route id. */
    private var links: Map<String, Link> = emptyMap()

    /** Caller holds [lock]. */
    private fun pickLinks(setup: Setup, keep: Map<String, Link>, accounts: Map<String, String>, avoid: Set<String> = emptySet(), offline: Boolean = false): LinkPicker.Result {
        val r = LinkPicker.pick(setup, keep, applied, appliedAccounts, accounts, store.lastLinks, avoid + failing, refusedFor(setup, accounts), offline, Providers::get)
        noteRefusals(setup, accounts, r)
        // Only a fallback cache: failing to write it never stops a connection.
        if (!offline) runCatching { store.rememberLinks(r.remember) }.onFailure { Log.w(TAG, "last servers not saved") }
        return r
    }

    /**
     * Routes whose provider refused the account it still has, or whose pinned server it no longer offers. A refusal
     * holds until that account changes (a sign-out or a new sign-in), a server's removal while connected: a later
     * request that fails never brings the saved server back.
     */
    private fun refusedFor(setup: Setup, accounts: Map<String, String>): Map<String, Exception> {
        refusals = refusals.filter { (p, v) -> v.first == accounts[p] }
        return setup.activeRoutes.filter { !it.imported }.mapNotNull { r ->
            (refusals[r.loc.provider]?.second ?: r.loc.pinned?.let { gone["${r.loc.provider}|${it.host}"] })?.let { r.id to it }
        }.toMap()
    }

    private fun noteRefusals(setup: Setup, accounts: Map<String, String>, r: LinkPicker.Result) = r.blocked.forEach { (id, e) ->
        setup.route(id)?.takeIf { !it.imported }?.let {
            if (e is AuthException) refusals = refusals + (it.loc.provider to (accounts[it.loc.provider] to e))
            if (e is app.unbraid.data.NoLongerOffered) it.loc.pinned?.let { p -> gone = gone + ("${it.loc.provider}|${p.host}" to e) }
        }
    }

    /** Pinned servers ("provider|host") their provider's list no longer has, while connected. */
    private var gone: Map<String, Exception> = emptyMap()

    /** Tailscale gave a sign-in link and waits for the user ([Compiler.Input.tsLoginPending]). */
    @Volatile private var tsLoginPending = false

    /** Providers that refused an account, with that account and why: their routes stay blocked until it changes. */
    private var refusals: Map<String, Pair<String?, Exception>> = emptyMap()

    /** Provider id → how many of its ports Automatic has moved past on this network ([LinkPicker.ported]). */
    @Volatile private var portStep: Map<String, Int> = emptyMap()
    /** The network [portStep] was learned on. */
    private var portNet: String? = null

    /**
     * Compiled as on Android under lockdown, where the system leaves no app out (Linux can't), then made a Linux config.
     * The paths are the engine's own: it keeps them in its root-only folder for this user.
     */
    private fun input(setup: Setup, links: Map<String, Link>, blocked: Set<String>, p: Pair<Int, String>? = probe, newTable: Boolean = false) =
        Compiler.Input(setup, LinkPicker.ported(setup, links, portStep), "app.unbraid", true, "tailscale", "cache.db", store.tsSuffix, p, fakeBlock(newTable), blocked, tsLoginPending)

    private fun compile(i: Compiler.Input) = Linux.config(Compiler.compile(i), Apps::matchers, self)

    /** The running table's fake-IP block, to compare a reload with what runs; a new table (an engine start) takes the next one. */
    private fun fakeBlock(newTable: Boolean = false) = Compiler.nextBlock(lastBlock ?: store.fakeBlock, synchronized(this) { tableOpen } && !newTable)


    /** The app's own way into each exit ([Compiler.PROBE]): a free loopback port and a 24-byte random password. */
    private fun newProbe(): Pair<Int, String> =
        java.net.ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress()).use { it.localPort } to
            java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(24).also { java.security.SecureRandom().nextBytes(it) })

    private fun watchTailscale() {
        ts = scope.launch {
            // The subscription outlives engine reloads; one the engine drops (it restarted) comes back.
            while (isActive) {
                try {
                    Engine.tailscaleStatus().collect { u -> u.endpointsList.firstOrNull()?.let(::tailscale) }
                } catch (e: kotlinx.coroutines.CancellationException) { throw e
                } catch (e: Exception) { Log.w(TAG, "tailscale status: ${Redact.log(e)}") }
                delay(2_000)
            }
        }
    }

    private fun tailscale(ep: app.unbraid.engine.daemon.TailscaleEndpointStatus) {
        val nodes = ep.userGroupsList.flatMap { it.peersList }.filter { it.exitNodeOption && it.tailscaleIPsCount > 0 }
            .map { p -> TsNode(p.hostName.ifEmpty { p.dnsName.substringBefore('.') }, p.getTailscaleIPs(0), p.online, p.stableID) }
            .sortedBy { it.name.lowercase() }
        val suffix = Compiler.tsSuffix(ep.magicDNSSuffix)
        val reported = if (ep.backendState == "Running") suffix else store.tsSuffix
        state.update { s -> s.copy(tsLoginUrl = ep.authURL.ifEmpty { null }, tsState = ep.backendState, tsExitNodes = nodes, tsSuffix = reported) }
        // The sign-in pages' way around the exit opens with a sign-in link and closes only once signed in: a
        // restarted engine reports no link at first, which must not close it (each reload restarts Tailscale).
        // Compared with what the engine runs, so a reload that failed is tried again on the next status.
        tsLoginPending = TsLogin.pending(ep.authURL, ep.backendState, tsLoginPending)
        if (lastInput?.let { it.tsLoginPending != tsLoginPending } == true) scope.launch { reload() }
        // A speed test that was cut off left Tailscale on its test node: put the configured one back.
        if (ep.backendState == "Running" && store.tsTestFrom != null && !SpeedTest.testing) SpeedTest.restoreNode()
        // The tailnet's own domain is only known once signed in: reload once so DNS routes it to Tailscale.
        if (ep.backendState == "Running" && suffix != store.tsSuffix) {
            store.tsSuffix = suffix
            scope.launch { reload() }
        }
    }

    /**
     * The engine's service, as Android's revoke tells the VPN it was ended: one that stops or fails while it runs ours
     * (the system service restarted, a crash) is said, once it stays stopped, since every reload stops and starts it too.
     */
    private fun watchEngine() {
        engineWatch?.cancel()
        val mine = session
        engineUp = true
        engineWatch = scope.launch {
            while (isActive) {
                try {
                    Engine.serviceStatus().collect { s -> engineUp = Engine.running(s); if (!engineUp) launch { lost(mine, s.errorMessage) } }
                } catch (e: kotlinx.coroutines.CancellationException) { throw e
                } catch (e: Exception) { engineUp = false; launch { lost(mine, null) } }
                delay(2_000)
            }
        }
    }

    private suspend fun lost(mine: Int, error: String?) {
        delay(3_000)
        if (engineUp || restarting || session != mine || state.value.phase != VpnState.Phase.On) return
        stoppedOutside(error?.takeIf { it.isNotBlank() }?.let { "The unbraid engine stopped: ${Redact.clean(it)}" } ?: "The unbraid engine stopped, so $APP's connection ended.")
    }

    /** Counts connections ended ([stopEngine]): a stop from outside applies only to the one it was sent for. */
    @Volatile private var session = 0
    /** Android or the engine ended the connection: said, like a failed connect, unless that one had already ended. */
    private fun stoppedOutside(why: String) {
        val mine = session // taken now: a stop and a new connect may be handled before this gets the lock
        scope.launch { lock.withLock { if (session == mine && state.value.phase != VpnState.Phase.Off) teardown(why) } }
    }

    /** Stops the engine and the tunnel; the service itself stays. Caller holds [lock]. */
    private fun stopEngine() {
        watch?.cancel(); watch = null
        health?.cancel(); health = null
        generation++
        session++
        retry?.cancel(); retry = null; retries = 0; retrying = emptyMap(); net.onChange = null; refusals = emptyMap(); gone = emptyMap(); failing = emptySet()
        ts?.cancel(); ts = null
        engineWatch?.cancel(); engineWatch = null
        tsLoginPending = false
        runCatching { Engine.stop() }
        openTable(false)
        net.stop()
        applied = null; rejected = null; lastGood = null; lastInput = null; probe = null; links = emptyMap(); appliedAccounts = emptyMap()
        running = null; tags = emptyMap(); tunnelDns = emptyMap()
    }

    /** Caller holds [lock]. */
    private fun teardown(error: String?) {
        cancelResume()
        stopEngine()
        state.value = VpnState(error = error)
        summary.value = ""
        // A failure in the background (resume after a pause, a revoked account) must not pass unnoticed.
        if (error != null) alert(error)
    }

    private fun cancelResume() { resume?.cancel(); resume = null }

    /** Traffic leaves without the VPN until resumed, by hand or after [minutes]. Caller holds [lock]. */
    private fun pauseNow(minutes: Int) {
        if (state.value.phase != VpnState.Phase.On) return
        stopEngine()
        val pause = ++pauses
        val until = if (minutes > 0) System.currentTimeMillis() + minutes * 60_000L else 0L
        // Short steps against the clock that counts suspend: a single delay doesn't count while the computer sleeps.
        if (until > 0) {
            val wake = SystemClock.elapsedRealtime() + minutes * 60_000L
            resume = scope.launch {
                while (SystemClock.elapsedRealtime() < wake) delay((wake - SystemClock.elapsedRealtime()).coerceIn(1, 15_000))
                lock.withLock { if (state.value.phase == VpnState.Phase.Paused && pauses == pause) connect() }
            }
        }
        val at = java.text.DateFormat.getTimeInstance(java.text.DateFormat.SHORT).format(java.util.Date(until))
        summary.value = if (until <= 0) "Paused" else "Paused until $at"
        state.value = VpnState(VpnState.Phase.Paused, pausedUntil = until, pausedAt = System.currentTimeMillis())
    }

    /**
     * Deletes the Tailscale node the engine keeps for this user (on Linux its state is the engine's, in its root-only
     * folder), as Android deletes the app's sealed copy; only while stopped ([whileStopped]). An engine that never ran
     * for this user has none to delete.
     */
    fun forgetTailscale(): Boolean {
        val e = runCatching { Engine.forget() }.exceptionOrNull()
        val gone = e == null || (e as? io.grpc.StatusRuntimeException)?.status?.code == io.grpc.Status.Code.UNKNOWN
        if (gone) store.tsStored = false else Log.w(TAG, "tailscale: node not deleted: ${Redact.log(e!!)}")
        return gone
    }

    /** Quitting the app ends its connection, as Android ends the VPN with the app. */
    fun quit() = kotlinx.coroutines.runBlocking { withTimeoutOrNull(10_000) { lock.withLock { if (state.value.phase != VpnState.Phase.Off) teardown(null) } } }

    // ---- what Android shows as notifications ---------------------------------------------------

    private fun alert(text: String) = Notify.send("$APP is off", text)

    private fun notify(setup: Setup) {
        summary.value = setup.activeRoutes.joinToString("  ·  ") { r ->
            if (r.id == setup.defaultRoute) "${r.code} default" else "${r.code} ${setup.apps.count { it.value == r.id }}"
        }.ifEmpty { "Only selected apps" }
    }
}

/** A start ([on]) or a stop or pause, numbered [n] in the order asked. */
class Ask(val n: Int, val on: Boolean)

/**
 * Whether the VPN is on or about to be, for toggles: the newest request the service hasn't handled yet wins over the
 * phase, so a second quick tap undoes the first instead of repeating it, however long the first one takes.
 */
fun vpnOn(phase: VpnState.Phase, ask: Ask?): Boolean = ask?.on ?: (phase == VpnState.Phase.On || phase == VpnState.Phase.Connecting)
