package app.unbraid.data

import app.unbraid.linux.Keyring
import app.unbraid.linux.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import java.io.File
import java.io.FileOutputStream
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Everything Unbraid persists. Plain JSON files in private storage; secrets AES-GCM sealed with a key from the desktop
 * keyring ([Keyring]). [dir] and [keyOf] can be swapped for tests.
 */
class Store(private val dir: File, private val keyOf: () -> SecretKey = { Keyring.key(dir) }) {
    private val json = NordApi.json

    // Declared before anything that loads sealed files at construction.
    private val key: SecretKey by lazy(keyOf)

    /** Set when a change applied but couldn't be written: it would be gone after a restart, so the UI says so. */
    val unsaved = MutableStateFlow(false)
    private var setupFailed = false
    private var accountsFailed = false
    private fun failed(setup: Boolean = setupFailed, accounts: Boolean = accountsFailed) {
        setupFailed = setup; accountsFailed = accounts; unsaved.value = setup || accounts
    }

    // Sealed: it can hold imported WireGuard private keys and a Tailscale auth key.
    private val _setup = MutableStateFlow(load("setup.bin") { json.decodeFromString(Setup.serializer(), it).migrated() } ?: Setup(version = VERSION))
    val setup: StateFlow<Setup> = _setup.asStateFlow()

    /** Applies [f]; false when it couldn't be written (see [unsaved]), so callers keep a pasted secret on the clipboard. */
    @Synchronized
    fun update(f: (Setup) -> Setup): Boolean {
        change(f)
        return saveSetup()
    }

    /**
     * Applies [f] at once and writes it on [writer], so a tap never waits for the keyring and the disk. Each write
     * takes the newest setup, so the last one on disk is always the latest; a failed one shows [unsaved], as [update].
     */
    fun edit(f: (Setup) -> Setup) {
        change(f)
        if (queued.compareAndSet(false, true)) writer.execute { queued.set(false); synchronized(this) { saveSetup() } }
    }

    /** Waits for the writes [edit] queued so far. */
    fun flush() = writer.submit {}.get()

    // Its own lock, not the one saves hold: a tap's edit never waits for a write under way. Changes still apply one at a time.
    private val changing = Any()
    private val queued = java.util.concurrent.atomic.AtomicBoolean()
    private val writer = java.util.concurrent.Executors.newSingleThreadExecutor { Thread(it, "store").apply { isDaemon = true } }

    // Wherever a route is removed, profiles that used it are mended here.
    private fun change(f: (Setup) -> Setup) = synchronized(changing) { _setup.update { f(it).tidy() } }

    // A keyring hiccup must not crash a tap: the change stays in memory, the banner says so, and a retry writes it.
    private fun saveSetup() = safely { seal("setup.bin", json.encodeToString(Setup.serializer(), _setup.value)) }
        .also { if (!it) Log.e("Unbraid", "store: setup not saved"); failed(setup = !it) }
    private fun saveAccounts() = safely { seal("accounts.bin", json.encodeToString(accountsSer, _accounts.value)) }
        .also { if (!it) Log.e("Unbraid", "store: accounts not saved"); failed(accounts = !it) }
    private inline fun safely(f: () -> Boolean) = runCatching(f).getOrDefault(false)

    /** Writes what is in memory again, after a failed save (the user's retry). True if all of it is on disk now. */
    @Synchronized
    fun saveAgain(): Boolean {
        return saveSetup() and saveAccounts()
    }

    /** Cached server catalog per provider. */
    fun countries(provider: String): List<Country> =
        read("countries-$provider.json")?.let { runCatching { json.decodeFromString(countriesSer, it) }.getOrNull() }.orEmpty()

    /** True when [provider]'s cached catalog is under a day old. */
    fun countriesFresh(provider: String) = File(dir, "countries-$provider.json").let { it.exists() && System.currentTimeMillis() - it.lastModified() < 86_400_000 }

    @Synchronized
    fun countries(provider: String, v: List<Country>) = write("countries-$provider.json", json.encodeToString(countriesSer, v))

    /** When each gluetun catalogue last read was published (epoch seconds, [Catalog.published]); kept across restarts. */
    val catalogDates = MutableStateFlow(read("catalog-dates.json")?.let { runCatching { json.decodeFromString(datesSer, it) }.getOrNull() }.orEmpty())

    @Synchronized
    fun catalogDate(name: String, epochSeconds: Long) {
        val d = catalogDates.value
        if (d[name] != epochSeconds) (d + (name to epochSeconds)).let { if (write("catalog-dates.json", json.encodeToString(datesSer, it))) catalogDates.value = it }
    }

    /** Last tunnel that worked per "provider|location", used when a provider's API is unreachable. Holds keys, so sealed. */
    val lastLinks: Map<String, Link>
        get() = runCatching { open("links.bin")?.let { json.decodeFromString(linksSer, it) } }.getOrNull().orEmpty()

    /** Merges [add], keeping only providers still signed in (a sign-out may have raced a connect). Only a cache: never throws. */
    @Synchronized
    fun rememberLinks(add: Map<String, Link>) {
        val live = _accounts.value.keys
        if (!safely { seal("links.bin", json.encodeToString(linksSer, (lastLinks + add).filterKeys { it.substringBefore('|') in live })) }) Log.w("Unbraid", "store: last servers not saved")
    }

    /** Signed-in providers: provider id → the sealed account blob its [Provider.signIn] returned. */
    private val _accounts = MutableStateFlow(
        load("accounts.bin") { json.decodeFromString(accountsSer, it) } ?: migrateNord(),
    )
    val accounts: StateFlow<Map<String, String>> = _accounts.asStateFlow()

    /**
     * False when the change couldn't be written. It applies in memory anyway: a new sign-in holds a device slot the
     * provider just gave, which only this copy knows; [unsaved] tells the user, and [saveAgain] retries.
     */
    @Synchronized
    fun account(provider: String, blob: String?): Boolean {
        _accounts.update { if (blob == null) it - provider else it + (provider to blob) }
        val ok = saveAccounts()
        if (blob == null) rememberLinks(emptyMap())
        return ok
    }

    /** Preview builds kept the Nord token and key in their own files. */
    private fun migrateNord(): Map<String, String> {
        val t = open("token.bin") ?: return emptyMap()
        val k = open("nlk.bin") ?: return emptyMap()
        val m = mapOf("nord" to json.encodeToString(Nord.Account.serializer(), Nord.Account(t, k)))
        if (safely { seal("accounts.bin", json.encodeToString(accountsSer, m)) }) listOf("token.bin", "nlk.bin", "servers.json").forEach { File(dir, it).delete() }
        return m
    }


    /** The tailnet's MagicDNS domain, learned once Tailscale is signed in. */
    var tsSuffix: String?
        get() = read("tssuffix")
        set(v) { if (v == null) File(dir, "tssuffix").delete() else write("tssuffix", v) }

    /**
     * A Tailscale node may be kept for this user: on Linux its state lives in the engine's own root-only directory, so
     * the app only notes that it started one, until the engine forgets it ([app.unbraid.vpn.UnbraidVpn.forgetTailscale]).
     */
    var tsStored: Boolean
        get() = File(dir, TS_USED).exists()
        set(v) { if (v) write(TS_USED, "1") else File(dir, TS_USED).delete() }

    /** Which block of the fake-IP pool the engine's last domain table used ([app.unbraid.vpn.Compiler.FAKE_RANGES]). */
    var fakeBlock: Int
        get() = read("fakeblock")?.toIntOrNull() ?: app.unbraid.vpn.Compiler.blockAfterHalf(read("fakehalf")?.toIntOrNull())
        set(v) = check(write("fakeblock", "$v"))

    /** The user agreed to M-Lab's terms for speed tests (results, with the exit's IP address, are published). */
    var mlabConsent: Boolean
        get() = File(dir, "mlab").exists()
        set(v) { if (v) write("mlab", "1") else File(dir, "mlab").delete() }

    /** Speed tests run today, for M-Lab's limit of 40 a day per user: "epochDay count". */
    var testsToday: Int
        get() = read("mlabday")?.split(' ')?.takeIf { it.getOrNull(0) == "${java.time.LocalDate.now().toEpochDay()}" }?.getOrNull(1)?.toIntOrNull() ?: 0
        set(v) { write("mlabday", "${java.time.LocalDate.now().toEpochDay()} $v") }

    /**
     * A speed test switched Tailscale to another exit node and hasn't switched it back yet: the stable ID of the node in
     * use before ("" for none); null when nothing is to be undone. Older versions wrote "1", which is no node ID.
     */
    var tsTestFrom: String?
        get() = read("tstest")?.takeIf { it != "1" } ?: if (File(dir, "tstest").exists()) "" else null
        set(v) { if (v != null) write("tstest", v) else File(dir, "tstest").delete() }

    fun signOutAll() {
        _accounts.value.keys.toList().forEach { account(it, null) }
        // Also over a file that didn't open (then nothing was in memory to remove): it must not come back later.
        _accounts.value = emptyMap(); saveAccounts()
        update { it.copy(home = it.home.copy(tsAuthKey = null)) }
        File(dir, "expiry").delete() // left by older versions
        tsSuffix = null
        // Copies of files that once failed to open hold accounts and keys too.
        listOf("links.bin", "cache.db", "setup.bin.bad", "accounts.bin.bad", "links.bin.bad").forEach { File(dir, it).delete() }
        File(dir, TS_USED).delete()
    }

    private fun read(name: String) = File(dir, name).takeIf { it.exists() }?.readText()

    private fun write(name: String, text: String) = durable(name, text.toByteArray())

    /** Replaces [name] with [bytes] in one rename, the data synced to disk first so a crash can't leave it half written. */
    private fun durable(name: String, bytes: ByteArray): Boolean {
        val tmp = File(dir, "$name.tmp")
        return try {
            FileOutputStream(tmp).use { it.write(bytes); it.fd.sync() }
            tmp.renameTo(File(dir, name))
        } finally { tmp.delete() }
    }

    /**
     * Reads a sealed file. One that exists but won't open (keyring reset, corruption) is kept as "<name>.bad" rather
     * than silently replaced by defaults on the next write.
     */
    private fun <T> load(name: String, decode: (String) -> T): T? {
        val text = open(name)
        val v = text?.let { runCatching { decode(it) }.getOrNull() }
        if (v == null && File(dir, name).exists()) runCatching { File(dir, name).copyTo(File(dir, "$name.bad"), overwrite = true) }
        return v
    }

    private fun seal(name: String, value: String?): Boolean {
        if (value == null) return File(dir, name).delete()
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key) }
        return durable(name, c.iv + c.doFinal(value.toByteArray()))
    }

    private fun open(name: String): String? {
        val b = File(dir, name).takeIf { it.exists() }?.readBytes() ?: return null
        return runCatching {
            val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, b, 0, 12)) }
            String(c.doFinal(b, 12, b.size - 12))
        }.getOrNull()
    }

    private companion object {
        const val TS_USED = "tailscale.used"
        val countriesSer = ListSerializer(Country.serializer())
        val linksSer = MapSerializer(String.serializer(), Link.serializer())
        val accountsSer = MapSerializer(String.serializer(), String.serializer())
        val datesSer = MapSerializer(String.serializer(), Long.serializer())
    }
}
