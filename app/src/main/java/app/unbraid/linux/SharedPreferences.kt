package app.unbraid.linux

import java.io.File
import java.util.Properties

/** Android's SharedPreferences, as the onboarding and the UI use it: small values in a properties file, written at once. */
class SharedPreferences(private val file: File) {
    private val p = Properties().apply { runCatching { file.inputStream().use(::load) } }

    @Synchronized fun contains(key: String) = p.containsKey(key)
    @Synchronized fun getBoolean(key: String, def: Boolean) = p.getProperty(key)?.toBooleanStrictOrNull() ?: def
    @Synchronized fun getInt(key: String, def: Int) = p.getProperty(key)?.toIntOrNull() ?: def
    @Synchronized fun getLong(key: String, def: Long) = p.getProperty(key)?.toLongOrNull() ?: def

    inner class Editor {
        fun putBoolean(key: String, v: Boolean) { p.setProperty(key, "$v") }
        fun putInt(key: String, v: Int) { p.setProperty(key, "$v") }
        fun putLong(key: String, v: Long) { p.setProperty(key, "$v") }
    }

    /** Applies [f] and writes the file in one rename; a failed write keeps the change in memory, as Android's apply(). */
    @Synchronized fun edit(f: Editor.() -> Unit) {
        Editor().f()
        runCatching {
            val tmp = File(file.path + ".tmp")
            tmp.outputStream().use { p.store(it, null) }
            check(tmp.renameTo(file))
        }.onFailure { Log.w("Unbraid", "prefs: not saved") }
    }

    companion object {
        private val open = HashMap<String, SharedPreferences>()
        /** The named preferences in the app's folder, one object per name as on Android. */
        @Synchronized fun named(name: String) = open.getOrPut(name) { SharedPreferences(File(Paths.data, "$name.properties")) }
    }
}
