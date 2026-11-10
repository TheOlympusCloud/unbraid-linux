package app.unbraid.linux

import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import java.util.Base64
import java.util.concurrent.TimeUnit
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * The key that seals the store, as the Android Keystore held it: in the desktop keyring (Secret Service, through
 * secret-tool), else in a file only this user can read. [WHERE] remembers which, so a keyring that is locked or gone
 * later fails the read instead of starting a new key that would leave the sealed files unreadable.
 */
object Keyring {
    private const val WHERE = "key.where"
    private const val FILE = "key"
    private val ATTRS = listOf("application", "unbraid", "kind", "store-key")

    fun key(dir: File, tool: String = "secret-tool", seconds: Long = 60): SecretKey {
        val where = File(dir, WHERE)
        return when (where.takeIf { it.exists() }?.readText()?.trim()) {
            "keyring" -> decode(run(tool, listOf("lookup") + ATTRS, seconds = seconds) ?: error("The desktop keyring didn't give unbraid its key. Unlock it and try again."))
            "file" -> decode(File(dir, FILE).readText())
            else -> {
                val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
                val text = Base64.getEncoder().encodeToString(key.encoded)
                // Stored, then read back: only a key the keyring really returns may seal anything.
                val inKeyring = run(tool, listOf("store", "--label", "unbraid storage key") + ATTRS, text, seconds) != null && run(tool, listOf("lookup") + ATTRS, seconds = seconds)?.trim() == text
                if (!inKeyring) private(File(dir, FILE)).writeText(text)
                private(where).writeText(if (inKeyring) "keyring" else "file")
                key
            }
        }
    }

    /** The key sits in a file beside what it seals: there was no desktop keyring when it was made. */
    fun inFile(dir: File) = File(dir, WHERE).takeIf { it.exists() }?.readText()?.trim() == "file"

    private fun decode(text: String): SecretKey = SecretKeySpec(Base64.getDecoder().decode(text.trim()), "AES")

    /** A new empty file only this user can read or write. */
    private fun private(f: File) = f.apply {
        delete()
        Files.createFile(toPath(), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
    }

    /**
     * [tool]'s output, or null if it is missing, fails or takes longer than [seconds] (an unlock prompt left open must not
     * hold the app's start). The secret goes in on stdin, never on the command line; the little that comes out is read
     * once it has exited.
     */
    private fun run(tool: String, args: List<String>, input: String? = null, seconds: Long = 60): String? = runCatching {
        val p = ProcessBuilder(listOf(tool) + args).redirectError(ProcessBuilder.Redirect.DISCARD).start()
        p.outputStream.use { o -> input?.let { o.write(it.toByteArray()) } }
        if (!p.waitFor(seconds, TimeUnit.SECONDS)) { p.destroyForcibly(); return@runCatching null }
        p.inputStream.bufferedReader().readText().takeIf { p.exitValue() == 0 && (input != null || it.isNotBlank()) }
    }.getOrNull()
}
