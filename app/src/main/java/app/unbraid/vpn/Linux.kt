package app.unbraid.vpn

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** How the engine knows a Linux app by its process: exact programs, folders it runs from (ending in '/'), program names. */
data class Matchers(val paths: List<String> = emptyList(), val dirs: List<String> = emptyList(), val names: List<String> = emptyList()) {
    val empty get() = paths.isEmpty() && dirs.isEmpty() && names.isEmpty()
}

/**
 * Turns what [Compiler] writes for Android into the config the Linux engine runs. Compiled with `lockdown = true`, the
 * Android path where the system leaves no app out of the VPN, as Linux can't: Direct apps and the LAN pass through the
 * engine and leave directly, so no lookup (not even one sent to the router) gets past it.
 *
 * - `package_name` becomes the process the app runs as ([Matchers]); an app no process is known for matches nothing.
 * - The TUN loses the Android-only package lists; the app's own process ([self]) goes out directly, as Android excludes it.
 * - The engine's cache file goes: it would keep every name looked up on disk, where only root could delete it. Each
 *   engine start is a new domain table ([Compiler.nextBlock]).
 * - Every connection is matched to its process, so statistics can name the app.
 */
object Linux {
    /** Keys that say what a rule does rather than what it matches. */
    private val ACTION = setOf("action", "outbound", "server", "no_drop", "rewrite_ttl")

    fun config(json: String, apps: (String) -> Matchers, self: String?): String {
        val c = Json.parseToJsonElement(json).jsonObject.toMutableMap()
        c["dns"] = c["dns"]!!.jsonObject.let { d -> JsonObject(d + ("rules" to JsonArray(d["rules"]!!.jsonArray.mapNotNull { rule(it.jsonObject, apps) }))) }
        c["inbounds"] = JsonArray(c["inbounds"]!!.jsonArray.map { i -> JsonObject(i.jsonObject - "exclude_package" - "include_package") })
        c["route"] = c["route"]!!.jsonObject.let { r ->
            val rules = r["rules"]!!.jsonArray.mapNotNull { rule(it.jsonObject, apps) }.toMutableList()
            if (self != null) {
                // After the DNS hijacks and the refusal of stale fake IPs, before any exit: as early as Android leaves the app out.
                // Only from the TUN: the app's own tests come in on the probe inbound and must leave through the exit they test.
                val at = rules.indexOfFirst { it["action"] == JsonPrimitive("reject") && "ip_cidr" in it && "inbound" !in it }
                    .takeIf { it >= 0 } ?: rules.indexOfLast { it["action"] == JsonPrimitive("hijack-dns") }
                rules.addAll(at + 1, listOf(
                    obj("inbound" to arr("tun"), "process_path" to arr(self), "action" to JsonPrimitive("resolve"), "server" to JsonPrimitive("local")),
                    obj("inbound" to arr("tun"), "process_path" to arr(self), "outbound" to JsonPrimitive("direct")),
                ))
            }
            JsonObject(r + ("rules" to JsonArray(rules)) + ("find_process" to JsonPrimitive(true)))
        }
        c["experimental"]?.jsonObject?.let { e -> (e - "cache_file").let { if (it.isEmpty()) c.remove("experimental") else c["experimental"] = JsonObject(it) } }
        return JsonObject(c).toString()
    }

    /** [r] matching processes instead of Android packages; null when none of its apps has a known process. */
    private fun rule(r: JsonObject, apps: (String) -> Matchers): JsonObject? {
        val pkgs = r["package_name"]?.jsonArray?.map { it.jsonPrimitive.content } ?: return r
        val m = pkgs.map(apps).let { all -> Matchers(all.flatMap { it.paths }.distinct(), all.flatMap { it.dirs }.distinct(), all.flatMap { it.names }.distinct()) }
        if (m.empty) return null
        val kinds = listOfNotNull(
            ("process_path" to arr(*m.paths.toTypedArray())).takeIf { m.paths.isNotEmpty() },
            ("process_path_regex" to arr(*m.dirs.map { "^" + quote(it) }.toTypedArray())).takeIf { m.dirs.isNotEmpty() },
            ("process_name" to arr(*m.names.toTypedArray())).takeIf { m.names.isNotEmpty() },
        )
        val match = r.filterKeys { it != "package_name" && it !in ACTION }
        val action = r.filterKeys { it in ACTION }
        kinds.singleOrNull()?.let { return JsonObject(match + it + action) }
        // The engine ANDs different fields of one rule: either process kind matches, each with the rule's other conditions.
        return JsonObject(mapOf("type" to JsonPrimitive("logical"), "mode" to JsonPrimitive("or"), "rules" to JsonArray(kinds.map { JsonObject(match + it) })) + action)
    }

    /** [s] as a literal in the engine's (RE2) regular expressions. */
    fun quote(s: String) = s.replace(Regex("""[\\.+*?()|\[\]{}^$]"""), """\\$0""")

    private fun arr(vararg v: String) = JsonArray(v.map(::JsonPrimitive))
    private fun obj(vararg kv: Pair<String, JsonElement>) = JsonObject(kv.toMap())
}
