package app.unbraid

import app.unbraid.data.DIRECT
import app.unbraid.data.Link
import app.unbraid.data.Location
import app.unbraid.data.Nord
import app.unbraid.data.Route
import app.unbraid.data.Server
import app.unbraid.data.Setup
import app.unbraid.data.WgLink
import app.unbraid.vpn.Compiler
import app.unbraid.vpn.Linux
import app.unbraid.vpn.Matchers
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class LinuxTest {
    private val key = "aGVsbG8taGVsbG8taGVsbG8taGVsbG8taGVsbG8tMTI="
    // Each route its own server: routes on one server with one key share a tunnel.
    private fun sv(n: String) = Server("$n #1", "$n.nordvpn.com", "10.9.${n[0].code}.${n[1].code}", "5p4RkybdRU5uaDi90eu4KZPTFif0lKCg4Qp6t1c4F30=", 10)

    private val setup = Setup(
        routes = listOf(Route("nl", Location("nord", 153, "NL", "Netherlands")), Route("us", Location("nord", 228, "US", "United States"), hue = 1)),
        defaultRoute = "nl",
        apps = mapOf("firefox" to "us", "/usr/bin/curl" to "us", "spotify" to DIRECT, "gone" to "us"),
    )
    private val known = mapOf(
        "firefox" to Matchers(paths = listOf("/usr/lib/firefox/firefox"), dirs = listOf("/usr/lib/firefox/"), names = listOf("firefox")),
        "spotify" to Matchers(paths = listOf("/opt/spotify/spotify")),
    )
    private fun apps(k: String) = if (k.startsWith('/')) Matchers(paths = listOf(k)) else known[k] ?: Matchers()
    private fun links(s: Setup): Map<String, Link> = s.activeRoutes.associate { r -> r.id to WgLink(sv(r.id), Nord.peer(sv(r.id), key)) }

    private fun linux(s: Setup = setup, self: String? = "/usr/lib/unbraid/bin/unbraid"): JsonObject {
        val out = Linux.config(Compiler.compile(Compiler.Input(s, links(s), "app.unbraid", true, "tailscale", "cache.db", probe = 40000 to "pw")), ::apps, self)
        File("build/compiled-linux").apply { mkdirs() }.resolve("linux-${s.hashCode()}-${self != null}.json").writeText(out)
        return Json.parseToJsonElement(out).jsonObject
    }
    private fun JsonObject.rules() = this["route"]!!.jsonObject["rules"]!!.jsonArray.map { it.jsonObject }
    private fun JsonObject.outbound() = this["outbound"]?.jsonPrimitive?.content

    /** No Android package rule is left; each app is known by its processes, all of its kinds in one OR rule. */
    @Test fun appsAreMatchedByProcess() {
        val c = linux()
        assertFalse("package_name" in c.toString())
        val us = c.rules().filter { it.outbound() == "r-us" && "inbound" !in it } // the app's own probe has a rule of its own
        // firefox and curl share the route: one rule, with the paths of both, firefox's folder and its name.
        val rule = us.single()
        assertEquals("logical", rule["type"]!!.jsonPrimitive.content)
        assertEquals("or", rule["mode"]!!.jsonPrimitive.content)
        val branches = rule["rules"]!!.jsonArray.map { it.jsonObject }
        assertEquals(listOf("/usr/bin/curl", "/usr/lib/firefox/firefox"), branches.first { "process_path" in it }["process_path"]!!.jsonArray.map { it.jsonPrimitive.content })
        assertEquals("^/usr/lib/firefox/", branches.first { "process_path_regex" in it }["process_path_regex"]!!.jsonArray.single().jsonPrimitive.content)
        assertEquals("firefox", branches.first { "process_name" in it }["process_name"]!!.jsonArray.single().jsonPrimitive.content)
        // The lookup at the app's exit comes first, for the same processes.
        val resolve = c.rules().first { it["action"]?.jsonPrimitive?.content == "resolve" && it["server"]?.jsonPrimitive?.content == "dns-r-us" && "inbound" !in it }
        assertEquals("logical", resolve["type"]!!.jsonPrimitive.content)
    }

    /** An app no process is known for (uninstalled) matches nothing: its traffic can't be told apart, so it follows the default. */
    @Test fun appWithoutProcessMatchesNothing() {
        val c = linux(setup.copy(apps = mapOf("gone" to "us")))
        assertTrue(c.rules().none { it.outbound() == "r-us" && "inbound" !in it })
        assertEquals("r-nl", c["route"]!!.jsonObject["final"]!!.jsonPrimitive.content)
    }

    /** Linux can't leave an app out of the VPN: Direct apps pass through the engine and go out directly, like the LAN. */
    @Test fun directAppsLeaveThroughTheEngine() {
        val c = linux()
        val tun = c["inbounds"]!!.jsonArray[0].jsonObject
        assertNull(tun["exclude_package"]); assertNull(tun["route_exclude_address"]); assertNull(tun["route_address"])
        val direct = c.rules().filter { it["process_path"]?.jsonArray?.map { p -> p.jsonPrimitive.content } == listOf("/opt/spotify/spotify") }
        assertEquals(listOf("local", null), direct.map { it["server"]?.jsonPrimitive?.content })
        assertEquals("direct", direct.last().outbound())
        assertTrue(c.rules().any { it["ip_cidr"]?.jsonArray?.any { r -> r.jsonPrimitive.content == "192.168.0.0/16" } == true && it.outbound() == "direct" })
    }

    /** The app itself goes out directly, as Android leaves it out, but only from the TUN: its tests must use the exit they test. */
    @Test fun ownTrafficGoesDirectOnlyFromTheTun() {
        val rules = linux().rules()
        val own = rules.withIndex().filter { (_, r) -> r["process_path"]?.jsonArray?.singleOrNull()?.jsonPrimitive?.content == "/usr/lib/unbraid/bin/unbraid" }
        assertEquals(2, own.size)
        own.forEach { (_, r) -> assertEquals(listOf("tun"), r["inbound"]!!.jsonArray.map { it.jsonPrimitive.content }) }
        assertEquals("direct", own.last().value.outbound())
        // After stale fake IPs are refused, before any exit.
        val stale = rules.indexOfFirst { it["action"] == JsonPrimitive("reject") && "ip_cidr" in it }
        assertEquals(stale + 1, own.first().index)
        assertTrue(rules.indexOfFirst { it.outbound()?.startsWith("r-") == true } > own.last().index)
        assertTrue(linux(self = null).rules().none { "process_path" in it && "inbound" in it })
    }

    /** Nothing about lookups is kept on disk, and every connection is matched to its process (for statistics). */
    @Test fun noCacheFileAndEveryProcessFound() {
        val c = linux()
        assertNull(c["experimental"])
        assertEquals(JsonPrimitive(true), c["route"]!!.jsonObject["find_process"])
    }

    @Test fun foldersAreQuotedForTheEngine() {
        assertEquals("""/opt/My App \(2\)/v1\.0\+x/""", Linux.quote("/opt/My App (2)/v1.0+x/"))
        assertEquals("""/a\[b\]\{c\}\^\$\|\*\?\\/""", Linux.quote("""/a[b]{c}^$|*?\/"""))
    }
}
