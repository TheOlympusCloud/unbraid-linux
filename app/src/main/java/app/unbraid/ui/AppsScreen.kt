package app.unbraid.ui

import androidx.compose.foundation.background
import androidx.compose.material3.MaterialTheme
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.border
import androidx.compose.foundation.horizontalScroll
import app.unbraid.APP
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.unbraid.data.DIRECT
import app.unbraid.data.Setup
import androidx.compose.foundation.focusable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsHoveredAsState
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.HorizontalDivider
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.input.key.key
import androidx.compose.ui.input.key.onPreviewKeyEvent
import androidx.compose.ui.input.key.type
import androidx.compose.ui.input.pointer.PointerIcon
import androidx.compose.ui.input.pointer.pointerHoverIcon
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextAlign
import app.unbraid.linux.Apps
import app.unbraid.linux.Desktop
import app.unbraid.stats.Stats
import java.time.LocalDate
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private fun Setup.codeOf(id: String) = route(id)?.code ?: "··"
private fun Setup.colorOf(id: String) = route(id)?.let { Ink.route(it.hue) } ?: Ink.direct

private enum class Sort(val label: String) { Name("Name"), Kind("Kind"), Route("Route"), Today("Today") }

/**
 * The installed apps as a table: search, filter by exit, sort by any column. A selected app opens its route choices
 * in the panel on the right; a right click on any app offers them at once.
 */
@Composable
fun AppsScreen(ui: Ui, disclose: () -> Unit, openPicker: (String) -> Unit) {
    val disclosed by ui.disclosed.collectAsStateWithLifecycle()
    // The setup as the viewed profile routes it; its route list and prefs are the live ones.
    val setup by ui.shown.collectAsStateWithLifecycle()
    val viewing by ui.viewing.collectAsStateWithLifecycle()
    val apps by ui.apps.collectAsStateWithLifecycle()
    var q by rememberSaveable { mutableStateOf("") }
    // What points at one profile's exits starts over when another is viewed; the search stays.
    var filter by rememberSaveable(viewing) { mutableStateOf<String?>(null) }
    var showSystem by rememberSaveable { mutableStateOf(false) }
    var sort by rememberSaveable { mutableStateOf(Sort.Name) }
    var down by rememberSaveable { mutableStateOf(false) }
    var selected by rememberSaveable { mutableStateOf<String?>(null) }
    val draft = viewing != null && viewing != setup.profile
    val list = rememberLazyListState()
    val scope = rememberCoroutineScope()
    val search = remember { FocusRequester() }
    val table = remember { FocusRequester() }
    // Ctrl+F, also from another page: the search box, once this page shows.
    val pending by Desk.pending.collectAsStateWithLifecycle()
    LaunchedEffect(pending, disclosed) { if (pending == Desk.Ask.Search) { Desk.pending.value = null; if (disclosed) runCatching { search.requestFocus() } } }
    OnReselect(Tab.Apps) { if (selected != null || filter != null) { selected = null; filter = null } else list.animateScrollToItem(0) }
    // Today's data per app, while statistics are recorded: read again each minute.
    val stats = setup.prefs.stats
    val today by produceState(emptyMap<String, Long>(), stats) {
        while (stats) {
            val d = LocalDate.now().toEpochDay()
            value = withContext(Dispatchers.IO) { runCatching { Stats.apps(d, d).groupBy({ it.first }, { it.third }).mapValues { it.value.sum() } }.getOrDefault(emptyMap()) }
            delay(60_000)
        }
        value = emptyMap()
    }
    val placeOf = { a: AppInfo -> setup.routeOf(a.follows(setup) ?: a.pkg) }
    val nameOf = { id: String -> setup.route(id)?.name ?: if (id == DIRECT) "Direct" else "" }
    val query = q.trim()
    val shown = remember(apps, setup, query, filter, showSystem, sort, down, today) {
        val by: Comparator<AppInfo> = when (sort) {
            Sort.Name -> compareBy { it.label.lowercase() }
            Sort.Kind -> compareBy<AppInfo> { it.kind }.thenBy { it.label.lowercase() }
            Sort.Route -> compareBy<AppInfo> { nameOf(placeOf(it)).lowercase() }.thenBy { it.label.lowercase() }
            Sort.Today -> compareByDescending<AppInfo> { today[it.pkg] ?: 0L }.thenBy { it.label.lowercase() }
        }
        apps.filter { a ->
            (showSystem || !a.system || a.pkg in setup.apps) &&
                (filter == null || placeOf(a) == filter) &&
                (query.isEmpty() || a.label.contains(query, true) || a.pkg.contains(query, true))
        }.sortedWith(if (down) by.reversed() else by)
    }
    val direct = apps.count { setup.apps[it.pkg] == DIRECT }
    val routed = apps.count { it.pkg in setup.apps } - direct
    val pick = rememberFilePicker("Choose a program") { f -> f?.let(ui::addProgram)?.let { p -> q = ""; filter = null; selected = p } }
    val select = { pkg: String -> selected = pkg; shown.indexOfFirst { it.pkg == pkg }.takeIf { it >= 0 }?.let { scope.launch { list.animateScrollToItem(it) } }; Unit }
    // The arrow keys walk the table, as in any desktop list.
    val step = { by: Int ->
        val at = shown.indexOfFirst { it.pkg == selected }
        shown.getOrNull(if (at < 0) 0 else (at + by).coerceIn(0, shown.lastIndex))?.let { select(it.pkg) }
    }

    Row(Modifier.fillMaxSize()) {
        Column(Modifier.weight(1f).fillMaxHeight().padding(start = 30.dp, top = 26.dp, end = 22.dp)) {
            PageHeader("${apps.size} installed · $routed routed · $direct direct", "Apps") {
                if (disclosed) PillButton("Add a program", pick, Icons.add)
            }
            if (draft) Column(Modifier.padding(bottom = 10.dp)) {
                Text("Editing $viewing · not in use. ${setup.profile?.let { "$it is in use." } ?: "No profile is in use."}", style = Type.caption, color = Ink.dim)
                if (setup.defaultRoute.isEmpty()) Text("Choose a default route on Routes", style = Type.caption, color = Ink.dim, modifier = Modifier.padding(top = 4.dp))
                Row {
                    Secondary("Back to ${setup.profile ?: "current setup"}", { ui.view(null) })
                    if (setup.defaultRoute.isNotEmpty()) Secondary("Use $viewing", { ui.useProfile(viewing.orEmpty()) })
                }
            }
            if (!disclosed) {
                Column(Modifier.padding(top = 12.dp).then(tourAnchor(TourStop.AppsList)), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text("$APP needs the list of installed apps to route each one. It stays on this computer.", style = Type.sub, color = Ink.dim)
                    Secondary("Show my apps", disclose)
                }
                return@Column
            }
            SearchField(q, { q = it }, "Search apps", compact = true, trailing = { Keys("Ctrl+F") },
                field = Modifier.focusRequester(search).onPreviewKeyEvent { e ->
                    (e.type == KeyEventType.KeyDown && e.key == Key.DirectionDown && shown.isNotEmpty()).also { if (it) { step(if (selected == null) 0 else 1); runCatching { table.requestFocus() } } }
                })
            Row(Modifier.padding(vertical = 6.dp).horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip("All", Ink.text, filter == null) { filter = null }
                // Two routes with one country code (NordVPN NL, Mullvad NL) are told apart by provider.
                setup.routes.forEach { r ->
                    val label = if (setup.routes.count { it.code == r.code } > 1) "${r.code} · ${r.source}" else r.code
                    FilterChip(label, Ink.route(r.hue), filter == r.id) { filter = r.id }
                }
                if (setup.defaultRoute.isEmpty()) FilterChip("Not set", null, filter == "") { filter = "" }
                FilterChip("Direct", Ink.direct, filter == DIRECT, direct = true) { filter = DIRECT }
                FilterChip("System", null, showSystem, independent = true) { showSystem = !showSystem }
            }
            // The column heads sort; again, the other way.
            Row(Modifier.fillMaxWidth().padding(start = 14.dp, end = 14.dp, top = 6.dp, bottom = 8.dp), horizontalArrangement = Arrangement.spacedBy(14.dp)) {
                Spacer(Modifier.width(32.dp))
                Column(Sort.Name, sort, down, Modifier.weight(1.7f)) { if (it == sort) down = !down else { sort = it; down = false } }
                Column(Sort.Kind, sort, down, Modifier.weight(1f)) { if (it == sort) down = !down else { sort = it; down = false } }
                Column(Sort.Route, sort, down, Modifier.weight(1.25f)) { if (it == sort) down = !down else { sort = it; down = false } }
                if (stats) Column(Sort.Today, sort, down, Modifier.width(76.dp), end = true) { if (it == sort) down = !down else { sort = it; down = false } }
            }
            Box(Modifier.fillMaxWidth().height(1.dp).background(Ink.surfaceHigh))
            LazyColumn(
                state = list,
                modifier = Modifier.weight(1f).testTag("apps").focusRequester(table).focusable().onPreviewKeyEvent { e ->
                    if (e.type != KeyEventType.KeyDown) false
                    else when (e.key) {
                        Key.DirectionDown -> { step(1); true }
                        Key.DirectionUp -> { step(-1); true }
                        else -> false
                    }
                },
                contentPadding = PaddingValues(top = 6.dp, bottom = 24.dp),
            ) {
                if (shown.isEmpty()) item("empty") { Text("No apps match", style = Type.sub, color = Ink.dim, modifier = Modifier.padding(vertical = 16.dp, horizontal = 14.dp)) }
                itemsIndexed(shown, key = { _, a -> a.pkg }) { i, a ->
                    Box(Modifier.then(if (i == 0) tourAnchor(TourStop.AppsList) else Modifier)) {
                        AppTableRow(ui, a, apps, setup, selected == a.pkg, today[a.pkg], stats, onClick = { selected = a.pkg; runCatching { table.requestFocus() } }, select = select, openPicker = openPicker)
                    }
                }
                item("addNote") {
                    Text("Add a program for one your launcher doesn't list, such as a command-line tool or a game. Scripts, AppImages and Windows programs can only follow the default route.",
                        style = Type.caption, color = Ink.faint, modifier = Modifier.padding(start = 14.dp, end = 14.dp, top = 14.dp))
                }
            }
        }
        Detail(ui, apps.firstOrNull { it.pkg == selected }, apps, setup, today[selected], stats, draft, select, openPicker)
    }
}

/** A column head that sorts the table, with the arrow of the order. */
@Composable
private fun Column(s: Sort, sort: Sort, down: Boolean, modifier: Modifier, end: Boolean = false, onClick: (Sort) -> Unit) = Text(
    s.label.uppercase() + if (s == sort) (if (down) " ▼" else " ▲") else "", style = Type.overline, color = if (s == sort) Ink.text else Ink.dim, maxLines = 1,
    textAlign = if (end) TextAlign.End else TextAlign.Start,
    modifier = modifier.clip(RoundedCornerShape(6.dp)).tap({ onClick(s) }, "Sort by ${s.label}", Role.Button).pointerHoverIcon(PointerIcon.Hand),
)

/** What a row says beside its route: an app that runs as another takes that one's; one that can't be told apart only the default. */
private fun noteOf(a: AppInfo, setup: Setup, apps: List<AppInfo>) = a.follows(setup)?.let { o -> "Runs as ${apps.firstOrNull { it.pkg == o }?.label ?: o}" }
    ?: "Default only".takeIf { !a.routable }

@Composable
private fun AppTableRow(ui: Ui, a: AppInfo, apps: List<AppInfo>, setup: Setup, selected: Boolean, today: Long?, stats: Boolean, onClick: () -> Unit, select: (String) -> Unit, openPicker: (String) -> Unit) {
    val source = remember { MutableInteractionSource() }
    val hovered by source.collectIsHoveredAsState()
    var menu by remember { mutableStateOf<Offset?>(null) }
    var height by remember { mutableIntStateOf(0) }
    val follows = a.follows(setup)
    val explicit = setup.apps[a.pkg]
    val current = setup.routeOf(follows ?: a.pkg)
    Box {
        Row(
            Modifier.fillMaxWidth().height(52.dp).clip(RoundedCornerShape(12.dp))
                .background(when { selected -> Ink.accentContainer; hovered -> Ink.surfaceHigh; else -> Color.Transparent })
                .onSizeChanged { height = it.height }.onRightClick { menu = it; onClick() }.hover(source).tap(onClick, a.label).padding(horizontal = 14.dp),
            verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            AppIcon(ui, a.pkg, a.label, 32.dp)
            Column(Modifier.weight(1.7f)) {
                Text(a.label, style = Type.body.copy(fontSize = Type.sub.fontSize), color = Ink.text, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(a.pkg, style = Type.small, color = Ink.faint, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            Text(a.kind, style = Type.caption, color = Ink.dim, maxLines = 1, modifier = Modifier.weight(1f))
            Row(Modifier.weight(1.25f), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                // An empty profile has no default route yet: its unassigned apps have no exit.
                if (current.isEmpty()) Text("Not set", style = Type.caption, color = Ink.dim)
                else RouteMark(setup.codeOf(current), setup.colorOf(current), filled = explicit != null, direct = current == DIRECT)
                noteOf(a, setup, apps)?.let { Text(it, style = Type.caption, color = Ink.dim, maxLines = 2, overflow = TextOverflow.Ellipsis) }
            }
            if (stats) Text(today?.let(::bytesText) ?: "—", style = Type.small, color = Ink.dim, textAlign = TextAlign.End, maxLines = 1, modifier = Modifier.width(76.dp))
        }
        ClickMenu(menu, height, { menu = null }) {
            val done = { menu = null }
            when {
                follows != null -> {
                    val o = apps.firstOrNull { it.pkg == follows }?.label ?: follows
                    MenuItem("Takes $o's route", {}, enabled = false)
                    MenuItem("Show $o", { done(); select(follows) }, icon = Icons.back)
                }
                !a.routable -> MenuItem("Follows the default route", {}, enabled = false)
                else -> {
                    MenuLabel("Route")
                    setup.routes.sortedByDescending { it.id == setup.defaultRoute }.forEach { r ->
                        MenuItem(r.name + if (r.id == setup.defaultRoute) " (default)" else "", { done(); ui.assign(a.pkg, r.id) },
                            lead = { RouteMark(r.code, Ink.route(r.hue)) }, checked = current == r.id)
                    }
                    MenuItem("Direct", { done(); ui.assign(a.pkg, DIRECT) }, lead = { RouteMark(null, Ink.direct, direct = true) }, checked = current == DIRECT, keys = null)
                    HorizontalDivider(Modifier.padding(vertical = 4.dp), color = Ink.line)
                    if (explicit != null) MenuItem("Use the default route", { done(); ui.assign(a.pkg, null) }, icon = Icons.back)
                    MenuItem("New route for this app…", { done(); openPicker("app:${a.pkg}") }, icon = Icons.add)
                }
            }
            Apps.programOf(a.pkg)?.let { path ->
                HorizontalDivider(Modifier.padding(vertical = 4.dp), color = Ink.line)
                MenuItem("Copy program path", { done(); Desktop.copy(path) }, icon = Icons.file)
            }
        }
    }
}


/** The selected app: what it runs as, its route choices, the apps that take its route, today's data. */
@Composable
private fun Detail(ui: Ui, a: AppInfo?, apps: List<AppInfo>, setup: Setup, today: Long?, stats: Boolean, draft: Boolean, select: (String) -> Unit, openPicker: (String) -> Unit) = Row(Modifier.fillMaxHeight()) {
    Box(Modifier.fillMaxHeight().width(1.dp).background(Ink.surfaceHigh))
    Column(
        Modifier.width(340.dp).fillMaxHeight().background(Ink.surface).verticalScroll(rememberScrollState()).padding(horizontal = 22.dp, vertical = 26.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        if (a == null) {
            Text("Select an app to choose its route.", style = Type.sub, color = Ink.dim)
            Text("A right click offers the routes at once; the arrow keys move through the list.", style = Type.caption, color = Ink.faint)
            return@Column
        }
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            AppIcon(ui, a.pkg, a.label, 46.dp)
            Column {
                Text(a.label, style = Type.title, color = Ink.text, maxLines = 2, overflow = TextOverflow.Ellipsis)
                Text(Apps.programOf(a.pkg) ?: a.pkg, style = Type.small, color = Ink.faint, maxLines = 2, overflow = TextOverflow.Ellipsis)
            }
        }
        val follows = a.follows(setup)
        val explicit = setup.apps[a.pkg]
        val current = setup.routeOf(follows ?: a.pkg)
        when {
            follows != null -> {
                val o = apps.firstOrNull { it.pkg == follows }?.label ?: follows
                Text("Takes $o's route: it runs as $o, and $APP can't tell their traffic apart.", style = Type.sub, color = Ink.dim)
                PillButton("Show $o", { select(follows) }, Icons.back, Pill.Outline)
            }
            // Linux: the engine can't tell a script's or an AppImage's traffic apart, so it can only follow the default.
            !a.routable -> Text("Follows the default route: it runs as a script, on Wine or Java, or from an AppImage, and $APP can't tell its traffic from other programs'.",
                style = Type.sub, color = Ink.dim)
            else -> {
                Text("ROUTE", style = Type.overline, color = Ink.dim, modifier = Modifier.padding(top = 6.dp))
                val tiles = setup.routes.sortedByDescending { it.id == setup.defaultRoute }
                val cells = tiles.map { it.id } + DIRECT + ""
                cells.chunked(2).forEach { pair ->
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        pair.forEach { id ->
                            val r = setup.route(id)
                            RouteTile(
                                when { r != null -> r.name; id == DIRECT -> "Direct"; else -> "New route" },
                                when { r != null -> if (id == setup.defaultRoute) "Default · ${r.source}" else r.loc.city ?: r.source; id == DIRECT -> "No VPN"; else -> "Pick a place" },
                                mark = { if (r != null) RouteMark(r.code, Ink.route(r.hue)) else if (id == DIRECT) RouteMark(null, Ink.direct, direct = true) else Icon(Icons.add, null, Modifier.size(20.dp), tint = Ink.dim) },
                                selected = id.isNotEmpty() && id == current, dashed = id.isEmpty(), modifier = Modifier.weight(1f),
                            ) { if (id.isEmpty()) openPicker("app:${a.pkg}") else ui.assign(a.pkg, id) }
                        }
                        if (pair.size == 1) Spacer(Modifier.weight(1f))
                    }
                }
                val also = apps.filter { it.follows(setup) == a.pkg }
                if (also.isNotEmpty()) {
                    Text("TAKES THIS ROUTE TOO", style = Type.overline, color = Ink.dim, modifier = Modifier.padding(top = 6.dp))
                    also.forEach { f ->
                        Row(Modifier.clip(RoundedCornerShape(10.dp)).tap({ select(f.pkg) }, "Show ${f.label}").pointerHoverIcon(PointerIcon.Hand).padding(vertical = 2.dp),
                            verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                            AppIcon(ui, f.pkg, f.label, 26.dp)
                            Text(f.label, style = Type.sub, color = Ink.text, maxLines = 1)
                            Text("runs as ${a.label}", style = Type.caption, color = Ink.dim, maxLines = 1)
                        }
                    }
                }
                // A Direct app's lookups: outside unbraid (the computer's DNS) or through it, with unbraid's filter.
                val f = setup.prefs.filter
                // A setting of every profile: not offered while editing a profile not in use.
                if (explicit == DIRECT && f.server() != null && !draft) {
                    val on = f.through(a.pkg)
                    GroupRow(0, 1, "Filter its lookups", if (on) "Through $APP, with ${f.server()?.name}. The app can see a VPN is on" else "Outside $APP, with the computer's DNS",
                        onClick = { ui.setPrefs { p -> p.copy(filter = p.filter.copy(apps = if (!on == p.filter.directApps) p.filter.apps - a.pkg else p.filter.apps + (a.pkg to !on))) } },
                        checked = on, trailing = { Toggle(on) })
                }
                if (explicit != null) PillButton("Use the default route", { ui.assign(a.pkg, null) }, kind = Pill.Outline, modifier = Modifier.fillMaxWidth())
            }
        }
        if (stats) {
            Text("TODAY", style = Type.overline, color = Ink.dim, modifier = Modifier.padding(top = 6.dp))
            Text(today?.let { "${bytesText(it)} through ${setup.route(current)?.name ?: if (current == DIRECT) "your own connection" else "the default route"}" } ?: "No traffic yet today",
                style = Type.sub, color = Ink.dim)
        }
    }
}

/** One route to choose for the selected app: its mark and name, filled and outlined in the accent once chosen. */
@Composable
private fun RouteTile(name: String, sub: String, mark: @Composable () -> Unit, selected: Boolean, dashed: Boolean, modifier: Modifier, onClick: () -> Unit) {
    val source = remember { MutableInteractionSource() }
    val hovered by source.collectIsHoveredAsState()
    val shape = RoundedCornerShape(16.dp)
    Column(
        modifier.clip(shape)
            .background(when { selected -> Ink.accentContainer; dashed -> Color.Transparent; hovered -> Ink.surfaceTop; else -> Ink.surfaceHigh })
            .border(if (selected) 2.dp else 1.dp, when { selected -> Ink.accent; dashed -> Ink.line; else -> Color.Transparent }, shape)
            .hover(source).selectable(selected, role = Role.RadioButton, onClick = onClick).padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            mark()
            Spacer(Modifier.weight(1f))
            if (selected) Icon(Icons.check, null, Modifier.size(18.dp), tint = Ink.accent)
        }
        Column {
            Text(name, style = Type.body.copy(fontSize = Type.sub.fontSize), color = if (dashed) Ink.dim else Ink.text, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(sub, style = Type.caption, color = Ink.dim, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
    }
}

@Composable
private fun FilterChip(label: String, dot: Color?, on: Boolean, direct: Boolean = false, independent: Boolean = false, onClick: () -> Unit) = Box(
    // Exit filters are one choice among many; "System" is an independent on/off filter.
    Modifier.height(48.dp).then(if (independent) Modifier.toggleable(on, role = Role.Checkbox) { onClick() } else Modifier.selectable(on, role = Role.RadioButton, onClick = onClick)),
    contentAlignment = Alignment.Center,
) {
    val shape = RoundedCornerShape(12.dp)
    // Selection fades in with the effects spring, like the other selectable pills.
    val bg by animateColorAsState(if (on) Ink.surfaceTop else Color.Transparent, MaterialTheme.motionScheme.fastEffectsSpec(), label = "chip")
    val edge by animateColorAsState(if (on) Ink.surfaceTop else Ink.line, MaterialTheme.motionScheme.fastEffectsSpec(), label = "chipEdge")
    Row(
        Modifier.height(36.dp).clip(shape).background(bg).border(1.dp, edge, shape).padding(horizontal = 12.dp),
        verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(7.dp),
    ) {
        if (direct) Icon(Icons.direct, null, Modifier.size(14.dp), tint = Ink.direct)
        else dot?.let { Box(Modifier.size(8.dp).clip(CircleShape).background(it)) }
        Text(label, style = Type.sub.copy(fontWeight = FontWeight.Medium), color = if (on) Ink.text else Ink.dim, maxLines = 1)
    }
}
