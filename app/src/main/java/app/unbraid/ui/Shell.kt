package app.unbraid.ui

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.TooltipArea
import androidx.compose.foundation.TooltipPlacement
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.hoverable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsHoveredAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialShapes
import androidx.compose.material3.Text
import androidx.compose.material3.toShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.pointer.PointerIcon
import androidx.compose.ui.input.pointer.pointerHoverIcon
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.unbraid.BuildConfig
import app.unbraid.vpn.UnbraidVpn
import app.unbraid.vpn.VpnState.Phase
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.RowScope
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.PointerEventType
import androidx.compose.ui.input.pointer.isSecondaryPressed
import androidx.compose.ui.input.pointer.onPointerEvent
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.DpOffset

/** What the window's keys, the tray and the sidebar ask the screens for. */
object Desk {
    val tab = MutableStateFlow(Tab.Routes)
    val asks = MutableSharedFlow<Ask>(extraBufferCapacity = 8)
    /** An ask for a page that may not be on screen yet (Ctrl+F from Routes): the page takes it once it shows, and clears it. */
    val pending = MutableStateFlow<Ask?>(null)

    enum class Ask { Search, NewRoute, Shortcuts, Connect, ManageProfiles }

    /** The window's shortcuts, as the shortcuts list shows them: what, and its keys. */
    val shortcuts = listOf(
        "Connect or disconnect" to "Ctrl+Shift+C", "Pause 15 minutes" to "Ctrl+Shift+P", "Routes" to "Ctrl+1", "Apps" to "Ctrl+2",
        "Stats" to "Ctrl+3", "Settings" to "Ctrl+,", "Search apps" to "Ctrl+F", "New route" to "Ctrl+N", "Close the open page or dialog" to "Esc",
        "Close the window" to "Ctrl+W", "Quit" to "Ctrl+Q", "This list" to "Ctrl+/",
    )

    fun key(tab: Tab) = when (tab) { Tab.Routes -> "Ctrl+1"; Tab.Apps -> "Ctrl+2"; Tab.Stats -> "Ctrl+3"; Tab.Settings -> "Ctrl+," }
}

/** Something under the pointer: rows, cards and buttons answer it, as desktop apps do. */
fun Modifier.hover(source: MutableInteractionSource): Modifier = hoverable(source).pointerHoverIcon(PointerIcon.Hand)

/**
 * The window's navigation: the wordmark, the connection with its power button, the pages, then the profiles. Wide, it
 * names everything; below [WIDE] it folds to a rail of icons whose names show on hover.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun Sidebar(ui: Ui, tab: Tab, wide: Boolean, onTab: (Tab) -> Unit, connect: () -> Unit) {
    val vpn by ui.vpn.collectAsStateWithLifecycle()
    val setup by ui.setup.collectAsStateWithLifecycle()
    val viewing by ui.viewing.collectAsStateWithLifecycle()
    Row(Modifier.fillMaxHeight()) {
        Column(
            Modifier.fillMaxHeight().width(if (wide) 248.dp else 72.dp).background(Ink.bar)
                .padding(horizontal = if (wide) 14.dp else 12.dp, vertical = 20.dp),
            horizontalAlignment = if (wide) Alignment.Start else Alignment.CenterHorizontally,
        ) {
            if (wide) Box(Modifier.padding(start = 10.dp, bottom = 18.dp)) { Wordmark(30) }
            Connection(ui, vpn, setup.route(setup.defaultRoute)?.name ?: "Direct", wide, connect)
            Spacer(Modifier.height(if (wide) 20.dp else 16.dp))
            Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
                Tab.entries.forEach { t -> NavItem(t.label, t.icon, Desk.key(t), t == tab, wide) { onTab(t) } }
            }
            Spacer(Modifier.weight(1f))
            if (wide) {
                Row(Modifier.fillMaxWidth().padding(start = 10.dp, end = 4.dp, bottom = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text("PROFILE", style = Type.overline, color = Ink.dim, modifier = Modifier.weight(1f))
                    Text(if (setup.profiles.isEmpty()) "Save…" else "Manage", style = Type.caption, color = Ink.accent,
                        modifier = Modifier.clip(RoundedCornerShape(8.dp)).tap({ Desk.tab.value = Tab.Routes; Desk.pending.value = Desk.Ask.ManageProfiles }, role = Role.Button)
                            .pointerHoverIcon(PointerIcon.Hand).padding(horizontal = 6.dp, vertical = 2.dp))
                }
                if (setup.profiles.isEmpty()) Text("Save this setup to switch back to it in one click.", style = Type.caption, color = Ink.faint, modifier = Modifier.padding(horizontal = 10.dp))
                else FlowRow(Modifier.padding(horizontal = 6.dp), horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    setup.profiles.forEach { p ->
                        val inUse = p.name == setup.profile
                        val shown = p.name == (viewing ?: setup.profile)
                        Text(p.name, style = Type.caption, color = if (inUse) Ink.ground else if (shown) Ink.text else Ink.dim, maxLines = 1,
                            modifier = Modifier.clip(RoundedCornerShape(16.dp))
                                .then(if (inUse) Modifier.background(Ink.text) else Modifier.border(1.dp, if (shown) Ink.accent else Ink.line, RoundedCornerShape(16.dp)))
                                .tap({ ui.view(p.name); Desk.tab.value = Tab.Routes }, label = if (inUse) "${p.name}, in use" else "Show ${p.name}", role = Role.Button)
                                .pointerHoverIcon(PointerIcon.Hand).padding(horizontal = 12.dp, vertical = 7.dp))
                    }
                }
                Row(Modifier.fillMaxWidth().padding(top = 14.dp, start = 10.dp, end = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text(BuildConfig.VERSION_NAME, style = Type.small, color = Ink.faint, modifier = Modifier.weight(1f))
                    Row(Modifier.clip(RoundedCornerShape(8.dp)).tap({ Desk.asks.tryEmit(Desk.Ask.Shortcuts) }, role = Role.Button).pointerHoverIcon(PointerIcon.Hand).padding(4.dp),
                        verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text("Shortcuts", style = Type.small, color = Ink.faint)
                        Keys("Ctrl+/")
                    }
                }
            }
        }
        Box(Modifier.fillMaxHeight().width(1.dp).background(Ink.surfaceHigh))
    }
}

/** The connection, as the sidebar keeps it in view on every page: its state, and the power button. */
@OptIn(ExperimentalMaterial3ExpressiveApi::class)
@Composable
private fun Connection(ui: Ui, vpn: app.unbraid.vpn.VpnState, exit: String, wide: Boolean, connect: () -> Unit) {
    var menu by remember { mutableStateOf(false) }
    val on = vpn.phase == Phase.On || vpn.phase == Phase.Connecting
    val label = when (vpn.phase) { Phase.On -> "Protected"; Phase.Paused -> "Paused"; Phase.Connecting -> "Connecting"; Phase.Off -> "Not connected" }
    val power = @Composable {
        Box {
            Box(
                Modifier.size(if (wide) 46.dp else 40.dp).clip(MaterialShapes.Cookie9Sided.toShape()).background(if (vpn.phase == Phase.Connecting) Ink.surfaceTop else stateColor(vpn.phase))
                    .tap({ if (on) menu = true else connect() }, label = if (on) "Pause or disconnect" else "Connect", role = Role.Button).pointerHoverIcon(PointerIcon.Hand),
                contentAlignment = Alignment.Center,
            ) { Icon(Icons.power, null, Modifier.size(if (wide) 24.dp else 20.dp), tint = Ink.ground) }
            DropdownMenu(menu, { menu = false }, containerColor = Ink.surfaceTop) {
                if (vpn.phase == Phase.On) DropdownMenuItem({ Text("Pause 15 minutes", style = Type.sub) }, { menu = false; ui.pause(15) }, leadingIcon = { Icon(Icons.pause, null, tint = Ink.text) })
                DropdownMenuItem({ Text("Disconnect", style = Type.sub) }, { menu = false; ui.disconnect() }, leadingIcon = { Icon(Icons.power, null, tint = Ink.text) })
            }
        }
    }
    if (!wide) { Tip(label) { power() }; return }
    Row(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(22.dp)).background(Ink.surface).padding(14.dp),
        verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        power()
        Column(Modifier.weight(1f)) {
            Text(label.uppercase(), style = Type.overline, color = if (vpn.phase == Phase.Connecting) Ink.dim else stateColor(vpn.phase), maxLines = 1)
            Text(if (vpn.phase == Phase.Off) "Unprotected" else exit, style = Type.body.copy(fontSize = Type.sub.fontSize), color = Ink.text, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(if (vpn.phase == Phase.Off) "Click to connect" else UnbraidVpn.summary.collectAsStateWithLifecycle().value.ifEmpty { " " }, style = Type.caption, color = Ink.dim, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
    }
}

@Composable
private fun NavItem(label: String, icon: ImageVector, keys: String, selected: Boolean, wide: Boolean, onClick: () -> Unit) {
    val source = remember { MutableInteractionSource() }
    val hovered by source.collectIsHoveredAsState()
    val ground = when { selected -> Ink.accentContainer; hovered -> Ink.surfaceHigh; else -> Ink.bar }
    val item = @Composable {
        Row(
            Modifier.then(if (wide) Modifier.fillMaxWidth() else Modifier.size(44.dp)).height(if (wide) 42.dp else 44.dp).clip(RoundedCornerShape(14.dp)).background(ground)
                .hover(source).tap(onClick, label, Role.Tab).then(if (wide) Modifier else Modifier.semantics { contentDescription = label })
                .padding(horizontal = if (wide) 12.dp else 0.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = if (wide) Arrangement.spacedBy(12.dp) else Arrangement.Center,
        ) {
            Icon(icon, null, Modifier.size(22.dp), tint = if (selected) Ink.accent else if (hovered) Ink.text else Ink.dim)
            if (wide) {
                Text(label, style = Type.body.copy(fontSize = Type.title.fontSize), color = if (selected || hovered) Ink.text else Ink.dim, modifier = Modifier.weight(1f))
                Text(keys, style = Type.small, color = Ink.faint)
            }
        }
    }
    if (wide) item() else Tip("$label  $keys") { item() }
}

/** A name on hover, for an icon that shows none (the folded sidebar). */
@OptIn(ExperimentalFoundationApi::class)
@Composable
fun Tip(text: String, content: @Composable () -> Unit) = TooltipArea(
    tooltip = { Text(text, style = Type.caption, color = Ink.ground, modifier = Modifier.clip(RoundedCornerShape(8.dp)).background(Ink.text).padding(horizontal = 9.dp, vertical = 5.dp)) },
    delayMillis = 400, tooltipPlacement = TooltipPlacement.CursorPoint(offset = androidx.compose.ui.unit.DpOffset(16.dp, 16.dp)),
) { content() }

/** Keys as a keyboard shows them. */
@Composable
fun Keys(keys: String) = Text(keys, style = Type.small, color = Ink.dim, maxLines = 1,
    modifier = Modifier.clip(RoundedCornerShape(6.dp)).background(Ink.surfaceHigh).border(1.dp, Ink.line, RoundedCornerShape(6.dp)).padding(horizontal = 6.dp, vertical = 1.dp))

/** Every shortcut of the window (Ctrl+/). */
@Composable
fun ShortcutsDialog(close: () -> Unit) = Dialog(onDismissRequest = close) {
    Column(Modifier.widthIn(min = 380.dp, max = 460.dp).clip(RoundedCornerShape(28.dp)).background(Ink.surface).padding(24.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text("KEYBOARD SHORTCUTS", style = Type.overline, color = Ink.dim, modifier = Modifier.padding(bottom = 8.dp))
        Desk.shortcuts.forEach { (what, keys) ->
            Row(Modifier.fillMaxWidth().height(32.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(what, style = Type.sub, color = Ink.text, modifier = Modifier.weight(1f))
                Keys(keys)
            }
        }
        Row(Modifier.fillMaxWidth().padding(top = 12.dp), horizontalArrangement = Arrangement.End) { Secondary("Close", close) }
    }
}

/** Below this width the sidebar folds to a rail. */
val WIDE = 1000.dp

/** A desktop page's head: what it holds (the overline), its title in the display face, its actions on the right. */
@Composable
fun PageHeader(overline: String, title: String, overlineColor: Color = Ink.dim, sub: String? = null, actions: @Composable RowScope.() -> Unit = {}) = Row(
    Modifier.fillMaxWidth().padding(bottom = 16.dp), verticalAlignment = Alignment.Bottom, horizontalArrangement = Arrangement.spacedBy(10.dp),
) {
    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(wordmarked(overline.uppercase()), style = Type.overline, color = overlineColor, maxLines = 1, overflow = TextOverflow.Ellipsis)
        Text(title.uppercase(), style = Type.headline, color = Ink.text, maxLines = 1)
        sub?.let { Text(it, style = Type.sub, color = Ink.dim, maxLines = 2, overflow = TextOverflow.Ellipsis) }
    }
    actions()
}

enum class Pill { Primary, Tonal, Outline }

/** A toolbar button: a pill, filled for the page's main action. */
@Composable
fun PillButton(text: String, onClick: () -> Unit, icon: ImageVector? = null, kind: Pill = Pill.Tonal, enabled: Boolean = true, modifier: Modifier = Modifier) {
    val source = remember { MutableInteractionSource() }
    val hovered by source.collectIsHoveredAsState()
    val shape = RoundedCornerShape(20.dp)
    val (bg, fg) = when (kind) {
        Pill.Primary -> Ink.accent to Ink.onAccent
        Pill.Tonal -> (if (hovered) Ink.surfaceTop else Ink.surfaceHigh) to Ink.text
        Pill.Outline -> (if (hovered) Ink.surfaceHigh else Color.Transparent) to Ink.text
    }
    Row(
        modifier.height(40.dp).clip(shape).background(bg).then(if (kind == Pill.Outline) Modifier.border(1.dp, Ink.line, shape) else Modifier)
            .then(if (enabled) Modifier.hover(source).tap(onClick, text, Role.Button) else Modifier).padding(horizontal = 18.dp),
        verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        icon?.let { Icon(it, null, Modifier.size(18.dp), tint = if (enabled) fg else Ink.faint) }
        Text(text, style = Type.title.copy(fontSize = Type.sub.fontSize), color = if (enabled) fg else Ink.faint, maxLines = 1)
    }
}

/** A right click, where it happened in the element's own coordinates. */
@OptIn(ExperimentalComposeUiApi::class)
fun Modifier.onRightClick(at: (Offset) -> Unit) = onPointerEvent(PointerEventType.Press) { e -> if (e.buttons.isSecondaryPressed) at(e.changes.first().position) }

/** A menu at a right click ([at], in the anchor's coordinates; the anchor is [height] px tall), in the app's colours. */
@Composable
fun ClickMenu(at: Offset?, height: Int, close: () -> Unit, content: @Composable ColumnScope.() -> Unit) {
    val d = LocalDensity.current
    DropdownMenu(at != null, close, containerColor = Ink.surfaceTop, shape = RoundedCornerShape(14.dp),
        offset = at?.let { with(d) { DpOffset(it.x.toDp(), (it.y - height).toDp()) } } ?: DpOffset.Zero, content = content)
}

@Composable
fun MenuItem(text: String, onClick: () -> Unit, icon: ImageVector? = null, lead: (@Composable () -> Unit)? = null, checked: Boolean = false, keys: String? = null, color: Color = Ink.text, enabled: Boolean = true) =
    DropdownMenuItem(
        { Text(text, style = Type.sub, color = if (enabled) color else Ink.faint, maxLines = 1) }, onClick, enabled = enabled,
        leadingIcon = lead ?: icon?.let { { Icon(it, null, Modifier.size(18.dp), tint = if (enabled) color else Ink.faint) } },
        trailingIcon = when { checked -> { { Icon(Icons.check, null, Modifier.size(18.dp), tint = Ink.accent) } }; keys != null -> { { Text(keys, style = Type.small, color = Ink.faint) } }; else -> null },
        modifier = Modifier.height(38.dp),
    )

/** A menu's section name. */
@Composable
fun MenuLabel(text: String) = Text(text.uppercase(), style = Type.overline, color = Ink.dim, modifier = Modifier.padding(start = 16.dp, top = 8.dp, bottom = 4.dp, end = 16.dp))
