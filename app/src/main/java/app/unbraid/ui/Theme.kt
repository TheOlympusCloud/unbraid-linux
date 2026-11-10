package app.unbraid.ui

import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.MaterialExpressiveTheme
import androidx.compose.material3.MotionScheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.platform.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * Design tokens; change here, never inline. Dark, the app's own look, or light, as Settings › Desktop and the desktop's
 * own setting choose ([light]). Each is a state read, so every colour follows a switch at once.
 */
object Ink {
    var light by mutableStateOf(false)
    private val p get() = if (light) LIGHT else DARK
    val ground get() = p.ground
    val surface get() = p.surface
    val surfaceHigh get() = p.surfaceHigh
    val surfaceTop get() = p.surfaceTop
    val bar get() = p.bar
    val line get() = p.line
    val text get() = p.text
    val dim get() = p.dim
    val faint get() = p.faint
    val accent get() = p.accent
    val onAccent get() = p.onAccent
    val accentContainer get() = p.accentContainer
    val good get() = p.good
    val bad get() = p.bad
    val direct get() = p.direct
    /** The home network row: a green-tinted surface, set apart from internet exits. */
    val homeSurface get() = p.homeSurface
    /** Behind a dialog or the tour: the page, dimmed. */
    val scrim get() = p.scrim

    /** One color per route, equal lightness so none shouts. */
    val routes get() = p.routes

    fun route(hue: Int) = p.routes[hue.mod(p.routes.size)]
}

private class Palette(
    val ground: Color, val surface: Color, val surfaceHigh: Color, val surfaceTop: Color, val bar: Color, val line: Color,
    val text: Color, val dim: Color, val faint: Color, val accent: Color, val onAccent: Color, val accentContainer: Color,
    val good: Color, val bad: Color, val direct: Color, val homeSurface: Color, val scrim: Color, val routes: List<Color>,
)

private val DARK = Palette(
    ground = Color(0xFF0F1214), surface = Color(0xFF171B1E), surfaceHigh = Color(0xFF1E2428), surfaceTop = Color(0xFF232A2E),
    bar = Color(0xFF13171A), line = Color(0xFF343C42), text = Color(0xFFECEFF1), dim = Color(0xFF9AA5AD), faint = Color(0xFF7D8890),
    accent = Color(0xFFFFA66B), onAccent = Color(0xFF2A1A0F), accentContainer = Color(0xFF3A2A1F),
    good = Color(0xFF8EE0A8), bad = Color(0xFFFF8A80), direct = Color(0xFF7D8890), homeSurface = Color(0xFF13201A), scrim = Color(0x8C060809),
    routes = listOf(Color(0xFFFFA66B), Color(0xFF7CC4FF), Color(0xFFC9A7FF), Color(0xFF8EE0A8), Color(0xFFFFD36B), Color(0xFFFF9EBB), Color(0xFF6BE3DC)),
)

// The same hues a shade deeper, so text and marks keep their contrast on a light ground (WCAG AA for the body's ink).
private val LIGHT = Palette(
    ground = Color(0xFFF5F2EE), surface = Color(0xFFFFFFFF), surfaceHigh = Color(0xFFEEE9E3), surfaceTop = Color(0xFFE5DFD7),
    bar = Color(0xFFEDE8E2), line = Color(0xFFD6CFC6), text = Color(0xFF16191B), dim = Color(0xFF56626A), faint = Color(0xFF65707A),
    accent = Color(0xFFB85A1A), onAccent = Color(0xFFFFFFFF), accentContainer = Color(0xFFFBE2D0),
    good = Color(0xFF1C7E45), bad = Color(0xFFC7362B), direct = Color(0xFF65707A), homeSurface = Color(0xFFE4F2EA), scrim = Color(0x7A2A2420),
    routes = listOf(Color(0xFFC25418), Color(0xFF2A74B5), Color(0xFF7E57C8), Color(0xFF1F7F53), Color(0xFF8C6A00), Color(0xFFB83D67), Color(0xFF0F7F78)),
)

val Display = FontFamily(Font("font/bigshoulders_black.ttf", FontWeight.Black))
val Sans = FontFamily(Font("font/onest_regular.ttf"), Font("font/onest_medium.ttf", FontWeight.Medium), Font("font/onest_semibold.ttf", FontWeight.SemiBold))
val Mono = FontFamily(Font("font/martian_regular.ttf"), Font("font/martian_medium.ttf", FontWeight.Medium))

object Type {
    val headline = TextStyle(fontFamily = Display, fontWeight = FontWeight.Black, fontSize = 44.sp, lineHeight = 44.sp)
    val overline = TextStyle(fontFamily = Mono, fontSize = 12.sp, lineHeight = 16.sp, letterSpacing = 1.2.sp)
    val code = TextStyle(fontFamily = Mono, fontWeight = FontWeight.Medium, fontSize = 12.sp, lineHeight = 16.sp)
    val small = TextStyle(fontFamily = Mono, fontSize = 12.sp, lineHeight = 16.sp)
    val title = TextStyle(fontFamily = Sans, fontWeight = FontWeight.SemiBold, fontSize = 16.sp, lineHeight = 22.sp)
    val body = TextStyle(fontFamily = Sans, fontWeight = FontWeight.Medium, fontSize = 16.sp, lineHeight = 22.sp)
    val sub = TextStyle(fontFamily = Sans, fontSize = 14.sp, lineHeight = 20.sp)
    val caption = TextStyle(fontFamily = Sans, fontSize = 13.sp, lineHeight = 18.sp)
}

@OptIn(ExperimentalMaterial3ExpressiveApi::class)
@Composable
fun UnbraidTheme(content: @Composable () -> Unit) = MaterialExpressiveTheme(
    colorScheme = (if (Ink.light) lightColorScheme() else darkColorScheme()).copy(
        primary = Ink.accent, onPrimary = Ink.onAccent,
        primaryContainer = Ink.accentContainer, onPrimaryContainer = Ink.text,
        secondary = Ink.route(1), tertiary = Ink.route(2),
        background = Ink.ground, onBackground = Ink.text,
        surface = Ink.ground, onSurface = Ink.text,
        surfaceVariant = Ink.surfaceHigh, onSurfaceVariant = Ink.dim,
        surfaceContainerLowest = Ink.ground, surfaceContainerLow = Ink.surface,
        surfaceContainer = Ink.surface, surfaceContainerHigh = Ink.surfaceHigh, surfaceContainerHighest = Ink.surfaceTop,
        secondaryContainer = Ink.accentContainer, onSecondaryContainer = Ink.text,
        outline = Ink.line, outlineVariant = Ink.surfaceTop, error = Ink.bad,
    ),
    motionScheme = MotionScheme.expressive(),
    typography = Typography(
        bodyLarge = Type.body, bodyMedium = Type.sub, bodySmall = Type.caption,
        titleMedium = Type.title, labelLarge = Type.title.copy(fontSize = 15.sp), labelMedium = Type.caption.copy(fontWeight = FontWeight.Medium, fontSize = 12.sp),
        headlineLarge = Type.headline,
    ),
    shapes = Shapes(small = RoundedCornerShape(12.dp), medium = RoundedCornerShape(20.dp), large = RoundedCornerShape(28.dp)),
    content = content,
)
