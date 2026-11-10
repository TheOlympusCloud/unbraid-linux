package app.unbraid.ui

import androidx.compose.runtime.Composable
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import java.awt.image.BufferedImage
import java.io.File
import javax.imageio.ImageIO

/** A QR code from a picture the user picks; [onPicked] gets the file, or null. The desktop has no camera app to take one. */
class QrScan(val picture: () -> Unit)

@Composable
fun rememberQrScan(onPicked: (File?) -> Unit) = QrScan(rememberFilePicker("Choose a picture of the QR code", images = true, onPicked = onPicked))

/** The first QR code in the picture, read at up to about 2000 pixels a side (a photo is often far larger); blocks. */
fun decodeQr(file: File): String? = try { decode(file) } catch (e: Exception) { null }

private fun decode(file: File): String? {
    val full = ImageIO.read(file) ?: return null
    var sample = 1
    while (maxOf(full.width, full.height) / sample > 2000) sample *= 2
    val img = if (sample == 1) full else BufferedImage(full.width / sample, full.height / sample, BufferedImage.TYPE_INT_RGB).also {
        it.createGraphics().apply { drawImage(full, 0, 0, it.width, it.height, null); dispose() }
    }
    val source = RGBLuminanceSource(img.width, img.height, img.getRGB(0, 0, img.width, img.height, null, 0, img.width))
    val hints = mapOf(DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE), DecodeHintType.TRY_HARDER to true)
    return runCatching { MultiFormatReader().decode(BinaryBitmap(HybridBinarizer(source)), hints).text }
        .recoverCatching { MultiFormatReader().decode(BinaryBitmap(HybridBinarizer(source.invert())), hints).text }.getOrNull()
}
