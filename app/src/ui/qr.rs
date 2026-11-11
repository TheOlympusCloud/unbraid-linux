//! Reading a QR code from a picture the user picks, at sign-in: the desktop has no camera app to take one.

use image::DynamicImage;
use image::imageops::FilterType;
use std::path::Path;

/// The file chooser's title.
pub const PICK_TITLE: &str = "Choose a picture of the QR code";

/// A photo is often far larger than its code needs: it's read at up to about this many pixels a side.
const MAX_SIDE: u32 = 2000;

/// The first QR code in the picture at `path`, or none. Blocks: call it off the window's thread.
pub fn decode(path: &Path) -> Option<String> {
    image::open(path).ok().and_then(|img| decode_image(&img))
}

/// The first QR code in `img`, dark on light or light on dark.
pub fn decode_image(img: &DynamicImage) -> Option<String> {
    let mut sample = 1;
    while img.width().max(img.height()) / sample > MAX_SIDE {
        sample *= 2;
    }
    let grey = if sample == 1 { img.to_luma8() } else { img.resize_exact(img.width() / sample, img.height() / sample, FilterType::Triangle).to_luma8() };
    [false, true].into_iter().find_map(|invert| {
        let mut prepared = rqrr::PreparedImage::prepare_from_greyscale(grey.width() as usize, grey.height() as usize, |x, y| {
            let v = grey.get_pixel(x as u32, y as u32).0[0];
            if invert { 255 - v } else { v }
        });
        prepared.detect_grids().into_iter().find_map(|g| g.decode().ok().map(|(_, text)| text))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ui/qr.png")
    }

    /// The code in a picture, also light on dark, and in a photo larger than it's read at; nothing in a picture
    /// without one, or in a file that isn't a picture.
    #[test]
    fn reads_the_code() {
        assert_eq!(Some("1234567890123456".to_string()), decode(&fixture()));
        let img = image::open(fixture()).unwrap();
        let mut light_on_dark = img.clone();
        light_on_dark.invert();
        assert_eq!(Some("1234567890123456".to_string()), decode_image(&light_on_dark));
        let big = img.resize_exact(2600, 2600, FilterType::Nearest);
        assert_eq!(Some("1234567890123456".to_string()), decode_image(&big));
        assert_eq!(None, decode_image(&DynamicImage::new_luma8(300, 200)));
        assert_eq!(None, decode(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml").as_path()));
    }
}
