//! The first start's introduction film, played through the desktop's own GStreamer. It is loaded only for this, so the
//! app needs none: without it, or without a decoder for the film, [`play`] fails at once and the app simply opens.
//! Frames come out as RGBA pictures at the film's pace; its sound, if it has any, goes to the desktop's output.

use slint::{Rgba8Pixel, SharedPixelBuffer};
use std::ffi::{CStr, CString, c_char, c_int, c_uint, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

type Ptr = *mut c_void;

const STATE_NULL: c_int = 1;
const STATE_PLAYING: c_int = 4;
const STATE_CHANGE_FAILURE: c_int = 0;
const MESSAGE_ERROR: c_uint = 1 << 1;
const MAP_READ: c_int = 1;
/// The first picture may wait for GStreamer to look over its plug-ins; the next ones come at the film's pace.
const FIRST: Duration = Duration::from_secs(5);
const STALL: Duration = Duration::from_secs(2);
/// Pictures as the window takes them: RGBA, square pixels, never more than two waiting.
const VIDEO: &CStr = c"videoconvert ! videoscale ! video/x-raw,format=RGBA,pixel-aspect-ratio=1/1 ! appsink name=frames sync=true max-buffers=2 drop=true";

/// The GStreamer calls the film needs, from the desktop's libraries.
pub struct Gst {
    init_check: unsafe extern "C" fn(*mut c_int, Ptr, *mut Ptr) -> c_int,
    factory_make: unsafe extern "C" fn(*const c_char, *const c_char) -> Ptr,
    factory_find: unsafe extern "C" fn(*const c_char) -> Ptr,
    parse_bin: unsafe extern "C" fn(*const c_char, c_int, *mut Ptr) -> Ptr,
    bin_get_by_name: unsafe extern "C" fn(Ptr, *const c_char) -> Ptr,
    ref_sink: unsafe extern "C" fn(Ptr) -> Ptr,
    unref: unsafe extern "C" fn(Ptr),
    set_state: unsafe extern "C" fn(Ptr, c_int) -> c_int,
    filename_to_uri: unsafe extern "C" fn(*const c_char, *mut Ptr) -> *mut c_char,
    get_bus: unsafe extern "C" fn(Ptr) -> Ptr,
    bus_pop_filtered: unsafe extern "C" fn(Ptr, c_uint) -> Ptr,
    sample_get_buffer: unsafe extern "C" fn(Ptr) -> Ptr,
    sample_get_caps: unsafe extern "C" fn(Ptr) -> Ptr,
    caps_get_structure: unsafe extern "C" fn(Ptr, c_uint) -> Ptr,
    structure_get_int: unsafe extern "C" fn(Ptr, *const c_char, *mut c_int) -> c_int,
    buffer_map: unsafe extern "C" fn(Ptr, *mut MapInfo, c_int) -> c_int,
    buffer_unmap: unsafe extern "C" fn(Ptr, *mut MapInfo),
    mini_object_unref: unsafe extern "C" fn(Ptr),
    try_pull_sample: unsafe extern "C" fn(Ptr, u64) -> Ptr,
    is_eos: unsafe extern "C" fn(Ptr) -> c_int,
    object_set: unsafe extern "C" fn(Ptr, *const c_char, ...),
    free: unsafe extern "C" fn(Ptr),
}

/// GstMapInfo, as GStreamer 1.x lays it out; only the mapped bytes are read here.
#[repr(C)]
struct MapInfo {
    _memory: Ptr,
    _flags: c_int,
    data: *mut u8,
    size: usize,
    _maxsize: usize,
    _user_data: [Ptr; 4],
    _reserved: [Ptr; 4],
}

/// `name` from the library `lib`, as the C function type `F`.
unsafe fn sym<F: Copy>(lib: Ptr, name: &CStr) -> Option<F> {
    assert_eq!(size_of::<F>(), size_of::<Ptr>());
    let f = unsafe { libc::dlsym(lib, name.as_ptr()) };
    (!f.is_null()).then(|| unsafe { std::mem::transmute_copy::<Ptr, F>(&f) })
}

impl Gst {
    /// The desktop's GStreamer, if it has one. Its libraries stay loaded.
    pub fn load() -> Option<Gst> {
        let open = |name: &CStr| {
            let lib = unsafe { libc::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
            (!lib.is_null()).then_some(lib)
        };
        let (gst, app) = (open(c"libgstreamer-1.0.so.0")?, open(c"libgstapp-1.0.so.0")?);
        let (gobject, glib) = (open(c"libgobject-2.0.so.0")?, open(c"libglib-2.0.so.0")?);
        // SAFETY: each type is the C signature GStreamer 1.x and GLib 2 document for that name.
        unsafe {
            Some(Gst {
                init_check: sym(gst, c"gst_init_check")?,
                factory_make: sym(gst, c"gst_element_factory_make")?,
                factory_find: sym(gst, c"gst_element_factory_find")?,
                parse_bin: sym(gst, c"gst_parse_bin_from_description")?,
                bin_get_by_name: sym(gst, c"gst_bin_get_by_name")?,
                ref_sink: sym(gst, c"gst_object_ref_sink")?,
                unref: sym(gst, c"gst_object_unref")?,
                set_state: sym(gst, c"gst_element_set_state")?,
                filename_to_uri: sym(gst, c"gst_filename_to_uri")?,
                get_bus: sym(gst, c"gst_element_get_bus")?,
                bus_pop_filtered: sym(gst, c"gst_bus_pop_filtered")?,
                sample_get_buffer: sym(gst, c"gst_sample_get_buffer")?,
                sample_get_caps: sym(gst, c"gst_sample_get_caps")?,
                caps_get_structure: sym(gst, c"gst_caps_get_structure")?,
                structure_get_int: sym(gst, c"gst_structure_get_int")?,
                buffer_map: sym(gst, c"gst_buffer_map")?,
                buffer_unmap: sym(gst, c"gst_buffer_unmap")?,
                mini_object_unref: sym(gst, c"gst_mini_object_unref")?,
                try_pull_sample: sym(app, c"gst_app_sink_try_pull_sample")?,
                is_eos: sym(app, c"gst_app_sink_is_eos")?,
                object_set: sym(gobject, c"g_object_set")?,
                free: sym(glib, c"g_free")?,
            })
        }
    }

    /// GStreamer starts and has what the film needs: WebM, and a VP9 decoder (gst-plugins-good's, or libav's).
    pub fn can_play(&self) -> bool {
        // SAFETY: GStreamer's calls as documented; each factory found is let go.
        let has = |name: &CStr| unsafe {
            let f = (self.factory_find)(name.as_ptr());
            if !f.is_null() {
                (self.unref)(f);
            }
            !f.is_null()
        };
        let started = unsafe { (self.init_check)(null_mut(), null_mut(), null_mut()) } != 0;
        started && has(c"matroskademux") && (has(c"vp9dec") || has(c"avdec_vp9"))
    }
}

/// The first start's introduction plays when it is `due` (a new install's, not yet seen), the window is `shown` at
/// start, the desktop's `animations` are on and the `film` is there; then `player` is asked for last, as it starts
/// GStreamer. None when it doesn't play now.
pub fn gate<G>(due: bool, shown: bool, animations: bool, film: bool, player: impl FnOnce() -> Option<G>) -> Option<G> {
    (due && shown && animations && film).then(player).flatten()
}

/// Plays the film at `path` until it ends, `stop` is set or it can't go on, handing each picture to `frame` as it is
/// due. An error says why it didn't play to its end, for the log.
pub fn play(
    g: &Gst,
    path: &Path,
    stop: &AtomicBool,
    mut frame: impl FnMut(SharedPixelBuffer<Rgba8Pixel>),
) -> Result<(), &'static str> {
    let file = CString::new(path.as_os_str().as_bytes()).map_err(|_| "a path GStreamer can't take")?;
    // SAFETY: GStreamer's calls as documented; every object taken here is let go before returning.
    unsafe {
        if (g.init_check)(null_mut(), null_mut(), null_mut()) == 0 {
            return Err("GStreamer didn't start");
        }
        let playbin = (g.factory_make)(c"playbin".as_ptr(), null());
        if playbin.is_null() {
            return Err("GStreamer has no playbin");
        }
        (g.ref_sink)(playbin);
        let video = (g.parse_bin)(VIDEO.as_ptr(), 1, null_mut());
        if video.is_null() {
            (g.unref)(playbin);
            return Err("GStreamer can't convert pictures");
        }
        (g.ref_sink)(video);
        let sink = (g.bin_get_by_name)(video, c"frames".as_ptr());
        let uri = (g.filename_to_uri)(file.as_ptr(), null_mut());
        let bus = (g.get_bus)(playbin);
        let played = if sink.is_null() || uri.is_null() || bus.is_null() {
            Err("GStreamer didn't set the film up")
        } else {
            (g.object_set)(playbin, c"uri".as_ptr(), uri, null::<c_void>());
            (g.object_set)(playbin, c"video-sink".as_ptr(), video, null::<c_void>());
            if (g.set_state)(playbin, STATE_PLAYING) == STATE_CHANGE_FAILURE {
                Err("GStreamer couldn't start the film")
            } else {
                frames(g, sink, bus, stop, &mut frame)
            }
        };
        (g.set_state)(playbin, STATE_NULL);
        for object in [bus, sink, video, playbin] {
            if !object.is_null() {
                (g.unref)(object);
            }
        }
        if !uri.is_null() {
            (g.free)(uri.cast());
        }
        played
    }
}

/// Pictures from `sink` until the film ends or `stop` is set (Ok), or it fails or stalls.
unsafe fn frames(
    g: &Gst,
    sink: Ptr,
    bus: Ptr,
    stop: &AtomicBool,
    frame: &mut impl FnMut(SharedPixelBuffer<Rgba8Pixel>),
) -> Result<(), &'static str> {
    let (mut last, mut started) = (Instant::now(), false);
    while !stop.load(Ordering::SeqCst) {
        let sample = unsafe { (g.try_pull_sample)(sink, 100_000_000) };
        if sample.is_null() {
            if unsafe { (g.is_eos)(sink) } != 0 {
                return Ok(());
            }
            let error = unsafe { (g.bus_pop_filtered)(bus, MESSAGE_ERROR) };
            if !error.is_null() {
                unsafe { (g.mini_object_unref)(error) };
                return Err("GStreamer couldn't play the film (a decoder missing?)");
            }
            if last.elapsed() > if started { STALL } else { FIRST } {
                return Err("no picture came");
            }
            continue;
        }
        let picture = unsafe { picture(g, sample) };
        unsafe { (g.mini_object_unref)(sample) };
        if let Some(p) = picture {
            frame(p);
            (last, started) = (Instant::now(), true);
        }
    }
    Ok(())
}

/// The sample's RGBA picture: rows of exactly width × 4 bytes, as GStreamer lays RGBA out.
unsafe fn picture(g: &Gst, sample: Ptr) -> Option<SharedPixelBuffer<Rgba8Pixel>> {
    let caps = unsafe { (g.sample_get_caps)(sample) };
    let s = if caps.is_null() { null_mut() } else { unsafe { (g.caps_get_structure)(caps, 0) } };
    let (mut w, mut h) = (0, 0);
    let sized = !s.is_null()
        && unsafe { (g.structure_get_int)(s, c"width".as_ptr(), &mut w) } != 0
        && unsafe { (g.structure_get_int)(s, c"height".as_ptr(), &mut h) } != 0;
    let buffer = unsafe { (g.sample_get_buffer)(sample) };
    if !sized || w <= 0 || h <= 0 || buffer.is_null() {
        return None;
    }
    // SAFETY: all zeroes is a valid MapInfo (null pointers, no sizes); GStreamer fills it in.
    let mut map: MapInfo = unsafe { std::mem::zeroed() };
    if unsafe { (g.buffer_map)(buffer, &mut map, MAP_READ) } == 0 {
        return None;
    }
    let len = w as usize * h as usize * 4;
    let p = (map.size >= len).then(|| {
        let mut p = SharedPixelBuffer::<Rgba8Pixel>::new(w as u32, h as u32);
        // SAFETY: GStreamer mapped `map.size` readable bytes at `map.data`, and `len` is no more.
        p.make_mut_bytes().copy_from_slice(unsafe { std::slice::from_raw_parts(map.data, len) });
        p
    });
    unsafe { (g.buffer_unmap)(buffer, &mut map) };
    p
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// The film plays only when every condition holds, and GStreamer is only asked once they all do: a start that
    /// shows no introduction never loads it.
    #[test]
    fn the_gate_asks_for_the_player_last() {
        let asked = Cell::new(0);
        let player = || {
            asked.set(asked.get() + 1);
            Some(())
        };
        assert_eq!(Some(()), gate(true, true, true, true, player));
        for (due, shown, animations, film) in
            [(false, true, true, true), (true, false, true, true), (true, true, false, true), (true, true, true, false)]
        {
            assert_eq!(None, gate(due, shown, animations, film, player));
        }
        assert_eq!(1, asked.get());
        assert_eq!(None::<()>, gate(true, true, true, true, || None), "no GStreamer that plays it");
    }
}
