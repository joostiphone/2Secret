//! Desktop: set up a one-time password from a QR code on the screen, as
//! websites show them for two-step verification. 2Secret hides its window,
//! takes a screenshot of every screen, and looks for a QR code with an
//! `otpauth://` link in it. The screenshot stays in memory and is dropped
//! right away.
//!
//! macOS: `screencapture`, after the system asks for permission to record the
//! screen. Windows: GDI. Linux: GDK under X11, the screenshot portal
//! (`org.freedesktop.portal.Screenshot`) under Wayland, which may ask for
//! permission too. Not on the BSDs.

use image::GrayImage;

pub enum Problem {
    /// No QR code with a one-time password.
    NotFound,
    /// A QR code, but not for a one-time password.
    OtherCode,
    /// macOS: 2Secret may not record the screen yet.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    Permission,
    /// The screenshot failed.
    Capture(String),
}

/// Hide the window, read the screens, and show the window again. Returns the
/// `otpauth://` link.
pub async fn scan() -> Result<String, Problem> {
    #[cfg(target_os = "macos")]
    if !os::allowed() {
        return Err(Problem::Permission);
    }
    let window = dioxus::desktop::window();
    window.set_visible(false);
    // Until the window is gone from the screen.
    crate::platform::sleep_ms(400).await;
    let screens = capture().await;
    window.set_visible(true);
    window.set_focus();
    let screens = screens.map_err(Problem::Capture)?;
    crate::platform::run_heavy(move || find(&screens)).await
}

#[cfg(target_os = "linux")]
async fn capture() -> Result<Vec<GrayImage>, String> {
    // GDK only on the main thread.
    if let Some(screen) = os::x11() {
        return Ok(vec![screen]);
    }
    crate::platform::run_heavy(os::portal).await
}

#[cfg(any(target_os = "macos", windows))]
async fn capture() -> Result<Vec<GrayImage>, String> {
    crate::platform::run_heavy(os::capture).await
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
async fn capture() -> Result<Vec<GrayImage>, String> {
    Err("screenshots are not supported here".into())
}

/// The first `otpauth://` link in a QR code on the screens.
fn find(screens: &[GrayImage]) -> Result<String, Problem> {
    let mut other = false;
    for screen in screens {
        let mut prepared = rqrr::PreparedImage::prepare(screen.clone());
        for grid in prepared.detect_grids() {
            let Ok((_, content)) = grid.decode() else { continue };
            let content = content.trim();
            if content.get(..10).is_some_and(|s| s.eq_ignore_ascii_case("otpauth://")) {
                return Ok(content.to_string());
            }
            other = true;
        }
    }
    Err(if other { Problem::OtherCode } else { Problem::NotFound })
}

#[cfg(target_os = "macos")]
mod os {
    use image::GrayImage;

    #[link(name = "CoreGraphics", kind = "framework")]
    extern "C" {
        fn CGPreflightScreenCaptureAccess() -> bool;
        fn CGRequestScreenCaptureAccess() -> bool;
        fn CGGetActiveDisplayList(max: u32, displays: *mut u32, count: *mut u32) -> i32;
    }

    /// Whether 2Secret may record the screen; asks the first time.
    pub fn allowed() -> bool {
        unsafe { CGPreflightScreenCaptureAccess() || CGRequestScreenCaptureAccess() }
    }

    pub fn capture() -> Result<Vec<GrayImage>, String> {
        let dir = std::env::temp_dir().join(format!("2secret-qr-{}", twosecret_core::util::new_id()));
        std::fs::create_dir(&dir).map_err(|e| e.to_string())?;
        // One file per screen.
        let mut screens = 0u32;
        unsafe { CGGetActiveDisplayList(0, std::ptr::null_mut(), &mut screens) };
        let files: Vec<_> = (1..=screens.clamp(1, 16)).map(|n| dir.join(format!("{n}.png"))).collect();
        let status = std::process::Command::new("/usr/sbin/screencapture").arg("-x").args(&files).status();
        let screens = files.iter().filter_map(|f| image::open(f).ok()).map(|i| i.to_luma8()).collect::<Vec<_>>();
        let _ = std::fs::remove_dir_all(&dir);
        match status {
            Ok(s) if s.success() && !screens.is_empty() => Ok(screens),
            Ok(_) => Err("screencapture failed".into()),
            Err(e) => Err(e.to_string()),
        }
    }
}

#[cfg(windows)]
mod os {
    use image::GrayImage;
    use windows::Win32::Graphics::Gdi::{
        BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC, DeleteObject, GetDC, GetDIBits, ReleaseDC,
        SelectObject, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS, SRCCOPY,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
    };

    /// All screens as one image.
    pub fn capture() -> Result<Vec<GrayImage>, String> {
        unsafe {
            let (x, y) = (GetSystemMetrics(SM_XVIRTUALSCREEN), GetSystemMetrics(SM_YVIRTUALSCREEN));
            let (width, height) = (GetSystemMetrics(SM_CXVIRTUALSCREEN), GetSystemMetrics(SM_CYVIRTUALSCREEN));
            if width <= 0 || height <= 0 {
                return Err("no screen".into());
            }
            let screen = GetDC(None);
            let memory = CreateCompatibleDC(Some(screen));
            let bitmap = CreateCompatibleBitmap(screen, width, height);
            let previous = SelectObject(memory, bitmap.into());
            let copied = BitBlt(memory, 0, 0, width, height, Some(screen), x, y, SRCCOPY);
            let mut info = BITMAPINFO {
                bmiHeader: BITMAPINFOHEADER {
                    biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                    biWidth: width,
                    // Top-down rows.
                    biHeight: -height,
                    biPlanes: 1,
                    biBitCount: 32,
                    biCompression: BI_RGB.0,
                    ..Default::default()
                },
                ..Default::default()
            };
            let mut pixels = vec![0u8; width as usize * height as usize * 4];
            let lines = GetDIBits(
                memory,
                bitmap,
                0,
                height as u32,
                Some(pixels.as_mut_ptr().cast()),
                &mut info,
                DIB_RGB_COLORS,
            );
            SelectObject(memory, previous);
            let _ = DeleteObject(bitmap.into());
            let _ = DeleteDC(memory);
            ReleaseDC(None, screen);
            copied.map_err(|e| e.to_string())?;
            if lines == 0 {
                return Err("GetDIBits failed".into());
            }
            // Blue, green, red, unused.
            let gray = pixels
                .chunks_exact(4)
                .map(|p| ((p[2] as u32 * 299 + p[1] as u32 * 587 + p[0] as u32 * 114) / 1000) as u8)
                .collect();
            GrayImage::from_raw(width as u32, height as u32, gray).map(|i| vec![i]).ok_or_else(|| "bad image".into())
        }
    }
}

#[cfg(target_os = "linux")]
mod os {
    use std::cell::RefCell;
    use std::rc::Rc;

    use gio::glib;
    use gio::prelude::*;
    use image::GrayImage;

    /// X11: the root window holds every screen.
    pub fn x11() -> Option<GrayImage> {
        use gdk::prelude::*;
        let display = gdk::Display::default()?;
        if display.type_().name() != "GdkX11Display" {
            return None;
        }
        let root = gdk::Window::default_root_window();
        let pixbuf = root.pixbuf(0, 0, root.width(), root.height())?;
        let (width, height) = (pixbuf.width() as usize, pixbuf.height() as usize);
        let (channels, stride) = (pixbuf.n_channels() as usize, pixbuf.rowstride() as usize);
        let bytes = pixbuf.read_pixel_bytes();
        let mut gray = Vec::with_capacity(width * height);
        for row in 0..height {
            for col in 0..width {
                let p = &bytes[row * stride + col * channels..];
                gray.push(((p[0] as u32 * 299 + p[1] as u32 * 587 + p[2] as u32 * 114) / 1000) as u8);
            }
        }
        GrayImage::from_raw(width as u32, height as u32, gray)
    }

    /// Wayland: ask the desktop for a screenshot (it may ask the user). It
    /// answers with a signal, so this runs its own main loop.
    pub fn portal() -> Result<Vec<GrayImage>, String> {
        let context = glib::MainContext::new();
        context
            .with_thread_default(|| {
                let bus =
                    gio::bus_get_sync(gio::BusType::Session, gio::Cancellable::NONE).map_err(|e| e.to_string())?;
                let sender = bus.unique_name().ok_or("no D-Bus name")?;
                let token = format!("twosecret{}", &twosecret_core::util::new_id()[..8]);
                let request = format!(
                    "/org/freedesktop/portal/desktop/request/{}/{token}",
                    sender.trim_start_matches(':').replace('.', "_")
                );
                let main_loop = glib::MainLoop::new(Some(&context), false);
                let answer = Rc::new(RefCell::new(None::<glib::Variant>));
                let subscription = {
                    let (answer, main_loop) = (answer.clone(), main_loop.clone());
                    #[allow(deprecated)]
                    bus.signal_subscribe(
                        Some("org.freedesktop.portal.Desktop"),
                        Some("org.freedesktop.portal.Request"),
                        Some("Response"),
                        Some(&request),
                        None,
                        gio::DBusSignalFlags::NONE,
                        move |_, _, _, _, _, parameters| {
                            *answer.borrow_mut() = Some(parameters.clone());
                            main_loop.quit();
                        },
                    )
                };
                let options = glib::VariantDict::new(None);
                options.insert("handle_token", &token);
                options.insert("interactive", false);
                let called = bus.call_sync(
                    Some("org.freedesktop.portal.Desktop"),
                    "/org/freedesktop/portal/desktop",
                    "org.freedesktop.portal.Screenshot",
                    "Screenshot",
                    // (sa{sv}): a tuple would wrap the options in a variant.
                    Some(&glib::Variant::tuple_from_iter(["".to_variant(), options.end()])),
                    None,
                    gio::DBusCallFlags::NONE,
                    10_000,
                    gio::Cancellable::NONE,
                );
                if called.is_ok() {
                    // Time to answer a permission question.
                    let quit = main_loop.clone();
                    let timeout = glib::timeout_source_new(
                        std::time::Duration::from_secs(120),
                        None,
                        glib::Priority::DEFAULT,
                        move || {
                            quit.quit();
                            glib::ControlFlow::Break
                        },
                    );
                    timeout.attach(Some(&context));
                    main_loop.run();
                    timeout.destroy();
                }
                #[allow(deprecated)]
                bus.signal_unsubscribe(subscription);
                called.map_err(|e| e.to_string())?;
                let answer = answer.borrow_mut().take().ok_or("no screenshot")?;
                let (response, results) = answer
                    .get::<(u32, std::collections::HashMap<String, glib::Variant>)>()
                    .ok_or("unexpected answer")?;
                if response != 0 {
                    return Err("no screenshot".to_string());
                }
                let uri = results.get("uri").and_then(|u| u.get::<String>()).ok_or("no screenshot")?;
                let path = gio::File::for_uri(&uri).path().ok_or("no screenshot file")?;
                let screen = image::open(&path).map(|i| i.to_luma8()).map_err(|e| e.to_string());
                // The portal saved it for us: it goes now.
                let _ = std::fs::remove_file(&path);
                screen.map(|s| vec![s])
            })
            .map_err(|e| e.to_string())?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_a_setup_code() {
        let link = "otpauth://totp/GitHub:octo?secret=JBSWY3DPEHPK3PXP&issuer=GitHub";
        let code = qrcode_image(link);
        assert_eq!(find(&[code]).ok().as_deref(), Some(link));
        assert!(matches!(find(&[qrcode_image("https://example.com")]), Err(Problem::OtherCode)));
        assert!(matches!(find(&[GrayImage::from_pixel(200, 200, image::Luma([255]))]), Err(Problem::NotFound)));
    }

    /// A QR code on a white screen, as a screenshot would hold it.
    fn qrcode_image(text: &str) -> GrayImage {
        let code = qrcode::QrCode::new(text.as_bytes()).unwrap();
        let modules = code.render::<image::Luma<u8>>().module_dimensions(6, 6).build();
        let mut screen = GrayImage::from_pixel(modules.width() + 400, modules.height() + 300, image::Luma([255]));
        image::imageops::overlay(&mut screen, &modules, 200, 150);
        screen
    }
}
