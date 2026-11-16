//! The iOS app's native view around the page: the area under the status bar
//! and the Dynamic Island, and the light or dark status bar.

use dioxus::mobile::tao::platform::ios::WindowExtIOS;
use dioxus::mobile::wry::WebViewExtIOS;
use objc2::rc::Retained;
use objc2::runtime::AnyObject;
use objc2::{msg_send, sel};

/// iOS 26 blurs and tints the edges of a scroll view under the status bar and
/// the home indicator. The page itself never scrolls (its panes do), and
/// style.css fades the content under the status bar and the Dynamic Island
/// itself, so the webview's own effect would only lay a band over it.
pub fn hide_scroll_edges() {
    let webview = dioxus::mobile::window().webview.webview();
    unsafe {
        let scroll: Option<Retained<AnyObject>> = msg_send![&*webview, scrollView];
        let Some(scroll) = scroll else { return };
        // UIScrollEdgeEffect, iOS 26 and later.
        let edges: bool = msg_send![&*scroll, respondsToSelector: sel!(topEdgeEffect)];
        if !edges {
            return;
        }
        let top: Option<Retained<AnyObject>> = msg_send![&*scroll, topEdgeEffect];
        let bottom: Option<Retained<AnyObject>> = msg_send![&*scroll, bottomEdgeEffect];
        let left: Option<Retained<AnyObject>> = msg_send![&*scroll, leftEdgeEffect];
        let right: Option<Retained<AnyObject>> = msg_send![&*scroll, rightEdgeEffect];
        for effect in [top, bottom, left, right].into_iter().flatten() {
            let _: () = msg_send![&*effect, setHidden: true];
        }
    }
}

/// iOS ends the process that draws a WKWebView when it needs the memory,
/// mostly while the app is in the background, and the webview stays empty
/// (black or white, the page's background) until the app restarts: Dioxus
/// 0.7 sets no handler for it in wry, and a reloaded page would not get the
/// templates Dioxus already sent. So 2Secret ends too, quietly, and the next
/// time it opens it starts as after a restart, on the lock screen. iOS often
/// tells only when the app comes back, so it may close once as it opens.
pub fn restart_when_web_content_ends() {
    let webview = dioxus::mobile::window().webview.webview();
    unsafe {
        let delegate: *mut AnyObject = msg_send![&*webview, navigationDelegate];
        if delegate.is_null() {
            return;
        }
        // wry's own navigation delegate, which answers this selector with a
        // handler Dioxus leaves unset.
        let class = objc2::ffi::object_getClass(delegate) as *mut objc2::runtime::AnyClass;
        if class.is_null() {
            return;
        }
        let imp = std::mem::transmute::<DidTerminate, objc2::runtime::Imp>(web_content_ended);
        objc2::ffi::class_replaceMethod(class, sel!(webViewWebContentProcessDidTerminate:), imp, c"v@:@".as_ptr());
    }
}

/// `webViewWebContentProcessDidTerminate:`: self, the selector, the webview.
type DidTerminate = unsafe extern "C-unwind" fn(*mut AnyObject, objc2::runtime::Sel, *mut AnyObject);

unsafe extern "C-unwind" fn web_content_ended(_: *mut AnyObject, _: objc2::runtime::Sel, _: *mut AnyObject) {
    eprintln!("2Secret: iOS ended the web content process; restarting on the next launch");
    std::process::exit(0);
}

/// The status bar text, the keyboard and the system's dialogs light or dark
/// like the app's theme (Settings → Appearance), also when the phone's own
/// setting differs, so the status bar stays readable on the app's colours.
pub fn follow_theme(theme: &str) {
    // UIUserInterfaceStyle: unspecified (follow the phone), light, dark.
    let style: isize = match theme {
        "light" => 1,
        "dark" => 2,
        _ => 0,
    };
    let window = dioxus::mobile::window().window.ui_window() as *mut AnyObject;
    if !window.is_null() {
        unsafe {
            let _: () = msg_send![window, setOverrideUserInterfaceStyle: style];
        }
    }
}

/// Whether the app is in front and active: not still starting or coming
/// back, when iOS does not let it show the Face ID or Touch ID prompt.
pub fn app_active() -> bool {
    let Some(class) = objc2::runtime::AnyClass::get(c"UIApplication") else { return true };
    unsafe {
        let app: *mut AnyObject = msg_send![class, sharedApplication];
        if app.is_null() {
            return true;
        }
        // UIApplicationStateActive
        let state: isize = msg_send![app, applicationState];
        state == 0
    }
}
