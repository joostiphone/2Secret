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
