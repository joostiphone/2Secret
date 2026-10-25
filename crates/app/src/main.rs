// The app itself lives in the library (src/lib.rs).
// No console window on Windows: 2Secret is a window app, and the browser
// extension's native messaging host (the same program) would otherwise flash
// a console every time a browser starts it. Its pipes keep working.
#![cfg_attr(windows, windows_subsystem = "windows")]
fn main() {
    twosecret_app::run();
}
