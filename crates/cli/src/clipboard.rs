//! Clipboard support with automatic clearing.
//!
//! The secret is handed to a short-lived background copy of `2secret` that
//! owns the clipboard (required on X11/Wayland, where clipboard contents
//! vanish with their owner) and clears it after the timeout if it was not
//! replaced in the meantime.

use anyhow::Result;

#[cfg(feature = "clipboard")]
pub fn copy(text: &str, clear_after_secs: u64) -> Result<()> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let exe = std::env::current_exe()?;
    let mut child = Command::new(exe)
        .arg("clipboard-daemon")
        .arg(clear_after_secs.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("could not start clipboard helper"))?
        .write_all(text.as_bytes())?;
    // Give the helper a moment to take ownership before we exit.
    std::thread::sleep(std::time::Duration::from_millis(150));
    Ok(())
}

#[cfg(feature = "clipboard")]
pub fn daemon(clear_after_secs: u64) -> Result<()> {
    use std::io::Read;
    let mut secret = String::new();
    std::io::stdin().read_to_string(&mut secret)?;
    let mut cb = arboard::Clipboard::new()?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(clear_after_secs);
    #[cfg(all(unix, not(any(target_os = "macos", target_os = "android", target_os = "emscripten"))))]
    {
        use arboard::SetExtLinux;
        // Blocks while we own the clipboard, until the deadline; clipboard
        // managers leave it out of their history.
        cb.set().wait_until(deadline).exclude_from_history().text(secret.clone())?;
    }
    #[cfg(not(all(unix, not(any(target_os = "macos", target_os = "android", target_os = "emscripten")))))]
    {
        let set = cb.set();
        // Not in Windows' clipboard history or cloud clipboard, nor in
        // clipboard managers on macOS.
        #[cfg(windows)]
        let set = arboard::SetExtWindows::exclude_from_cloud(arboard::SetExtWindows::exclude_from_history(set));
        #[cfg(target_os = "macos")]
        let set = arboard::SetExtApple::exclude_from_history(set);
        set.text(secret.clone())?;
        std::thread::sleep(deadline.saturating_duration_since(std::time::Instant::now()));
    }
    if cb.get_text().map(|t| t == secret).unwrap_or(false) {
        let _ = cb.clear();
    }
    zeroize::Zeroize::zeroize(&mut secret);
    Ok(())
}

#[cfg(not(feature = "clipboard"))]
pub fn copy(_text: &str, _clear_after_secs: u64) -> Result<()> {
    anyhow::bail!("this build of 2secret has no clipboard support")
}

#[cfg(not(feature = "clipboard"))]
pub fn daemon(_clear_after_secs: u64) -> Result<()> {
    Ok(())
}
