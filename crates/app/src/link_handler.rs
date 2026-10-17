//! Windows, Linux and the BSDs: `otpauth://` setup links open 2Secret, which
//! adds the one-time password to a login (`code_setup`). macOS and iOS hand
//! such links to the running app themselves.
//!
//! 2Secret registers itself for the links, for this user only: under
//! `HKEY_CURRENT_USER\Software\Classes\otpauth` on Windows, with a desktop
//! entry and `xdg-mime` on Linux and the BSDs. It does so by itself while no
//! other app opens them; *Settings → Security → Setup links* makes 2Secret the
//! app for them.
//!
//! A link starts a new 2Secret process with the link as its argument. When
//! 2Secret already runs, that process hands the link over and quits: it
//! writes the link to a file in the data directory, which only this user can
//! read, and connects to the running app's local socket (a named pipe on
//! Windows), which then reads and removes the file. Nothing goes through the
//! socket, so whoever took its name learns no secret.
//!
//! 2Secret started again without a link does the same without the file: the
//! running app shows its window (also when it is hidden in the system tray),
//! so one 2Secret runs.

use crate::platform;

/// The storage key of a link handed to the running app.
const HANDED_OVER: &str = "opened-link";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Handler {
    /// No app opens the links.
    None,
    /// 2Secret does.
    TwoSecret,
    /// Another app does.
    Other,
}

fn is_link(arg: &str) -> bool {
    arg.get(..10).is_some_and(|s| s.eq_ignore_ascii_case("otpauth://"))
}

/// At start, before the window opens: hand a link from the command line (or
/// just the start) to the 2Secret that already runs and quit, or else receive
/// links from now on.
pub fn start() {
    let link = std::env::args().skip(1).find(|a| is_link(a));
    if hand_over(link.as_deref()) {
        std::process::exit(0);
    }
    os::listen(take_handed_over);
    if let Some(link) = link {
        crate::code_setup::opened([link.as_str()]);
    }
    // Starts programs on Linux (xdg-mime), so not on the way to the window.
    std::thread::spawn(|| {
        if handler() != Handler::Other {
            register();
        }
    });
}

fn hand_over(link: Option<&str>) -> bool {
    if let Some(link) = link {
        if platform::storage().write(HANDED_OVER, link).is_err() {
            return false;
        }
    }
    if os::ring() {
        return true;
    }
    if link.is_some() {
        let _ = platform::storage().delete(HANDED_OVER);
    }
    false
}

/// The running app was rung: show the window, and take the link from the
/// data directory if there is one.
fn take_handed_over() {
    let storage = platform::storage();
    if let Ok(Some(link)) = storage.read(HANDED_OVER) {
        let _ = storage.delete(HANDED_OVER);
        crate::code_setup::opened([link.trim()]);
    }
    crate::tray::request_show();
}

/// Which app opens setup links.
pub fn handler() -> Handler {
    os::handler()
}

/// Make 2Secret the app that opens setup links (again, with the path of this
/// executable).
pub fn register() -> bool {
    os::register()
}

#[cfg(windows)]
mod os {
    use windows::core::HSTRING;
    use windows::Win32::Foundation::{CloseHandle, ERROR_PIPE_CONNECTED, HANDLE};
    use windows::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_INBOUND};
    use windows::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
    };
    use windows::Win32::System::Registry::{
        RegGetValueW, RegSetKeyValueW, HKEY, HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, REG_SZ, RRF_RT_REG_SZ,
    };
    use windows::Win32::UI::WindowsAndMessaging::{AllowSetForegroundWindow, ASFW_ANY};

    use super::Handler;

    /// One pipe per data directory, so per user.
    fn pipe() -> String {
        format!(r"\\.\pipe\2Secret links {}", crate::platform::data_dir().to_string_lossy().replace('\\', "/"))
    }

    pub fn ring() -> bool {
        // This process was started by the user, so it may bring a window to
        // the front: the running 2Secret may too.
        let _ = unsafe { AllowSetForegroundWindow(ASFW_ANY) };
        for _ in 0..10 {
            match std::fs::OpenOptions::new().write(true).open(pipe()) {
                Ok(_) => return true,
                // ERROR_PIPE_BUSY: the app is between two links.
                Err(e) if e.raw_os_error() == Some(231) => std::thread::sleep(std::time::Duration::from_millis(50)),
                Err(_) => return false,
            }
        }
        false
    }

    pub fn listen(on_ring: fn()) {
        let pipe = unsafe {
            CreateNamedPipeW(
                &HSTRING::from(pipe()),
                PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                0,
                0,
                0,
                None,
            )
        };
        // Another 2Secret window listens already.
        if pipe.is_invalid() {
            return;
        }
        // A handle is a pointer, which threads may not share.
        let raw = pipe.0 as usize;
        std::thread::spawn(move || {
            let pipe = HANDLE(raw as *mut _);
            loop {
                match unsafe { ConnectNamedPipe(pipe, None) } {
                    Ok(()) => {}
                    // It connected before we waited.
                    Err(e) if e.code() == ERROR_PIPE_CONNECTED.to_hresult() => {}
                    Err(_) => break,
                }
                on_ring();
                let _ = unsafe { DisconnectNamedPipe(pipe) };
            }
            let _ = unsafe { CloseHandle(pipe) };
        });
    }

    const KEY: &str = r"Software\Classes\otpauth";

    /// A text value of a registry key ("" is its default value).
    fn read(root: HKEY, key: &str, name: &str) -> Option<String> {
        let (key, name) = (HSTRING::from(key), HSTRING::from(name));
        let mut size = 0u32;
        unsafe { RegGetValueW(root, &key, &name, RRF_RT_REG_SZ, None, None, Some(&mut size)) }.ok().ok()?;
        let mut buffer = vec![0u16; size as usize / 2 + 1];
        unsafe {
            RegGetValueW(root, &key, &name, RRF_RT_REG_SZ, None, Some(buffer.as_mut_ptr().cast()), Some(&mut size))
        }
        .ok()
        .ok()?;
        let text = String::from_utf16_lossy(&buffer[..size as usize / 2]);
        Some(text.trim_end_matches('\0').to_string())
    }

    fn write(key: &str, name: &str, value: &str) -> bool {
        let data: Vec<u16> = value.encode_utf16().chain([0]).collect();
        let (key, name) = (HSTRING::from(format!(r"{KEY}{key}")), HSTRING::from(name));
        unsafe {
            RegSetKeyValueW(
                HKEY_CURRENT_USER,
                &key,
                &name,
                REG_SZ.0,
                Some(data.as_ptr().cast()),
                (data.len() * 2) as u32,
            )
        }
        .is_ok()
    }

    fn exe() -> Option<String> {
        Some(std::env::current_exe().ok()?.to_string_lossy().into_owned())
    }

    pub fn handler() -> Handler {
        // HKEY_CLASSES_ROOT: this user's classes, else the machine's.
        let Some(command) = read(HKEY_CLASSES_ROOT, r"otpauth\shell\open\command", "") else { return Handler::None };
        let name = std::env::current_exe().ok().and_then(|e| Some(e.file_name()?.to_string_lossy().to_lowercase()));
        if name.is_some_and(|n| command.to_lowercase().contains(&n)) {
            Handler::TwoSecret
        } else {
            Handler::Other
        }
    }

    pub fn register() -> bool {
        let Some(exe) = exe() else { return false };
        write("", "", "URL:otpauth")
            && write("", "URL Protocol", "")
            && write(r"\DefaultIcon", "", &format!("\"{exe}\",0"))
            && write(r"\shell\open\command", "", &format!("\"{exe}\" \"%1\""))
    }
}

#[cfg(unix)]
mod os {
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::PathBuf;
    use std::process::{Command, Stdio};

    use super::Handler;

    fn socket() -> PathBuf {
        crate::platform::data_dir().join("links.sock")
    }

    pub fn ring() -> bool {
        UnixStream::connect(socket()).is_ok()
    }

    pub fn listen(on_ring: fn()) {
        // Creates the data directory, readable only by this user.
        let _ = crate::platform::storage();
        let path = socket();
        let listener = match UnixListener::bind(&path) {
            Ok(listener) => listener,
            // Left behind by a 2Secret that quit (else one listens already).
            Err(_) if !ring() => {
                let _ = std::fs::remove_file(&path);
                match UnixListener::bind(&path) {
                    Ok(listener) => listener,
                    Err(_) => return,
                }
            }
            Err(_) => return,
        };
        std::thread::spawn(move || {
            for connection in listener.incoming() {
                drop(connection);
                on_ring();
            }
        });
    }

    const DESKTOP: &str = "2secret-links.desktop";
    const SCHEME: &str = "x-scheme-handler/otpauth";

    fn applications() -> Option<PathBuf> {
        let data = std::env::var_os("XDG_DATA_HOME")
            .filter(|d| !d.is_empty())
            .map(PathBuf::from)
            .or_else(|| Some(PathBuf::from(std::env::var_os("HOME")?).join(".local").join("share")))?;
        Some(data.join("applications"))
    }

    /// The program to start: the AppImage itself, not the copy it runs from.
    fn exe() -> Option<PathBuf> {
        std::env::var_os("APPIMAGE").map(PathBuf::from).filter(|p| p.is_file()).or_else(|| std::env::current_exe().ok())
    }

    /// A hidden desktop entry that opens setup links with this program.
    fn entry() -> Option<String> {
        let exe = exe()?.to_string_lossy().replace('%', "%%");
        // Paths that would need escaping in an Exec line are not worth it.
        if exe.contains(['"', '`', '$', '\\', '\n']) {
            return None;
        }
        // Quoted only when needed: xdg-open without a desktop environment
        // does not understand quotes.
        let exe = if exe.contains(|c| " \t'><~|&;*?#()".contains(c)) { format!("\"{exe}\"") } else { exe };
        Some(format!(
            "[Desktop Entry]\nType=Application\nName=2Secret\nComment=Set up one-time passwords\n\
             Exec={exe} %u\nTerminal=false\nNoDisplay=true\nMimeType={SCHEME};\n"
        ))
    }

    fn xdg_mime(args: &[&str]) -> Option<String> {
        let output = Command::new("xdg-mime").args(args).stderr(Stdio::null()).output().ok()?;
        output.status.success().then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    pub fn handler() -> Handler {
        match xdg_mime(&["query", "default", SCHEME]) {
            Some(app) if app == DESKTOP => Handler::TwoSecret,
            Some(app) if !app.is_empty() => Handler::Other,
            _ => Handler::None,
        }
    }

    pub fn register() -> bool {
        let (Some(dir), Some(entry)) = (applications(), entry()) else { return false };
        let path = dir.join(DESKTOP);
        if std::fs::read_to_string(&path).ok().as_deref() != Some(entry.as_str())
            && std::fs::create_dir_all(&dir).and_then(|_| std::fs::write(&path, &entry)).is_err()
        {
            return false;
        }
        let _ = Command::new("update-desktop-database").arg(&dir).stdout(Stdio::null()).stderr(Stdio::null()).status();
        xdg_mime(&["default", DESKTOP, SCHEME]).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_on_the_command_line() {
        assert!(is_link("otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXP"));
        assert!(is_link("OTPAUTH://totp/x"));
        assert!(!is_link("--help"));
        assert!(!is_link("otpauth:"));
        assert!(!is_link("ötpauth://x"));
    }
}
