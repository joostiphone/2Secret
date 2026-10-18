//! Desktop: start 2Secret when the user logs in (*Settings → Desktop app*).
//! It starts with [`HIDDEN`]: only its icon in the menu bar or system tray,
//! without the window (with the window when there is no icon).
//!
//! macOS: a LaunchAgent in `~/Library/LaunchAgents`. Windows: the user's
//! `Run` key in the registry. Linux and the BSDs: an XDG autostart entry in
//! `~/.config/autostart`.

/// The argument of a start at login.
pub const HIDDEN: &str = "--hidden";

/// Started at login.
pub fn started_hidden() -> bool {
    std::env::args().skip(1).any(|a| a == HIDDEN)
}

/// Whether 2Secret starts at login.
pub fn enabled() -> bool {
    os::enabled()
}

/// Start 2Secret at login, or not. False when that failed.
pub fn set(on: bool) -> bool {
    if on {
        os::enable()
    } else {
        os::disable()
    }
}

/// At start: point the entry at this copy of 2Secret, which may have moved.
pub fn refresh() {
    if os::enabled() {
        os::enable();
    }
}

#[cfg(target_os = "macos")]
mod os {
    use std::path::PathBuf;

    const LABEL: &str = "io.github.joostiphone.twosecret";

    fn plist() -> Option<PathBuf> {
        let home = std::env::var_os("HOME")?;
        Some(PathBuf::from(home).join("Library/LaunchAgents").join(format!("{LABEL}.plist")))
    }

    fn xml(text: &str) -> String {
        text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
    }

    /// `open` starts the app bundle as if it was opened in the Finder; the
    /// executable itself when 2Secret does not run from a bundle.
    fn program() -> Option<Vec<String>> {
        let exe = std::env::current_exe().ok()?;
        let bundle = exe.ancestors().nth(3).filter(|b| b.extension().is_some_and(|e| e == "app"));
        Some(match bundle {
            Some(bundle) => vec![
                "/usr/bin/open".into(),
                "-a".into(),
                bundle.to_string_lossy().into_owned(),
                "--args".into(),
                super::HIDDEN.into(),
            ],
            None => vec![exe.to_string_lossy().into_owned(), super::HIDDEN.into()],
        })
    }

    pub fn enabled() -> bool {
        plist().is_some_and(|p| p.is_file())
    }

    pub fn enable() -> bool {
        let (Some(path), Some(program)) = (plist(), program()) else { return false };
        let args: String = program.iter().map(|a| format!("<string>{}</string>", xml(a))).collect();
        let content = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\"><dict>\
             <key>Label</key><string>{LABEL}</string>\
             <key>ProgramArguments</key><array>{args}</array>\
             <key>RunAtLoad</key><true/>\
             <key>ProcessType</key><string>Interactive</string>\
             </dict></plist>\n"
        );
        if std::fs::read_to_string(&path).ok().as_deref() == Some(content.as_str()) {
            return true;
        }
        path.parent().is_some_and(|dir| std::fs::create_dir_all(dir).is_ok()) && std::fs::write(&path, content).is_ok()
    }

    pub fn disable() -> bool {
        plist().is_some_and(|p| !p.exists() || std::fs::remove_file(p).is_ok())
    }
}

#[cfg(windows)]
mod os {
    use windows::core::HSTRING;
    use windows::Win32::Foundation::ERROR_FILE_NOT_FOUND;
    use windows::Win32::System::Registry::{
        RegDeleteKeyValueW, RegGetValueW, RegSetKeyValueW, HKEY_CURRENT_USER, REG_SZ, RRF_RT_REG_SZ,
    };

    const KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
    const NAME: &str = "2Secret";

    pub fn enabled() -> bool {
        let mut size = 0u32;
        unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                &HSTRING::from(KEY),
                &HSTRING::from(NAME),
                RRF_RT_REG_SZ,
                None,
                None,
                Some(&mut size),
            )
        }
        .is_ok()
    }

    pub fn enable() -> bool {
        let Ok(exe) = std::env::current_exe() else { return false };
        let command = format!("\"{}\" {}", exe.to_string_lossy(), super::HIDDEN);
        let data: Vec<u16> = command.encode_utf16().chain([0]).collect();
        unsafe {
            RegSetKeyValueW(
                HKEY_CURRENT_USER,
                &HSTRING::from(KEY),
                &HSTRING::from(NAME),
                REG_SZ.0,
                Some(data.as_ptr().cast()),
                (data.len() * 2) as u32,
            )
        }
        .is_ok()
    }

    pub fn disable() -> bool {
        let result = unsafe { RegDeleteKeyValueW(HKEY_CURRENT_USER, &HSTRING::from(KEY), &HSTRING::from(NAME)) };
        result.is_ok() || result == ERROR_FILE_NOT_FOUND
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
mod os {
    use std::path::PathBuf;

    fn entry_path() -> Option<PathBuf> {
        let config = std::env::var_os("XDG_CONFIG_HOME")
            .filter(|d| !d.is_empty())
            .map(PathBuf::from)
            .or_else(|| Some(PathBuf::from(std::env::var_os("HOME")?).join(".config")))?;
        Some(config.join("autostart").join("2secret.desktop"))
    }

    pub fn enabled() -> bool {
        entry_path().is_some_and(|p| p.is_file())
    }

    pub fn enable() -> bool {
        let (Some(path), Some(program)) = (entry_path(), crate::link_handler::exec_program()) else {
            return false;
        };
        let content = format!(
            "[Desktop Entry]\nType=Application\nName=2Secret\nComment=Password manager\n\
             Exec={program} {}\nTerminal=false\nX-GNOME-Autostart-enabled=true\n",
            super::HIDDEN
        );
        if std::fs::read_to_string(&path).ok().as_deref() == Some(content.as_str()) {
            return true;
        }
        path.parent().is_some_and(|dir| std::fs::create_dir_all(dir).is_ok()) && std::fs::write(&path, content).is_ok()
    }

    pub fn disable() -> bool {
        entry_path().is_some_and(|p| !p.exists() || std::fs::remove_file(p).is_ok())
    }
}
