//! App updates from the GitHub releases, opt-in (Settings → Updates).
//!
//! Where the app can replace itself, it does:
//!
//! - **Windows**, installed with the setup program in a folder the user may
//!   write to (the default): once 2Secret has quit, the new setup runs
//!   silently and starts 2Secret again.
//! - **macOS**, when the folder with the app is writable (`/Applications`
//!   for administrators): the app from the new disk image replaces this one.
//! - **Linux AppImage**: the new AppImage replaces the file.
//!
//! An update is downloaded into a private folder, verified (signature,
//! version, size and SHA-256, see [`twosecret_core::update`]) and installed
//! at the next start or with *Restart now*, after verifying it once more.
//! Elsewhere (Linux packages, an .msi of 2Secret up to 1.7.0 in Program Files,
//! whose replacement is the setup, Android, the BSDs) the
//! app only says that a new version is available and opens the download. The
//! iOS app, the web vault and the browser extension are updated by their
//! stores and servers and have no updater.

use dioxus::prelude::*;

// Only Off where the stores update the app (web, extension, iOS).
#[cfg_attr(any(target_arch = "wasm32", target_os = "ios"), allow(dead_code))]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// No updates through the app.
    Off,
    /// Say that an update is available and open the download.
    Notify,
    /// Download and install updates.
    Install,
}

#[cfg_attr(any(target_arch = "wasm32", target_os = "ios"), allow(dead_code))]
#[derive(Clone, PartialEq, Debug, Default)]
pub enum Status {
    #[default]
    Idle,
    Checking,
    UpToDate,
    /// `installable`: the app can install it itself; otherwise the Download
    /// button opens `download`.
    Available {
        version: String,
        notes: String,
        installable: bool,
        download: String,
    },
    Downloading {
        version: String,
    },
    /// Downloaded and verified; installed at the next start.
    Ready {
        version: String,
        notes: String,
    },
    Failed(String),
}

pub static STATUS: GlobalSignal<Status> = Signal::global(Status::default);

pub use imp::{apply_at_start, background, check, install, mode, restart};

#[cfg(not(any(target_arch = "wasm32", target_os = "ios")))]
mod imp {
    use std::cell::{Cell, RefCell};
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, OnceLock};

    use dioxus::prelude::*;

    use twosecret_core::update::{target, Update};
    use twosecret_core::util::now;
    use twosecret_core::VERSION;

    use super::{Mode, Status, STATUS};
    use crate::i18n::t;
    use crate::platform;
    use crate::state::{client_error, toast, PREFS};

    const DAY: i64 = 24 * 3600;
    const MANIFEST: &str = "update.json";
    const SIGNATURE: &str = "update.json.sig";
    /// Holds the version being installed; still there at the next start
    /// means the installation did not finish.
    const ATTEMPT: &str = "attempt";

    thread_local! {
        static LAST_CHECK: Cell<i64> = const { Cell::new(0) };
        static LATEST: RefCell<Option<Update>> = const { RefCell::new(None) };
    }

    /// Why installing failed (translated when shown: the first attempt is
    /// made before the UI, and its language, exist).
    enum Problem {
        Gone,
        Interrupted,
        Other(String),
    }

    impl Problem {
        fn text(self) -> String {
            match self {
                Problem::Gone => t("update.gone").into(),
                Problem::Interrupted => t("update.interrupted").into(),
                Problem::Other(e) => e,
            }
        }
    }

    /// An installation at start that failed, for Settings.
    static START_ERROR: Mutex<Option<Problem>> = Mutex::new(None);

    /// The installer this build updates with.
    fn target() -> Option<&'static str> {
        if cfg!(all(windows, target_arch = "x86_64")) {
            Some(target::WINDOWS_X64)
        } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
            Some(target::MACOS_ARM64)
        } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
            Some(target::MACOS_X64)
        } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) && std::env::var_os("APPIMAGE").is_some() {
            Some(target::LINUX_X64_APPIMAGE)
        } else if cfg!(all(target_os = "android", target_arch = "aarch64")) {
            Some(target::ANDROID_ARM64)
        } else {
            None
        }
    }

    pub fn mode() -> Mode {
        static MODE: OnceLock<Mode> = OnceLock::new();
        *MODE.get_or_init(|| if target().is_some() && os::can_install() { Mode::Install } else { Mode::Notify })
    }

    /// Where updates are downloaded to (private to the user).
    fn dir() -> PathBuf {
        #[cfg(windows)]
        if let Some(local) = std::env::var_os("LOCALAPPDATA") {
            return PathBuf::from(local).join("2Secret").join("update");
        }
        platform::data_dir().join("update")
    }

    /// The downloaded update, verified again, if it is newer than this
    /// version.
    fn staged() -> Option<(Update, PathBuf)> {
        let dir = dir();
        let json = std::fs::read(dir.join(MANIFEST)).ok()?;
        let signature = std::fs::read_to_string(dir.join(SIGNATURE)).ok()?;
        let update = Update::verify(json, &signature).ok()?;
        if !update.manifest.is_newer_than(VERSION) {
            return None;
        }
        let asset = update.manifest.file(target()?)?;
        let path = dir.join(asset.name());
        asset.verify(&std::fs::read(&path).ok()?).ok()?;
        Some((update, path))
    }

    fn ready(update: &Update) -> Status {
        Status::Ready { version: update.manifest.version.clone(), notes: update.manifest.url.clone() }
    }

    /// Install a downloaded update before the app starts. Returns only if
    /// there is nothing to install or installing failed.
    pub fn apply_at_start() {
        if mode() != Mode::Install || !dir().exists() {
            return;
        }
        let Some((update, _)) = staged() else {
            // Installed (this is the new version), outdated or damaged.
            let _ = std::fs::remove_dir_all(dir());
            return;
        };
        let attempted = std::fs::read_to_string(dir().join(ATTEMPT)).ok();
        let result = if attempted.as_deref() == Some(update.manifest.version.as_str()) {
            // The last attempt did not finish: do not retry at every start.
            Err(Problem::Interrupted)
        } else {
            apply()
        };
        if let Err(e) = result {
            let _ = std::fs::remove_dir_all(dir());
            *START_ERROR.lock().unwrap_or_else(|e| e.into_inner()) = Some(e);
        }
    }

    /// Install the downloaded update and start the new version (exits).
    fn apply() -> Result<(), Problem> {
        let (update, path) = staged().ok_or(Problem::Gone)?;
        let marker = dir().join(ATTEMPT);
        std::fs::write(&marker, &update.manifest.version).map_err(|e| Problem::Other(e.to_string()))?;
        os::install(&path, &marker).map_err(Problem::Other)?;
        #[cfg(feature = "desktop")]
        crate::tray::remove();
        std::process::exit(0);
    }

    /// *Restart now*.
    pub fn restart() {
        if let Err(e) = apply() {
            *STATUS.write() = Status::Failed(e.text());
        }
    }

    /// Check now and then while automatic updates are on.
    pub async fn background() {
        let failed = START_ERROR.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(e) = failed {
            *STATUS.write() = Status::Failed(e.text());
        }
        platform::sleep_ms(15_000).await;
        loop {
            if PREFS.peek().auto_update && now() - LAST_CHECK.with(Cell::get) >= DAY {
                check(true).await;
            }
            platform::sleep_ms(3600 * 1000).await;
        }
    }

    /// Look for a newer version. `auto`: started by automatic updates, which
    /// download it right away and only report what changed.
    pub async fn check(auto: bool) {
        if matches!(*STATUS.peek(), Status::Checking | Status::Downloading { .. }) {
            return;
        }
        LAST_CHECK.with(|c| c.set(now()));
        if mode() == Mode::Install {
            if let Some((update, _)) = platform::run_heavy(staged).await {
                *STATUS.write() = ready(&update);
                return;
            }
        }
        *STATUS.write() = Status::Checking;
        let update = match twosecret_client::update::latest().await {
            Ok(Some(update)) if update.manifest.is_newer_than(VERSION) => update,
            Ok(_) => {
                *STATUS.write() = Status::UpToDate;
                return;
            }
            Err(e) => {
                *STATUS.write() = Status::Failed(client_error(&e));
                return;
            }
        };
        let manifest = &update.manifest;
        let file = target().and_then(|t| manifest.file(t));
        let installable = mode() == Mode::Install && file.is_some();
        *STATUS.write() = Status::Available {
            version: manifest.version.clone(),
            notes: manifest.url.clone(),
            installable,
            download: file.map(|f| f.url.clone()).unwrap_or_else(|| manifest.url.clone()),
        };
        LATEST.with(|l| *l.borrow_mut() = Some(update.clone()));
        if !auto {
            return;
        }
        if installable {
            install().await;
            if matches!(*STATUS.peek(), Status::Ready { .. }) {
                toast(&t("update.toast_ready").replace("{version}", &manifest.version));
            }
        } else {
            toast(&t("update.toast_available").replace("{version}", &manifest.version));
        }
    }

    /// Download the update found by [`check`] and keep it for the next start.
    pub async fn install() {
        let Some(update) = LATEST.with(|l| l.borrow().clone()) else { return };
        let Some(asset) = target().and_then(|t| update.manifest.file(t)).cloned() else {
            *STATUS.write() = Status::Failed(t("update.no_file").into());
            return;
        };
        *STATUS.write() = Status::Downloading { version: update.manifest.version.clone() };
        let bytes = match twosecret_client::update::download(&asset).await {
            Ok(b) => b,
            Err(e) => {
                *STATUS.write() = Status::Failed(client_error(&e));
                return;
            }
        };
        let stage = update.clone();
        let saved = platform::run_heavy(move || -> std::io::Result<()> {
            let dir = dir();
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir)?;
            std::fs::write(dir.join(asset.name()), &bytes)?;
            std::fs::write(dir.join(SIGNATURE), &stage.signature)?;
            // The manifest last: without it nothing is installed.
            std::fs::write(dir.join(MANIFEST), &stage.json)
        })
        .await;
        *STATUS.write() = match saved {
            Ok(()) => ready(&update),
            Err(e) => Status::Failed(e.to_string()),
        };
    }

    /// Whether a folder can be written to (for replacing the app in it).
    #[allow(dead_code)]
    fn writable(dir: &Path) -> bool {
        let probe = dir.join(format!(".2secret-update-{}", std::process::id()));
        let ok = std::fs::File::create(&probe).is_ok();
        let _ = std::fs::remove_file(&probe);
        ok
    }

    #[cfg(windows)]
    mod os {
        use std::os::windows::process::CommandExt;
        use std::path::Path;

        /// Installed with the per-user setup program (not the .msi of
        /// releases up to 1.7.0 in Program Files, which needs an
        /// administrator; the setup offers to remove that one).
        pub fn can_install() -> bool {
            std::env::current_exe().ok().and_then(|exe| exe.parent().map(super::writable)).unwrap_or(false)
        }

        fn quote(text: &str) -> String {
            format!("'{}'", text.replace('\'', "''"))
        }

        /// After 2Secret has quit, run the new setup silently into this
        /// folder and start 2Secret again.
        pub fn install(setup: &Path, marker: &Path) -> Result<(), String> {
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            let dir = exe.parent().ok_or("no installation folder")?;
            // NSIS: `/D=` comes last and without quotes, even with spaces.
            let script = format!(
                "$ErrorActionPreference = 'SilentlyContinue'
$exe = {exe}
$deadline = (Get-Date).AddMinutes(2)
while (Get-Process | Where-Object {{ $_.Path -eq $exe }}) {{
  if ((Get-Date) -gt $deadline) {{ Remove-Item -LiteralPath {marker}; exit }}
  Start-Sleep -Milliseconds 300
}}
$setup = Start-Process -PassThru -FilePath {setup} -ArgumentList {args}
$setup.WaitForExit()
Start-Sleep -Seconds 1
if (-not (Get-Process | Where-Object {{ $_.Path -eq $exe }})) {{ Start-Process -FilePath $exe }}
",
                exe = quote(&exe.to_string_lossy()),
                marker = quote(&marker.to_string_lossy()),
                setup = quote(&setup.to_string_lossy()),
                args = quote(&format!("/S /D={}", dir.to_string_lossy())),
            );
            let encoded: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            std::process::Command::new("powershell.exe")
                .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand"])
                .arg(twosecret_core::util::b64(&encoded))
                .creation_flags(CREATE_NO_WINDOW)
                .spawn()
                .map(drop)
                .map_err(|e| format!("PowerShell: {e}"))
        }
    }

    #[cfg(target_os = "macos")]
    mod os {
        use std::path::{Path, PathBuf};
        use std::process::Command;

        /// `…/2Secret.app` of the running app.
        fn bundle() -> Option<PathBuf> {
            let exe = std::env::current_exe().ok()?;
            let bundle = exe.ancestors().nth(3)?;
            (bundle.extension()? == "app").then(|| bundle.to_path_buf())
        }

        /// Not when started from the disk image or a quarantined download
        /// (App Translocation), which are read-only.
        pub fn can_install() -> bool {
            bundle().and_then(|b| b.parent().map(super::writable)).unwrap_or(false)
        }

        fn run(program: &str, args: &[&Path]) -> Result<(), String> {
            let out = Command::new(program).args(args).output().map_err(|e| format!("{program}: {e}"))?;
            if out.status.success() {
                Ok(())
            } else {
                Err(format!("{program}: {}", String::from_utf8_lossy(&out.stderr).trim()))
            }
        }

        /// Replace the app with the one in the disk image and start it.
        pub fn install(dmg: &Path, _marker: &Path) -> Result<(), String> {
            let bundle = bundle().ok_or("not running from an app bundle")?;
            let parent = bundle.parent().ok_or("no folder")?;
            let mount = dmg.with_file_name("mount");
            let _ = std::fs::create_dir_all(&mount);
            run(
                "hdiutil",
                &[
                    Path::new("attach"),
                    Path::new("-nobrowse"),
                    Path::new("-readonly"),
                    Path::new("-noautoopen"),
                    Path::new("-mountpoint"),
                    &mount,
                    dmg,
                ],
            )?;
            let new = parent.join(".2Secret-update.app");
            let copied = (|| {
                let app = std::fs::read_dir(&mount)
                    .map_err(|e| e.to_string())?
                    .flatten()
                    .map(|e| e.path())
                    .find(|p| p.extension().is_some_and(|e| e == "app"))
                    .ok_or("no app in the disk image")?;
                let _ = std::fs::remove_dir_all(&new);
                run("ditto", &[&app, &new])
            })();
            let _ = run("hdiutil", &[Path::new("detach"), &mount, Path::new("-force")]);
            copied?;
            // The copy must be intact (and signed like the release).
            run("codesign", &[Path::new("--verify"), Path::new("--deep"), Path::new("--strict"), &new])?;
            let old = parent.join(".2Secret-old.app");
            let _ = std::fs::remove_dir_all(&old);
            std::fs::rename(&bundle, &old).map_err(|e| e.to_string())?;
            if let Err(e) = std::fs::rename(&new, &bundle) {
                let _ = std::fs::rename(&old, &bundle);
                return Err(e.to_string());
            }
            let _ = std::fs::remove_dir_all(&old);
            Command::new("/bin/sh")
                .args(["-c", r#"while kill -0 "$1" 2>/dev/null; do sleep 0.2; done; open -n "$0""#])
                .arg(&bundle)
                .arg(std::process::id().to_string())
                .spawn()
                .map(drop)
                .map_err(|e| e.to_string())
        }
    }

    #[cfg(target_os = "linux")]
    mod os {
        use std::path::{Path, PathBuf};
        use std::process::Command;

        fn appimage() -> Option<PathBuf> {
            std::env::var_os("APPIMAGE").map(PathBuf::from).filter(|p| p.is_file())
        }

        pub fn can_install() -> bool {
            appimage().and_then(|p| p.parent().map(super::writable)).unwrap_or(false)
        }

        /// Replace the AppImage and start the new one.
        pub fn install(file: &Path, _marker: &Path) -> Result<(), String> {
            use std::os::unix::fs::PermissionsExt;
            let target = appimage().ok_or("not running as an AppImage")?;
            let name = target.file_name().ok_or("no file name")?.to_string_lossy();
            let tmp = target.with_file_name(format!(".{name}.update"));
            std::fs::copy(file, &tmp).map_err(|e| e.to_string())?;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
            std::fs::rename(&tmp, &target).map_err(|e| e.to_string())?;
            let mut command = Command::new("/bin/sh");
            command
                .args(["-c", r#"while kill -0 "$1" 2>/dev/null; do sleep 0.2; done; exec "$0""#])
                .arg(&target)
                .arg(std::process::id().to_string());
            // Leave out what this AppImage's runtime set up for itself.
            if let Some(appdir) = std::env::var("APPDIR").ok().filter(|d| !d.is_empty()) {
                for (key, value) in std::env::vars() {
                    if ["APPDIR", "APPIMAGE", "ARGV0", "OWD"].contains(&key.as_str()) {
                        command.env_remove(&key);
                    } else if value.contains(&appdir) {
                        let kept: Vec<&str> = value.split(':').filter(|p| !p.starts_with(&appdir)).collect();
                        if kept.iter().all(|p| p.is_empty()) {
                            command.env_remove(&key);
                        } else {
                            command.env(&key, kept.join(":"));
                        }
                    }
                }
            }
            command.spawn().map(drop).map_err(|e| e.to_string())
        }
    }

    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    mod os {
        use std::path::Path;

        pub fn can_install() -> bool {
            false
        }

        pub fn install(_file: &Path, _marker: &Path) -> Result<(), String> {
            Err("not supported".into())
        }
    }
}

#[cfg(any(target_arch = "wasm32", target_os = "ios"))]
mod imp {
    use super::Mode;

    pub fn mode() -> Mode {
        Mode::Off
    }
    pub fn apply_at_start() {}
    pub async fn background() {}
    pub async fn check(_auto: bool) {}
    pub async fn install() {}
    pub fn restart() {}
}
