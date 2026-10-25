//! The browser connection: where each browser looks for the native messaging
//! host manifest, what the manifest says, and how the host is recognised when
//! a browser starts it. Pure functions; the app writes the files and the
//! registry values ([`crate::host`] is the host itself).
//!
//! A browser starts the program named in the manifest with the extension as
//! the only allowed caller. Chromium browsers pass the extension's origin as
//! the first argument (`chrome-extension://<id>/`, on Windows followed by
//! `--parent-window=<hwnd>`); Firefox passes the manifest's path and the
//! extension's id.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use twosecret_core::crypto::sha256;
use twosecret_core::util::unb64;

/// The host's name in every manifest and registry key.
pub const HOST_NAME: &str = "io.github.joostiphone.twosecret";
/// The extension's id in Firefox (`browser_specific_settings.gecko.id`).
pub const GECKO_ID: &str = "2secret@joostiphone.github.io";
/// The id of the 2Secret extension in Chromium browsers: derived from the
/// public key in `extension/manifest.json`, so the store build and an
/// unpacked build share it. Development builds without the key get other
/// ids; the app lets the user add those.
pub const KNOWN_EXTENSION_IDS: &[&str] = &["gnkfgnlegljjfnihdefkjepdoaphccfd"];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Browser {
    Chrome,
    Chromium,
    Brave,
    Edge,
    Vivaldi,
    Arc,
    Firefox,
}

impl Browser {
    pub const ALL: [Browser; 7] = [
        Browser::Chrome,
        Browser::Chromium,
        Browser::Brave,
        Browser::Edge,
        Browser::Vivaldi,
        Browser::Arc,
        Browser::Firefox,
    ];

    /// The name the protocol uses (`chrome`, `edge`, ...).
    pub fn name(&self) -> &'static str {
        match self {
            Browser::Chrome => "chrome",
            Browser::Chromium => "chromium",
            Browser::Brave => "brave",
            Browser::Edge => "edge",
            Browser::Vivaldi => "vivaldi",
            Browser::Arc => "arc",
            Browser::Firefox => "firefox",
        }
    }

    /// The name as the user sees it.
    pub fn label(&self) -> &'static str {
        match self {
            Browser::Chrome => "Chrome",
            Browser::Chromium => "Chromium",
            Browser::Brave => "Brave",
            Browser::Edge => "Microsoft Edge",
            Browser::Vivaldi => "Vivaldi",
            Browser::Arc => "Arc",
            Browser::Firefox => "Firefox",
        }
    }

    pub fn is_firefox(&self) -> bool {
        matches!(self, Browser::Firefox)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Os {
    MacOs,
    Linux,
    Windows,
}

impl Os {
    pub fn current() -> Option<Os> {
        if cfg!(target_os = "macos") {
            Some(Os::MacOs)
        } else if cfg!(target_os = "windows") {
            Some(Os::Windows)
        } else if cfg!(target_os = "linux") {
            Some(Os::Linux)
        } else {
            None
        }
    }
}

/// Where a browser reads the manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Place {
    /// A directory holding `<HOST_NAME>.json` (macOS, Linux).
    Dir(PathBuf),
    /// A registry key under HKEY_CURRENT_USER whose default value is the
    /// path of the manifest file (Windows).
    Registry(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Location {
    pub browser: Browser,
    pub place: Place,
}

impl Location {
    /// The manifest file for a directory place.
    pub fn manifest_path(&self) -> Option<PathBuf> {
        match &self.place {
            Place::Dir(dir) => Some(dir.join(format!("{HOST_NAME}.json"))),
            Place::Registry(_) => None,
        }
    }
}

/// Every browser's place on `os` for the user with home directory `home`.
/// On Linux `config` is `$XDG_CONFIG_HOME` (`~/.config` when unset).
pub fn locations(os: Os, home: &Path, config: &Path) -> Vec<Location> {
    let dir = |browser: Browser, path: PathBuf| Location { browser, place: Place::Dir(path) };
    match os {
        Os::MacOs => {
            let support = home.join("Library/Application Support");
            vec![
                dir(Browser::Chrome, support.join("Google/Chrome/NativeMessagingHosts")),
                dir(Browser::Chromium, support.join("Chromium/NativeMessagingHosts")),
                dir(Browser::Brave, support.join("BraveSoftware/Brave-Browser/NativeMessagingHosts")),
                dir(Browser::Edge, support.join("Microsoft Edge/NativeMessagingHosts")),
                dir(Browser::Vivaldi, support.join("Vivaldi/NativeMessagingHosts")),
                dir(Browser::Arc, support.join("Arc/User Data/NativeMessagingHosts")),
                dir(Browser::Firefox, support.join("Mozilla/NativeMessagingHosts")),
            ]
        }
        Os::Linux => vec![
            dir(Browser::Chrome, config.join("google-chrome/NativeMessagingHosts")),
            dir(Browser::Chromium, config.join("chromium/NativeMessagingHosts")),
            dir(Browser::Brave, config.join("BraveSoftware/Brave-Browser/NativeMessagingHosts")),
            dir(Browser::Edge, config.join("microsoft-edge/NativeMessagingHosts")),
            dir(Browser::Vivaldi, config.join("vivaldi/NativeMessagingHosts")),
            dir(Browser::Firefox, home.join(".mozilla/native-messaging-hosts")),
        ],
        Os::Windows => {
            let key = |browser: Browser, vendor: &str| Location {
                browser,
                place: Place::Registry(format!(r"Software\{vendor}\NativeMessagingHosts\{HOST_NAME}")),
            };
            vec![
                key(Browser::Chrome, r"Google\Chrome"),
                key(Browser::Chromium, "Chromium"),
                key(Browser::Brave, r"BraveSoftware\Brave-Browser"),
                key(Browser::Edge, r"Microsoft\Edge"),
                key(Browser::Vivaldi, "Vivaldi"),
                key(Browser::Firefox, "Mozilla"),
            ]
        }
    }
}

/// Whether `id` looks like a Chromium extension id: 32 letters a–p.
pub fn valid_extension_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| (b'a'..=b'p').contains(&b))
}

/// The id Chromium derives from a `key` in the manifest (the DER public key,
/// base64): the first 16 bytes of its SHA-256, as letters a–p.
pub fn extension_id_from_key(key_b64: &str) -> Option<String> {
    let der = unb64(key_b64).ok()?;
    let hash = sha256(&der);
    Some(hash[..16].iter().flat_map(|b| [b >> 4, b & 0x0f]).map(|nibble| (b'a' + nibble) as char).collect())
}

/// The origins a Chromium manifest allows: the known ids and the user's own
/// (development) ids, each once, malformed ones left out.
pub fn origins(known: &[&str], dev_ids: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for id in known.iter().copied().chain(dev_ids.iter().map(|s| s.trim())) {
        let id = id.to_lowercase();
        if valid_extension_id(&id) {
            let origin = format!("chrome-extension://{id}/");
            if !out.contains(&origin) {
                out.push(origin);
            }
        }
    }
    out
}

fn manifest(exe: &Path, allowed: (&str, Vec<String>)) -> String {
    let mut m = json!({
        "name": HOST_NAME,
        "description": "2Secret browser connection: fills logins that the user allowed an AI agent to use",
        "path": exe.to_string_lossy(),
        "type": "stdio",
    });
    m[allowed.0] = Value::Array(allowed.1.into_iter().map(Value::String).collect());
    serde_json::to_string_pretty(&m).unwrap_or_default() + "\n"
}

/// The manifest for Chrome, Chromium, Brave, Edge, Vivaldi and Arc.
pub fn chromium_manifest(exe: &Path, origins: &[String]) -> String {
    manifest(exe, ("allowed_origins", origins.to_vec()))
}

/// The manifest for Firefox.
pub fn firefox_manifest(exe: &Path) -> String {
    manifest(exe, ("allowed_extensions", vec![GECKO_ID.to_string()]))
}

/// How a browser started the program, read from its arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostArgs {
    /// A Chromium browser: the extension's origin.
    Chromium { origin: String },
    /// Firefox: the manifest it read and the extension's id.
    Firefox { manifest: PathBuf, id: String },
    /// `--native-host [browser]`: started by hand, for tests.
    Manual { browser: Option<String> },
}

impl HostArgs {
    /// The extension as the app records it.
    pub fn extension(&self) -> Option<String> {
        match self {
            HostArgs::Chromium { origin } => Some(origin.clone()),
            HostArgs::Firefox { id, .. } => Some(id.clone()),
            HostArgs::Manual { .. } => None,
        }
    }
}

/// Recognise a start by a browser (the arguments after the program name).
/// Anything else, a setup link or `--hidden` for instance, is `None`.
pub fn from_args(args: &[String]) -> Option<HostArgs> {
    let first = args.first()?;
    if let Some(rest) = first.strip_prefix("chrome-extension://") {
        let id = rest.trim_end_matches('/');
        if valid_extension_id(id) {
            return Some(HostArgs::Chromium { origin: format!("chrome-extension://{id}/") });
        }
        return None;
    }
    if first == "--native-host" {
        return Some(HostArgs::Manual { browser: args.get(1).cloned().filter(|b| !b.starts_with('-')) });
    }
    if first.ends_with(".json") && args.get(1).is_some_and(|id| id == GECKO_ID) {
        return Some(HostArgs::Firefox { manifest: PathBuf::from(first), id: GECKO_ID.to_string() });
    }
    None
}

/// The browser behind a parent process name (`Google Chrome`, `msedge.exe`,
/// `firefox-bin`, ...), when it is one.
pub fn browser_from_parent(name: &str) -> Option<&'static str> {
    let n = name.rsplit(['/', '\\']).next().unwrap_or(name).to_lowercase();
    if n.contains("chromium") {
        Some("chromium")
    } else if n.contains("msedge") || n.contains("microsoft edge") {
        Some("edge")
    } else if n.contains("brave") {
        Some("brave")
    } else if n.contains("vivaldi") {
        Some("vivaldi")
    } else if n.contains("firefox") {
        Some("firefox")
    } else if n.contains("opera") {
        Some("opera")
    } else if n == "arc" || n.starts_with("arc ") || n == "arc.exe" {
        Some("arc")
    } else if n.contains("chrome") {
        Some("chrome")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_are_recognised() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            from_args(&a(&["chrome-extension://gnkfgnlegljjfnihdefkjepdoaphccfd/", "--parent-window=1234"])),
            Some(HostArgs::Chromium { origin: "chrome-extension://gnkfgnlegljjfnihdefkjepdoaphccfd/".into() })
        );
        assert_eq!(from_args(&a(&["chrome-extension://nope/"])), None, "not an id");
        assert_eq!(
            from_args(&a(&["/home/me/.mozilla/native-messaging-hosts/x.json", GECKO_ID])),
            Some(HostArgs::Firefox {
                manifest: "/home/me/.mozilla/native-messaging-hosts/x.json".into(),
                id: GECKO_ID.into()
            })
        );
        assert_eq!(from_args(&a(&["/x.json", "other@example"])), None);
        assert_eq!(
            from_args(&a(&["--native-host", "chrome"])),
            Some(HostArgs::Manual { browser: Some("chrome".into()) })
        );
        assert_eq!(from_args(&a(&["--native-host"])), Some(HostArgs::Manual { browser: None }));
        assert_eq!(from_args(&a(&["otpauth://totp/x"])), None);
        assert_eq!(from_args(&a(&["--hidden"])), None);
        assert_eq!(from_args(&[]), None);
        assert_eq!(
            from_args(&a(&["chrome-extension://gnkfgnlegljjfnihdefkjepdoaphccfd/"])).unwrap().extension().unwrap(),
            "chrome-extension://gnkfgnlegljjfnihdefkjepdoaphccfd/"
        );
    }

    #[test]
    fn manifests_and_origins() {
        let exe = Path::new("/Applications/2Secret.app/Contents/MacOS/2-secret");
        let origins = origins(
            KNOWN_EXTENSION_IDS,
            &["ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP".into(), "bad".into(), "gnkfgnlegljjfnihdefkjepdoaphccfd".into()],
        );
        assert_eq!(
            origins,
            vec![
                "chrome-extension://gnkfgnlegljjfnihdefkjepdoaphccfd/",
                "chrome-extension://abcdefghijklmnopabcdefghijklmnop/"
            ]
        );
        let m: Value = serde_json::from_str(&chromium_manifest(exe, &origins)).unwrap();
        assert_eq!(m["name"], HOST_NAME);
        assert_eq!(m["type"], "stdio");
        assert_eq!(m["path"], exe.to_string_lossy().as_ref());
        assert_eq!(m["allowed_origins"].as_array().unwrap().len(), 2);
        assert!(m.get("allowed_extensions").is_none());
        let f: Value = serde_json::from_str(&firefox_manifest(exe)).unwrap();
        assert_eq!(f["allowed_extensions"], json!([GECKO_ID]));
        assert!(f.get("allowed_origins").is_none());
        assert!(valid_extension_id("gnkfgnlegljjfnihdefkjepdoaphccfd"));
        assert!(!valid_extension_id("gnkfgnlegljjfnihdefkjepdoaphccfq"));
        assert!(!valid_extension_id("gnkfgnlegljjfnihdefkjepdoaphccf"));
    }

    #[test]
    fn locations_per_os() {
        let home = Path::new("/Users/me");
        let mac = locations(Os::MacOs, home, home);
        assert_eq!(mac.len(), 7);
        assert_eq!(
            mac[0].manifest_path().unwrap(),
            PathBuf::from("/Users/me/Library/Application Support/Google/Chrome/NativeMessagingHosts/io.github.joostiphone.twosecret.json")
        );
        assert!(mac.iter().any(|l| l.browser == Browser::Firefox
            && l.manifest_path().unwrap().to_string_lossy().contains("Mozilla/NativeMessagingHosts")));
        let linux = locations(Os::Linux, Path::new("/home/me"), Path::new("/home/me/.config"));
        assert_eq!(
            linux.iter().find(|l| l.browser == Browser::Firefox).unwrap().place,
            Place::Dir("/home/me/.mozilla/native-messaging-hosts".into())
        );
        assert_eq!(linux[0].place, Place::Dir("/home/me/.config/google-chrome/NativeMessagingHosts".into()));
        let win = locations(Os::Windows, Path::new(r"C:\Users\me"), Path::new(r"C:\Users\me"));
        assert_eq!(
            win[0].place,
            Place::Registry(r"Software\Google\Chrome\NativeMessagingHosts\io.github.joostiphone.twosecret".into())
        );
        assert!(win[0].manifest_path().is_none());
        assert!(win.iter().any(|l| l.place
            == Place::Registry(r"Software\Mozilla\NativeMessagingHosts\io.github.joostiphone.twosecret".into())));
        for b in Browser::ALL {
            assert_eq!(b.name(), b.name().to_lowercase());
            assert!(!b.label().is_empty());
        }
    }

    #[test]
    fn parents_name_browsers() {
        assert_eq!(browser_from_parent("Google Chrome"), Some("chrome"));
        assert_eq!(browser_from_parent(r"C:\Program Files\Google\Chrome\Application\chrome.exe"), Some("chrome"));
        assert_eq!(browser_from_parent("chromium-browser"), Some("chromium"));
        assert_eq!(browser_from_parent("msedge.exe"), Some("edge"));
        assert_eq!(browser_from_parent("Brave Browser"), Some("brave"));
        assert_eq!(browser_from_parent("firefox-bin"), Some("firefox"));
        assert_eq!(browser_from_parent("Arc"), Some("arc"));
        assert_eq!(browser_from_parent("cmd.exe"), None);
    }

    #[test]
    fn the_manifest_key_gives_the_known_id() {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../extension/manifest.json")).unwrap();
        let manifest: Value = serde_json::from_str(&text).unwrap();
        let key = manifest["key"].as_str().expect("extension/manifest.json has a key");
        let id = extension_id_from_key(key).unwrap();
        assert!(valid_extension_id(&id));
        assert!(KNOWN_EXTENSION_IDS.contains(&id.as_str()), "{id} is not in KNOWN_EXTENSION_IDS");
        assert!(extension_id_from_key("not base64!").is_none());
    }
}
