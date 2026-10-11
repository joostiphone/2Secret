//! Persistence backends. The profile and device secrets are stored as small
//! JSON documents under string keys.

use std::cell::RefCell;
use std::collections::HashMap;

use crate::Result;

/// Minimal key/value storage used by the apps.
pub trait Storage {
    fn read(&self, key: &str) -> Result<Option<String>>;
    fn write(&self, key: &str, value: &str) -> Result<()>;
    fn delete(&self, key: &str) -> Result<()>;
}

/// In-memory storage (tests, ephemeral sessions).
#[derive(Default)]
pub struct MemoryStorage {
    data: RefCell<HashMap<String, String>>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Storage for MemoryStorage {
    fn read(&self, key: &str) -> Result<Option<String>> {
        Ok(self.data.borrow().get(key).cloned())
    }
    fn write(&self, key: &str, value: &str) -> Result<()> {
        self.data.borrow_mut().insert(key.to_string(), value.to_string());
        Ok(())
    }
    fn delete(&self, key: &str) -> Result<()> {
        self.data.borrow_mut().remove(key);
        Ok(())
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use file::FileStorage;

#[cfg(not(target_arch = "wasm32"))]
mod file {
    use std::fs;
    use std::io::Write;
    use std::path::{Path, PathBuf};

    use super::Storage;
    use crate::{Error, Result};

    /// Stores each key as `<dir>/<key>.json`, written atomically (temp file +
    /// rename) with owner-only permissions. The previous version of every
    /// file is kept as `<key>.json.bak`.
    pub struct FileStorage {
        dir: PathBuf,
    }

    impl FileStorage {
        pub fn new(dir: impl Into<PathBuf>) -> Result<Self> {
            let dir = dir.into();
            fs::create_dir_all(&dir)?;
            restrict_dir(&dir);
            Ok(Self { dir })
        }

        pub fn dir(&self) -> &Path {
            &self.dir
        }

        fn path(&self, key: &str) -> Result<PathBuf> {
            if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                return Err(Error::Storage(format!("invalid storage key '{key}'")));
            }
            Ok(self.dir.join(format!("{key}.json")))
        }
    }

    #[cfg(unix)]
    fn restrict_dir(dir: &Path) {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }

    #[cfg(not(unix))]
    fn restrict_dir(_dir: &Path) {}

    fn create_private(path: &Path) -> std::io::Result<fs::File> {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        opts.open(path)
    }

    impl Storage for FileStorage {
        fn read(&self, key: &str) -> Result<Option<String>> {
            let path = self.path(key)?;
            match fs::read_to_string(&path) {
                Ok(s) => Ok(Some(s)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e.into()),
            }
        }

        fn write(&self, key: &str, value: &str) -> Result<()> {
            let path = self.path(key)?;
            let tmp = path.with_extension("json.tmp");
            {
                let mut f = create_private(&tmp)?;
                f.write_all(value.as_bytes())?;
                f.sync_all()?;
            }
            if path.exists() {
                let _ = fs::copy(&path, path.with_extension("json.bak"));
            }
            fs::rename(&tmp, &path)?;
            Ok(())
        }

        fn delete(&self, key: &str) -> Result<()> {
            let path = self.path(key)?;
            for p in [path.clone(), path.with_extension("json.bak")] {
                match fs::remove_file(&p) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                }
            }
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn file_storage_roundtrip() {
            let dir = std::env::temp_dir().join(format!("2secret-test-{}", crate::util::new_id()));
            let s = FileStorage::new(&dir).unwrap();
            assert_eq!(s.read("profile").unwrap(), None);
            s.write("profile", "one").unwrap();
            s.write("profile", "two").unwrap();
            assert_eq!(s.read("profile").unwrap().as_deref(), Some("two"));
            assert_eq!(fs::read_to_string(dir.join("profile.json.bak")).unwrap(), "one");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = fs::metadata(dir.join("profile.json")).unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o600);
            }
            assert!(s.write("../evil", "x").is_err());
            s.delete("profile").unwrap();
            assert_eq!(s.read("profile").unwrap(), None);
            fs::remove_dir_all(dir).unwrap();
        }
    }
}

/// The default data directory for 2Secret on native platforms.
#[cfg(not(target_arch = "wasm32"))]
pub fn default_data_dir() -> std::path::PathBuf {
    if let Ok(dir) = std::env::var("TWOSECRET_HOME") {
        if !dir.is_empty() {
            return dir.into();
        }
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    #[cfg(target_os = "windows")]
    {
        if let Some(appdata) = std::env::var_os("APPDATA") {
            return std::path::PathBuf::from(appdata).join("2Secret");
        }
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        return home.join("Library").join("Application Support").join("2Secret");
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    {
        if let Some(xdg) = std::env::var_os("XDG_DATA_HOME").filter(|v| !v.is_empty()) {
            return std::path::PathBuf::from(xdg).join("2secret");
        }
        home.join(".local").join("share").join("2secret")
    }
}
