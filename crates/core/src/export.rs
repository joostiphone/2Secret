//! Exporting vaults: 2Secret JSON (plain or password-encrypted) and CSV.

use serde::{Deserialize, Serialize};

use crate::crypto::{KdfParams, PasswordEnvelope};
use crate::item::Item;
use crate::session::Session;
use crate::util::now;
use crate::Result;

pub const EXPORT_FORMAT: &str = "2secret-export";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExportData {
    pub format: String,
    pub version: u32,
    pub exported_at: i64,
    #[serde(default)]
    pub account: Option<String>,
    pub vaults: Vec<ExportVault>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExportVault {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub items: Vec<Item>,
}

impl ExportData {
    pub fn item_count(&self) -> usize {
        self.vaults.iter().map(|v| v.items.len()).sum()
    }

    /// Plain JSON. **Contains every secret in clear text.**
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("export serialization cannot fail")
    }

    /// Password protected JSON (Argon2id + XChaCha20-Poly1305).
    pub fn to_encrypted(&self, password: &str) -> Result<String> {
        let json = zeroize::Zeroizing::new(serde_json::to_vec(self)?);
        let env = PasswordEnvelope::seal(password, &json, KdfParams::default())?;
        Ok(serde_json::to_string_pretty(&env)?)
    }

    /// CSV with the most common columns (compatible with most password
    /// managers' CSV importers). **Contains secrets in clear text.**
    pub fn to_csv(&self) -> Result<String> {
        let mut w = csv::Writer::from_writer(Vec::new());
        w.write_record([
            "title", "url", "username", "password", "otpauth", "notes", "category", "tags", "favorite", "vault",
        ])
        .map_err(|e| crate::Error::invalid(e.to_string()))?;
        for vault in &self.vaults {
            for item in &vault.items {
                w.write_record([
                    item.title.as_str(),
                    item.primary_url().unwrap_or(""),
                    item.username().unwrap_or(""),
                    item.password().unwrap_or(""),
                    item.totp_secret().unwrap_or(""),
                    item.notes.as_str(),
                    item.category.id(),
                    item.tags.join(",").as_str(),
                    if item.favorite { "1" } else { "0" },
                    vault.name.as_str(),
                ])
                .map_err(|e| crate::Error::invalid(e.to_string()))?;
            }
        }
        let bytes = w.into_inner().map_err(|e| crate::Error::invalid(e.to_string()))?;
        Ok(String::from_utf8(bytes).expect("csv output is utf-8"))
    }
}

impl Session {
    /// Collect vaults (all, or the given ids) for export.
    pub fn export(&self, vault_ids: Option<&[String]>, include_trash: bool) -> ExportData {
        let vaults = self
            .vaults()
            .into_iter()
            .filter(|v| vault_ids.is_none_or(|ids| ids.contains(&v.id)))
            .map(|v| {
                let mut items: Vec<Item> = self
                    .all_items()
                    .filter(|(vid, i)| *vid == v.id && (include_trash || !i.is_trashed()))
                    .map(|(_, i)| i.clone())
                    .collect();
                items.sort_by_key(|i| i.title.to_lowercase());
                ExportVault {
                    name: v.name,
                    description: v.description,
                    items,
                }
            })
            .collect();
        ExportData {
            format: EXPORT_FORMAT.into(),
            version: 1,
            exported_at: now(),
            account: Some(self.account().email.clone()),
            vaults,
        }
    }
}
