//! Secret references: `2s://<vault>/<item>/<field>` URIs that point at a
//! single value, used by `2secret read`, `2secret inject` and `2secret run`
//! to keep secrets out of config files and environment definitions.
//!
//! * `vault` – vault name or id (may be omitted: `2s://<item>/<field>`)
//! * `item`  – item title or id
//! * `field` – field id or label, or one of the virtual fields `title`,
//!   `notes`, `url`, `username`, `password`, `otp` (current TOTP code)
//!
//! Path segments may be percent-encoded (`My%20Vault`).

use zeroize::Zeroizing;

use crate::session::Session;
use crate::totp::Totp;
use crate::{Error, Result};

pub const SCHEME: &str = "2s://";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretRef {
    pub vault: Option<String>,
    pub item: String,
    pub field: String,
}

fn decode(s: &str) -> String {
    let mut out = Vec::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

impl SecretRef {
    pub fn parse(s: &str) -> Result<Self> {
        let rest = s
            .trim()
            .strip_prefix(SCHEME)
            .ok_or_else(|| Error::invalid(format!("secret references start with {SCHEME}")))?;
        let parts: Vec<String> = rest.split('/').map(decode).collect();
        if parts.iter().any(|p| p.is_empty()) {
            return Err(Error::invalid("empty segment in secret reference"));
        }
        match parts.len() {
            2 => Ok(SecretRef {
                vault: None,
                item: parts[0].clone(),
                field: parts[1].clone(),
            }),
            3 => Ok(SecretRef {
                vault: Some(parts[0].clone()),
                item: parts[1].clone(),
                field: parts[2].clone(),
            }),
            _ => Err(Error::invalid("expected 2s://vault/item/field")),
        }
    }

    /// Resolve the reference against an unlocked session.
    pub fn resolve(&self, session: &Session) -> Result<Zeroizing<String>> {
        let vault_id = match &self.vault {
            Some(v) => Some(session.find_vault(v)?.id),
            None => None,
        };
        let item = session.find_item(&self.item, vault_id.as_deref())?;
        let value = match self.field.to_lowercase().as_str() {
            "title" => Some(item.title.clone()),
            "notes" | "notesplain" => Some(item.notes.clone()),
            "url" | "website" => item.primary_url().map(|s| s.to_string()),
            "username" => item.username().map(|s| s.to_string()),
            "password" => item.password().map(|s| s.to_string()),
            "otp" | "totp" | "one-time password" | "code" => match item.totp_secret() {
                Some(secret) => Some(Totp::parse(secret)?.now().0),
                None => None,
            },
            _ => item.field(&self.field).map(|f| f.value.clone()),
        };
        value
            .filter(|v| !v.is_empty())
            .map(Zeroizing::new)
            .ok_or_else(|| Error::not_found(format!("field '{}' in '{}'", self.field, item.title)))
    }
}

/// Resolve one reference string.
pub fn resolve(session: &Session, reference: &str) -> Result<Zeroizing<String>> {
    SecretRef::parse(reference)?.resolve(session)
}

/// Replace every `{{ 2s://... }}` in a template with the referenced value.
pub fn inject(session: &Session, template: &str) -> Result<Zeroizing<String>> {
    let mut out = Zeroizing::new(String::with_capacity(template.len()));
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        let Some(end_rel) = rest[start..].find("}}") else {
            break;
        };
        let inner = rest[start + 2..start + end_rel].trim();
        if inner.starts_with(SCHEME) {
            out.push_str(&rest[..start]);
            out.push_str(&resolve(session, inner)?);
        } else {
            out.push_str(&rest[..start + end_rel + 2]);
        }
        rest = &rest[start + end_rel + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Is this string a secret reference?
pub fn is_reference(s: &str) -> bool {
    s.trim().starts_with(SCHEME)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::Item;
    use crate::session::tests::new_session;

    #[test]
    fn parse() {
        let r = SecretRef::parse("2s://My%20Vault/GitHub/password").unwrap();
        assert_eq!(r.vault.as_deref(), Some("My Vault"));
        assert_eq!(r.item, "GitHub");
        assert_eq!(r.field, "password");
        assert_eq!(SecretRef::parse("2s://GitHub/username").unwrap().vault, None);
        assert!(SecretRef::parse("op://a/b/c").is_err());
        assert!(SecretRef::parse("2s://a//c").is_err());
        assert!(SecretRef::parse("2s://a/b/c/d").is_err());
    }

    #[test]
    fn resolve_and_inject() {
        let (mut s, _) = new_session();
        let v = s.default_vault_id().unwrap();
        let mut item = Item::login("Database", "admin", "hunter2", Some("db.local"));
        item.set_value("port", "5432");
        item.set_value("totp", "JBSWY3DPEHPK3PXP");
        s.add_item(&v, item).unwrap();
        assert_eq!(&*resolve(&s, "2s://Personal/Database/password").unwrap(), "hunter2");
        assert_eq!(&*resolve(&s, "2s://database/username").unwrap(), "admin");
        assert_eq!(&*resolve(&s, "2s://Database/port").unwrap(), "5432");
        assert_eq!(resolve(&s, "2s://Database/otp").unwrap().len(), 6);
        assert!(resolve(&s, "2s://Database/missing").is_err());
        assert!(resolve(&s, "2s://Nope/Database/password").is_err());
        let out = inject(&s, "postgres://{{ 2s://Database/username }}:{{2s://Database/password}}@db:{{ x }}").unwrap();
        assert_eq!(&*out, "postgres://admin:hunter2@db:{{ x }}");
    }
}
