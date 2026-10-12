//! The item model: logins, credit cards, identities, notes and more.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::passkey::Passkey;
use crate::util::{new_id, now, url_host};

/// Maximum size of a single attachment (before base64 encoding).
pub const MAX_ATTACHMENT_BYTES: usize = 5 * 1024 * 1024;
/// Maximum size of a serialized item (all attachments included). Encrypted
/// and encoded this stays well below the server's per-item limit.
pub const MAX_ITEM_BYTES: usize = 7 * 1024 * 1024;
/// Maximum number of remembered previous passwords per item.
pub const MAX_PASSWORD_HISTORY: usize = 50;

/// What kind of secret an item represents. Determines its default fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Login,
    Password,
    SecureNote,
    CreditCard,
    Identity,
    BankAccount,
    CryptoWallet,
    SoftwareLicense,
    SshKey,
    ApiCredential,
    Database,
    Server,
    WirelessRouter,
    EmailAccount,
    Passport,
    DriverLicense,
    Membership,
    RewardProgram,
    Document,
}

impl Zeroize for Category {
    fn zeroize(&mut self) {}
}

impl Category {
    pub const ALL: [Category; 19] = [
        Category::Login,
        Category::Password,
        Category::SecureNote,
        Category::CreditCard,
        Category::Identity,
        Category::BankAccount,
        Category::CryptoWallet,
        Category::SoftwareLicense,
        Category::SshKey,
        Category::ApiCredential,
        Category::Database,
        Category::Server,
        Category::WirelessRouter,
        Category::EmailAccount,
        Category::Passport,
        Category::DriverLicense,
        Category::Membership,
        Category::RewardProgram,
        Category::Document,
    ];

    /// Stable identifier (`login`, `credit_card`, …).
    pub fn id(&self) -> &'static str {
        match self {
            Category::Login => "login",
            Category::Password => "password",
            Category::SecureNote => "secure_note",
            Category::CreditCard => "credit_card",
            Category::Identity => "identity",
            Category::BankAccount => "bank_account",
            Category::CryptoWallet => "crypto_wallet",
            Category::SoftwareLicense => "software_license",
            Category::SshKey => "ssh_key",
            Category::ApiCredential => "api_credential",
            Category::Database => "database",
            Category::Server => "server",
            Category::WirelessRouter => "wireless_router",
            Category::EmailAccount => "email_account",
            Category::Passport => "passport",
            Category::DriverLicense => "driver_license",
            Category::Membership => "membership",
            Category::RewardProgram => "reward_program",
            Category::Document => "document",
        }
    }

    /// English display name.
    pub fn name(&self) -> &'static str {
        match self {
            Category::Login => "Login",
            Category::Password => "Password",
            Category::SecureNote => "Secure Note",
            Category::CreditCard => "Credit Card",
            Category::Identity => "Identity",
            Category::BankAccount => "Bank Account",
            Category::CryptoWallet => "Crypto Wallet",
            Category::SoftwareLicense => "Software License",
            Category::SshKey => "SSH Key",
            Category::ApiCredential => "API Credential",
            Category::Database => "Database",
            Category::Server => "Server",
            Category::WirelessRouter => "Wireless Router",
            Category::EmailAccount => "Email Account",
            Category::Passport => "Passport",
            Category::DriverLicense => "Driver License",
            Category::Membership => "Membership",
            Category::RewardProgram => "Reward Program",
            Category::Document => "Document",
        }
    }

    /// Lenient parser accepting ids, display names and common aliases.
    pub fn parse(s: &str) -> Option<Category> {
        let norm: String = s.trim().to_lowercase().chars().filter(|c| c.is_alphanumeric()).collect();
        Some(match norm.as_str() {
            "login" | "logins" | "website" | "webform" => Category::Login,
            "password" | "passwords" => Category::Password,
            "securenote" | "note" | "notes" | "securenotes" => Category::SecureNote,
            "creditcard" | "card" | "cards" => Category::CreditCard,
            "identity" | "identities" => Category::Identity,
            "bankaccount" | "bank" => Category::BankAccount,
            "cryptowallet" | "crypto" | "wallet" => Category::CryptoWallet,
            "softwarelicense" | "license" | "licence" | "software" => Category::SoftwareLicense,
            "sshkey" | "ssh" => Category::SshKey,
            "apicredential" | "api" | "apikey" | "token" => Category::ApiCredential,
            "database" | "db" => Category::Database,
            "server" => Category::Server,
            "wirelessrouter" | "router" | "wifi" | "wireless" => Category::WirelessRouter,
            "emailaccount" | "email" => Category::EmailAccount,
            "passport" => Category::Passport,
            "driverlicense" | "driverslicense" | "driverlicence" => Category::DriverLicense,
            "membership" => Category::Membership,
            "rewardprogram" | "reward" | "loyalty" => Category::RewardProgram,
            "document" | "file" => Category::Document,
            _ => return None,
        })
    }

    /// The default fields of a new item in this category.
    pub fn template(&self) -> Vec<Field> {
        use FieldKind::*;
        let f = |id: &str, label: &str, kind: FieldKind| Field::new(id, label, kind, "");
        match self {
            Category::Login => vec![
                f("username", "username", Text),
                f("password", "password", Concealed),
                f("totp", "one-time password", Totp),
            ],
            Category::Password => vec![f("password", "password", Concealed)],
            Category::SecureNote | Category::Document => vec![],
            Category::CreditCard => vec![
                f("cardholder", "cardholder name", Text),
                f("type", "type", Text),
                f("number", "number", Concealed),
                f("expiry", "expiry date", MonthYear),
                f("cvv", "verification number", Concealed),
                f("pin", "PIN", Concealed),
            ],
            Category::Identity => vec![
                f("first_name", "first name", Text),
                f("last_name", "last name", Text),
                f("birth_date", "birth date", Date),
                f("email", "email", Email),
                f("phone", "phone", Phone),
                f("address", "address", Multiline),
                f("company", "company", Text),
            ],
            Category::BankAccount => vec![
                f("bank_name", "bank name", Text),
                f("owner", "name on account", Text),
                f("iban", "IBAN", Text),
                f("bic", "BIC / SWIFT", Text),
                f("account_number", "account number", Text),
                f("pin", "PIN", Concealed),
            ],
            Category::CryptoWallet => vec![
                f("recovery_phrase", "recovery phrase", Concealed),
                f("password", "password", Concealed),
                f("wallet_address", "wallet address", Text),
                f("network", "network", Text),
            ],
            Category::SoftwareLicense => vec![
                f("license_key", "license key", Concealed),
                f("licensed_to", "licensed to", Text),
                f("registered_email", "registered email", Email),
                f("version", "version", Text),
                f("purchase_date", "purchase date", Date),
            ],
            Category::SshKey => vec![
                f("private_key", "private key", Concealed),
                f("public_key", "public key", Multiline),
                f("fingerprint", "fingerprint", Text),
                f("key_type", "key type", Text),
                f("passphrase", "passphrase", Concealed),
            ],
            Category::ApiCredential => vec![
                f("username", "username", Text),
                f("credential", "credential", Concealed),
                f("type", "type", Text),
                f("hostname", "hostname", Text),
                f("expires", "expires", Date),
            ],
            Category::Database => vec![
                f("database_type", "type", Text),
                f("server", "server", Text),
                f("port", "port", Text),
                f("database", "database", Text),
                f("username", "username", Text),
                f("password", "password", Concealed),
            ],
            Category::Server => vec![
                f("url", "URL", Url),
                f("username", "username", Text),
                f("password", "password", Concealed),
                f("hosting_provider", "hosting provider", Text),
            ],
            Category::WirelessRouter => vec![
                f("network_name", "network name", Text),
                f("wireless_password", "wireless password", Concealed),
                f("security", "security", Text),
                f("base_station_name", "base station name", Text),
                f("base_station_password", "base station password", Concealed),
                f("server_ip", "server / IP address", Text),
            ],
            Category::EmailAccount => vec![
                f("email", "email", Email),
                f("username", "username", Text),
                f("password", "password", Concealed),
                f("imap_server", "IMAP server", Text),
                f("smtp_server", "SMTP server", Text),
            ],
            Category::Passport => vec![
                f("full_name", "full name", Text),
                f("number", "number", Text),
                f("nationality", "nationality", Text),
                f("issuing_country", "issuing country", Text),
                f("date_of_birth", "date of birth", Date),
                f("issued_on", "issued on", Date),
                f("expiry_date", "expiry date", Date),
            ],
            Category::DriverLicense => vec![
                f("full_name", "full name", Text),
                f("number", "number", Text),
                f("license_class", "license class", Text),
                f("country", "country", Text),
                f("date_of_birth", "date of birth", Date),
                f("expiry_date", "expiry date", Date),
            ],
            Category::Membership => vec![
                f("group", "group", Text),
                f("member_name", "member name", Text),
                f("member_id", "member ID", Text),
                f("expiry_date", "expiry date", Date),
                f("pin", "PIN", Concealed),
            ],
            Category::RewardProgram => vec![
                f("company_name", "company name", Text),
                f("member_name", "member name", Text),
                f("member_id", "member ID", Text),
                f("pin", "PIN", Concealed),
            ],
        }
    }

    /// Does this category show website URLs by default?
    pub fn has_urls(&self) -> bool {
        matches!(self, Category::Login | Category::Password | Category::Server | Category::ApiCredential)
    }
}

/// How a field value is interpreted and displayed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    /// Plain single-line text.
    Text,
    /// Hidden by default (passwords, PINs, keys).
    Concealed,
    Email,
    Url,
    Phone,
    /// `YYYY-MM-DD`
    Date,
    /// `MM/YYYY`
    MonthYear,
    /// An `otpauth://` URI or base32 secret; displayed as a live code.
    Totp,
    /// Multi-line text.
    Multiline,
}

impl Zeroize for FieldKind {
    fn zeroize(&mut self) {}
}

impl FieldKind {
    pub const ALL: [FieldKind; 9] = [
        FieldKind::Text,
        FieldKind::Concealed,
        FieldKind::Email,
        FieldKind::Url,
        FieldKind::Phone,
        FieldKind::Date,
        FieldKind::MonthYear,
        FieldKind::Totp,
        FieldKind::Multiline,
    ];

    pub fn id(&self) -> &'static str {
        match self {
            FieldKind::Text => "text",
            FieldKind::Concealed => "concealed",
            FieldKind::Email => "email",
            FieldKind::Url => "url",
            FieldKind::Phone => "phone",
            FieldKind::Date => "date",
            FieldKind::MonthYear => "month_year",
            FieldKind::Totp => "totp",
            FieldKind::Multiline => "multiline",
        }
    }

    pub fn parse(s: &str) -> Option<FieldKind> {
        Some(match s.trim().to_lowercase().as_str() {
            "text" | "string" => FieldKind::Text,
            "concealed" | "password" | "secret" | "hidden" => FieldKind::Concealed,
            "email" => FieldKind::Email,
            "url" | "link" => FieldKind::Url,
            "phone" => FieldKind::Phone,
            "date" => FieldKind::Date,
            "month_year" | "monthyear" | "expiry" => FieldKind::MonthYear,
            "totp" | "otp" | "2fa" => FieldKind::Totp,
            "multiline" | "note" => FieldKind::Multiline,
            _ => return None,
        })
    }

    pub fn is_secret(&self) -> bool {
        matches!(self, FieldKind::Concealed | FieldKind::Totp)
    }
}

/// A single labelled value inside an item.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Field {
    /// Stable key: template fields use well known ids (`username`, `password`,
    /// `number`, …); custom fields get a random id.
    pub id: String,
    pub label: String,
    pub kind: FieldKind,
    pub value: String,
    /// Optional section heading used to group custom fields.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub section: String,
}

impl Field {
    pub fn new(id: &str, label: &str, kind: FieldKind, value: &str) -> Self {
        Self { id: id.to_string(), label: label.to_string(), kind, value: value.to_string(), section: String::new() }
    }

    /// A custom field with a random id.
    pub fn custom(label: &str, kind: FieldKind, value: &str) -> Self {
        let id = format!("custom-{}", &new_id()[..8]);
        Self::new(&id, label, kind, value)
    }

    pub fn is_custom(&self) -> bool {
        self.id.starts_with("custom-")
    }
}

/// A previous password of an item.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PasswordHistoryEntry {
    pub value: String,
    pub changed_at: i64,
}

/// A small encrypted file stored inside an item.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Attachment {
    pub id: String,
    pub name: String,
    pub mime: String,
    pub size: u64,
    /// File contents, base64 encoded.
    pub data: String,
    pub created_at: i64,
}

impl Attachment {
    pub fn new(name: &str, mime: &str, bytes: &[u8]) -> crate::Result<Self> {
        if bytes.len() > MAX_ATTACHMENT_BYTES {
            return Err(crate::Error::invalid(format!(
                "attachments are limited to {} MB",
                MAX_ATTACHMENT_BYTES / 1024 / 1024
            )));
        }
        Ok(Self {
            id: new_id(),
            name: name.to_string(),
            mime: if mime.is_empty() { "application/octet-stream".into() } else { mime.into() },
            size: bytes.len() as u64,
            data: crate::util::b64(bytes),
            created_at: now(),
        })
    }

    pub fn bytes(&self) -> crate::Result<Vec<u8>> {
        crate::util::unb64(&self.data)
    }
}

/// A decrypted vault item.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Item {
    pub id: String,
    pub category: Category,
    pub title: String,
    #[serde(default)]
    pub fields: Vec<Field>,
    #[serde(default)]
    pub urls: Vec<String>,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub favorite: bool,
    pub created_at: i64,
    pub updated_at: i64,
    /// When the primary password was last changed (Watchtower "old passwords").
    #[serde(default)]
    pub password_changed_at: Option<i64>,
    /// Set while the item is in the trash.
    #[serde(default)]
    pub trashed_at: Option<i64>,
    #[serde(default)]
    pub password_history: Vec<PasswordHistoryEntry>,
    #[serde(default)]
    pub attachments: Vec<Attachment>,
    /// Passkeys for the item's website.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub passkeys: Vec<Passkey>,
}

impl Item {
    /// A new, empty item with the category's template fields.
    pub fn new(category: Category, title: &str) -> Self {
        let ts = now();
        Self {
            id: new_id(),
            category,
            title: title.to_string(),
            fields: category.template(),
            urls: Vec::new(),
            notes: String::new(),
            tags: Vec::new(),
            favorite: false,
            created_at: ts,
            updated_at: ts,
            password_changed_at: None,
            trashed_at: None,
            password_history: Vec::new(),
            attachments: Vec::new(),
            passkeys: Vec::new(),
        }
    }

    /// Convenience constructor for a login.
    pub fn login(title: &str, username: &str, password: &str, url: Option<&str>) -> Self {
        let mut item = Item::new(Category::Login, title);
        item.set_value("username", username);
        item.set_value("password", password);
        if let Some(u) = url.filter(|u| !u.trim().is_empty()) {
            item.urls.push(u.trim().to_string());
        }
        item
    }

    /// Look a field up by id, falling back to a case-insensitive label match.
    pub fn field(&self, key: &str) -> Option<&Field> {
        self.fields.iter().find(|f| f.id == key).or_else(|| {
            let key = key.to_lowercase();
            self.fields.iter().find(|f| f.label.to_lowercase() == key)
        })
    }

    pub fn field_mut(&mut self, key: &str) -> Option<&mut Field> {
        if let Some(pos) = self.fields.iter().position(|f| f.id == key) {
            return self.fields.get_mut(pos);
        }
        let lower = key.to_lowercase();
        let pos = self.fields.iter().position(|f| f.label.to_lowercase() == lower)?;
        self.fields.get_mut(pos)
    }

    /// Non-empty value of a field.
    pub fn value(&self, key: &str) -> Option<&str> {
        self.field(key).map(|f| f.value.as_str()).filter(|v| !v.is_empty())
    }

    /// Set a field value, creating the field (from the template if possible)
    /// when it does not exist yet.
    pub fn set_value(&mut self, key: &str, value: &str) {
        if let Some(f) = self.field_mut(key) {
            f.value = value.to_string();
            return;
        }
        let template = Category::ALL.iter().flat_map(|c| c.template()).find(|f| f.id == key);
        let field = match template {
            Some(mut f) => {
                f.value = value.to_string();
                f
            }
            None => Field::new(key, &key.replace('_', " "), FieldKind::Text, value),
        };
        self.fields.push(field);
    }

    pub fn username(&self) -> Option<&str> {
        self.value("username").or_else(|| self.value("email")).or_else(|| self.value("member_id"))
    }

    /// The item's primary secret.
    pub fn password(&self) -> Option<&str> {
        self.value("password").or_else(|| self.value("wireless_password")).or_else(|| self.value("credential"))
    }

    /// The first configured one-time password secret.
    pub fn totp_secret(&self) -> Option<&str> {
        self.fields.iter().find(|f| f.kind == FieldKind::Totp && !f.value.trim().is_empty()).map(|f| f.value.as_str())
    }

    pub fn primary_url(&self) -> Option<&str> {
        self.urls.iter().map(|u| u.as_str()).find(|u| !u.trim().is_empty()).or_else(|| self.value("url"))
    }

    pub fn host(&self) -> Option<String> {
        self.primary_url().and_then(url_host)
    }

    pub fn is_trashed(&self) -> bool {
        self.trashed_at.is_some()
    }

    /// Secondary line shown under the title in lists.
    pub fn subtitle(&self) -> String {
        let pick = |keys: &[&str]| -> Option<String> { keys.iter().find_map(|k| self.value(k)).map(|s| s.to_string()) };
        let s = match self.category {
            Category::Login | Category::Server | Category::Database | Category::EmailAccount => {
                pick(&["username", "email"]).or_else(|| self.host())
            }
            Category::Password => self.host(),
            Category::CreditCard => self.value("number").map(|n| {
                let digits: String = n.chars().filter(|c| c.is_ascii_digit()).collect();
                let last4 = &digits[digits.len().saturating_sub(4)..];
                match self.value("type") {
                    Some(t) => format!("{t} •••• {last4}"),
                    None => format!("•••• {last4}"),
                }
            }),
            Category::Identity => {
                let name = [self.value("first_name"), self.value("last_name")]
                    .iter()
                    .flatten()
                    .copied()
                    .collect::<Vec<_>>()
                    .join(" ");
                if name.is_empty() {
                    pick(&["email"])
                } else {
                    Some(name)
                }
            }
            Category::BankAccount => pick(&["bank_name", "iban"]),
            Category::SecureNote => {
                self.notes.lines().find(|l| !l.trim().is_empty()).map(|l| l.chars().take(60).collect())
            }
            Category::SshKey => pick(&["key_type", "fingerprint"]),
            Category::WirelessRouter => pick(&["network_name", "base_station_name"]),
            Category::Passport | Category::DriverLicense => pick(&["full_name", "number"]),
            Category::Membership | Category::RewardProgram => pick(&["group", "company_name", "member_name"]),
            Category::Document => self.attachments.first().map(|a| a.name.clone()),
            _ => None,
        };
        s.or_else(|| {
            self.fields
                .iter()
                .find(|f| !f.kind.is_secret() && !f.value.is_empty() && f.kind != FieldKind::Multiline)
                .map(|f| f.value.clone())
        })
        .unwrap_or_default()
    }

    /// Case-insensitive search over the visible parts of the item.
    pub fn matches(&self, query: &str) -> bool {
        let q = query.trim().to_lowercase();
        if q.is_empty() {
            return true;
        }
        let hay = |s: &str| s.to_lowercase().contains(&q);
        hay(&self.title)
            || hay(&self.subtitle())
            || self.urls.iter().any(|u| hay(u))
            || self.tags.iter().any(|t| hay(t))
            || hay(&self.notes)
            || hay(self.category.name())
            || self.fields.iter().any(|f| !f.kind.is_secret() && (hay(&f.value) || hay(&f.label)))
    }

    /// Record a password change compared to `previous`, keeping history.
    pub fn track_password_change(&mut self, previous: &Item) {
        let old = previous.password().unwrap_or("").to_string();
        let new = self.password().unwrap_or("").to_string();
        if old == new {
            if self.password_changed_at.is_none() {
                self.password_changed_at = previous.password_changed_at;
            }
            return;
        }
        let ts = now();
        if !old.is_empty() && !self.password_history.iter().any(|h| h.value == old) {
            self.password_history.insert(0, PasswordHistoryEntry { value: old, changed_at: ts });
            self.password_history.truncate(MAX_PASSWORD_HISTORY);
        }
        self.password_changed_at = Some(ts);
    }

    /// Normalise user input: trim title/URLs/tags, drop empty custom fields,
    /// deduplicate tags.
    pub fn normalize(&mut self) {
        self.title = self.title.trim().to_string();
        if self.title.is_empty() {
            self.title = self.host().unwrap_or_else(|| self.category.name().to_string());
        }
        let urls: Vec<String> = self.urls.iter().map(|u| u.trim().to_string()).filter(|u| !u.is_empty()).collect();
        self.urls = urls;
        let mut tags: Vec<String> = self.tags.iter().map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect();
        tags.sort_by_key(|t| t.to_lowercase());
        tags.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
        self.tags = tags;
        self.fields.retain(|f| !(f.is_custom() && f.value.is_empty() && f.label.trim().is_empty()));
    }

    /// Check limits before saving.
    pub fn validate(&self) -> crate::Result<()> {
        let size = serde_json::to_vec(self).map(|v| v.len()).unwrap_or(usize::MAX);
        if size > MAX_ITEM_BYTES {
            return Err(crate::Error::invalid(format!(
                "this item is too large ({} MB); items including attachments are limited to {} MB",
                size / 1024 / 1024,
                MAX_ITEM_BYTES / 1024 / 1024
            )));
        }
        Ok(())
    }

    pub fn summary(&self, vault_id: &str) -> ItemSummary {
        ItemSummary {
            id: self.id.clone(),
            vault_id: vault_id.to_string(),
            category: self.category,
            title: self.title.clone(),
            subtitle: self.subtitle(),
            url: self.primary_url().map(|s| s.to_string()),
            host: self.host(),
            tags: self.tags.clone(),
            favorite: self.favorite,
            created_at: self.created_at,
            updated_at: self.updated_at,
            trashed: self.is_trashed(),
            has_totp: self.totp_secret().is_some(),
            has_password: self.password().is_some(),
        }
    }
}

/// Lightweight, non-secret view of an item for list displays.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemSummary {
    pub id: String,
    pub vault_id: String,
    pub category: Category,
    pub title: String,
    pub subtitle: String,
    pub url: Option<String>,
    pub host: Option<String>,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub created_at: i64,
    pub updated_at: i64,
    pub trashed: bool,
    pub has_totp: bool,
    pub has_password: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_and_accessors() {
        let mut item = Item::login("GitHub", "octocat", "s3cret!", Some("https://github.com/login"));
        assert_eq!(item.username(), Some("octocat"));
        assert_eq!(item.password(), Some("s3cret!"));
        assert_eq!(item.host().as_deref(), Some("github.com"));
        assert_eq!(item.subtitle(), "octocat");
        assert!(item.totp_secret().is_none());
        item.set_value("totp", "JBSWY3DPEHPK3PXP");
        assert!(item.totp_secret().is_some());
        item.set_value("Recovery codes", "a b c");
        assert_eq!(item.value("recovery codes"), Some("a b c"));
    }

    #[test]
    fn credit_card_subtitle() {
        let mut card = Item::new(Category::CreditCard, "Visa");
        card.set_value("number", "4111 1111 1111 1234");
        card.set_value("type", "Visa");
        assert_eq!(card.subtitle(), "Visa •••• 1234");
    }

    #[test]
    fn password_history() {
        let old = Item::login("x", "u", "first", None);
        let mut new = old.clone();
        new.set_value("password", "second");
        new.track_password_change(&old);
        assert_eq!(new.password_history.len(), 1);
        assert_eq!(new.password_history[0].value, "first");
        assert!(new.password_changed_at.is_some());
    }

    #[test]
    fn category_parse_and_serde() {
        for c in Category::ALL {
            assert_eq!(Category::parse(c.id()), Some(c));
            assert_eq!(Category::parse(c.name()), Some(c));
            let json = serde_json::to_string(&c).unwrap();
            assert_eq!(json, format!("\"{}\"", c.id()));
        }
        assert_eq!(Category::parse("Credit card"), Some(Category::CreditCard));
    }

    #[test]
    fn search() {
        let mut item = Item::login("Bank", "jan", "pw-not-searchable", Some("https://ing.nl"));
        item.tags.push("finance".into());
        assert!(item.matches("ing.nl"));
        assert!(item.matches("FINANCE"));
        assert!(item.matches("jan"));
        assert!(!item.matches("pw-not-searchable"));
    }

    #[test]
    fn normalize() {
        let mut item = Item::new(Category::Login, "  ");
        item.urls = vec![" https://example.com ".into(), "".into()];
        item.tags = vec!["b".into(), "A".into(), "a".into(), " ".into()];
        item.normalize();
        assert_eq!(item.title, "example.com");
        assert_eq!(item.urls, vec!["https://example.com"]);
        assert_eq!(item.tags, vec!["A", "b"]);
    }
}
