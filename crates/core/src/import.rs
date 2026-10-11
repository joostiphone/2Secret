//! Importers for other password managers.
//!
//! | Source | Format |
//! |---|---|
//! | 2Secret | `.json` export, encrypted `.json` export |
//! | 1Password | `.1pux`, `.csv` |
//! | Bitwarden / Vaultwarden | unencrypted `.json`, `.csv` |
//! | LastPass, Chrome, Edge, Brave, Firefox, Safari, Dashlane, KeePassXC, NordPass, Proton Pass | `.csv` |
//! | KeePass 2 | XML export |

use std::collections::HashMap;
use std::io::Read;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::crypto::PasswordEnvelope;
use crate::export::{ExportData, EXPORT_FORMAT};
use crate::item::{Category, Field, FieldKind, Item, PasswordHistoryEntry};
use crate::session::Session;
use crate::util::{now, parse_date, url_host};
use crate::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportFormat {
    TwoSecret,
    OnePasswordPux,
    BitwardenJson,
    KeePassXml,
    /// Any CSV file; columns are recognised by their headers.
    Csv,
}

impl ImportFormat {
    pub const ALL: [ImportFormat; 5] = [
        ImportFormat::TwoSecret,
        ImportFormat::OnePasswordPux,
        ImportFormat::BitwardenJson,
        ImportFormat::KeePassXml,
        ImportFormat::Csv,
    ];

    pub fn id(&self) -> &'static str {
        match self {
            ImportFormat::TwoSecret => "2secret",
            ImportFormat::OnePasswordPux => "1pux",
            ImportFormat::BitwardenJson => "bitwarden",
            ImportFormat::KeePassXml => "keepass",
            ImportFormat::Csv => "csv",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            ImportFormat::TwoSecret => "2Secret export (.json)",
            ImportFormat::OnePasswordPux => "1Password (.1pux)",
            ImportFormat::BitwardenJson => "Bitwarden (.json)",
            ImportFormat::KeePassXml => "KeePass 2 (.xml)",
            ImportFormat::Csv => "CSV (1Password, Bitwarden, LastPass, Chrome, Firefox, Safari, KeePassXC, …)",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim().to_lowercase();
        ImportFormat::ALL.into_iter().find(|f| f.id() == s).or(match s.as_str() {
            "1password" | "onepassword" => Some(ImportFormat::OnePasswordPux),
            "keepass2" | "kdbx-xml" | "xml" => Some(ImportFormat::KeePassXml),
            "json" => Some(ImportFormat::TwoSecret),
            "lastpass" | "chrome" | "firefox" | "safari" | "dashlane" | "keepassxc" | "edge" | "brave" => {
                Some(ImportFormat::Csv)
            }
            _ => None,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ImportedVault {
    pub name: String,
    pub items: Vec<Item>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ImportResult {
    pub source: String,
    pub vaults: Vec<ImportedVault>,
    pub warnings: Vec<String>,
}

impl ImportResult {
    pub fn item_count(&self) -> usize {
        self.vaults.iter().map(|v| v.items.len()).sum()
    }
}

/// Guess the format from the file name and contents.
pub fn detect(filename: &str, data: &[u8]) -> Option<ImportFormat> {
    let lower = filename.to_lowercase();
    if lower.ends_with(".1pux") || data.starts_with(b"PK\x03\x04") {
        return Some(ImportFormat::OnePasswordPux);
    }
    let head = String::from_utf8_lossy(&data[..data.len().min(4096)]);
    let trimmed = head.trim_start_matches('\u{feff}').trim_start();
    if trimmed.starts_with('<') {
        return Some(ImportFormat::KeePassXml);
    }
    if trimmed.starts_with('{') {
        if head.contains(EXPORT_FORMAT) || head.contains("2secret-encrypted") {
            return Some(ImportFormat::TwoSecret);
        }
        if head.contains("\"items\"") || head.contains("\"encrypted\"") || head.contains("\"folders\"") {
            return Some(ImportFormat::BitwardenJson);
        }
        return Some(ImportFormat::TwoSecret);
    }
    if lower.ends_with(".csv") || trimmed.lines().next().is_some_and(|l| l.contains(',')) {
        return Some(ImportFormat::Csv);
    }
    None
}

/// Parse an export file of another password manager.
pub fn import(data: &[u8], format: ImportFormat, password: Option<&str>) -> Result<ImportResult> {
    let mut result = match format {
        ImportFormat::TwoSecret => import_2secret(data, password)?,
        ImportFormat::OnePasswordPux => import_1pux(data)?,
        ImportFormat::BitwardenJson => import_bitwarden(data)?,
        ImportFormat::KeePassXml => import_keepass_xml(data)?,
        ImportFormat::Csv => import_csv(data)?,
    };
    for v in &mut result.vaults {
        for item in &mut v.items {
            item.normalize();
            if item.created_at == 0 {
                item.created_at = now();
            }
            if item.updated_at == 0 {
                item.updated_at = item.created_at;
            }
        }
    }
    result.vaults.retain(|v| !v.items.is_empty());
    Ok(result)
}

fn text(data: &[u8]) -> Result<String> {
    let s = String::from_utf8(data.to_vec())
        .or_else(|_| Ok::<String, Error>(String::from_utf8_lossy(data).into_owned()))?;
    Ok(s.trim_start_matches('\u{feff}').to_string())
}

// ---------------------------------------------------------------------------
// 2Secret
// ---------------------------------------------------------------------------

fn import_2secret(data: &[u8], password: Option<&str>) -> Result<ImportResult> {
    let s = text(data)?;
    let json: zeroize::Zeroizing<String> = if PasswordEnvelope::is_envelope(&s) {
        let env: PasswordEnvelope = serde_json::from_str(&s)?;
        let pw = password.ok_or_else(|| Error::invalid("this export is encrypted; a password is required"))?;
        let plain = env.open(pw)?;
        zeroize::Zeroizing::new(String::from_utf8(plain.to_vec()).map_err(|_| Error::Decryption)?)
    } else {
        zeroize::Zeroizing::new(s)
    };
    let export: ExportData = serde_json::from_str(&json)?;
    if export.format != EXPORT_FORMAT {
        return Err(Error::Unsupported("not a 2Secret export".into()));
    }
    Ok(ImportResult {
        source: "2Secret".into(),
        vaults: export.vaults.into_iter().map(|v| ImportedVault { name: v.name, items: v.items }).collect(),
        warnings: vec![],
    })
}

// ---------------------------------------------------------------------------
// Generic CSV
// ---------------------------------------------------------------------------

fn norm_header(h: &str) -> String {
    h.trim().trim_start_matches('\u{feff}').to_lowercase().chars().filter(|c| c.is_alphanumeric()).collect()
}

fn find_col(headers: &[String], names: &[&str]) -> Option<usize> {
    names.iter().find_map(|n| headers.iter().position(|h| h == n))
}

fn import_csv(data: &[u8]) -> Result<ImportResult> {
    let s = text(data)?;
    let mut reader = csv::ReaderBuilder::new().flexible(true).has_headers(true).from_reader(s.as_bytes());
    let headers: Vec<String> =
        reader.headers().map_err(|e| Error::Import(e.to_string()))?.iter().map(norm_header).collect();

    let col = |names: &[&str]| find_col(&headers, names);
    let c_title = col(&["title", "name", "itemname", "account", "entry", "accountname"]);
    let c_url = col(&["url", "loginuri", "website", "uri", "loginurl", "urls", "web", "hostname"]);
    let c_user = col(&["username", "loginusername", "user", "login", "username1", "usernamefield"]);
    let c_email = col(&["email", "emailaddress"]);
    let c_pass = col(&["password", "loginpassword", "pass"]);
    let c_notes = col(&["notes", "note", "extra", "comments", "comment", "notesplain"]);
    let c_totp = col(&["totp", "logintotp", "otpauth", "otp", "onetimepassword", "otpsecret", "otpurl", "2fa"]);
    let c_folder = col(&["folder", "grouping", "group", "vault", "groupname"]);
    let c_fav = col(&["favorite", "fav", "favourite"]);
    let c_tags = col(&["tags", "tag", "labels"]);
    let c_type = col(&["type", "category", "itemtype"]);
    let c_fields = col(&["fields", "customfields"]);
    let c_archived = col(&["archived"]);
    let c_created = col(&["timecreated", "created", "createdat", "creationtime"]);
    let c_pw_changed = col(&["timepasswordchanged", "passwordmodified", "lastmodified", "modified"]);

    if c_pass.is_none() && c_notes.is_none() && c_url.is_none() {
        return Err(Error::Import("unrecognised CSV: no password, url or notes column found".into()));
    }

    let source = if headers.contains(&"loginuri".to_string()) {
        "Bitwarden CSV"
    } else if headers.contains(&"grouping".to_string()) {
        "LastPass CSV"
    } else if headers.contains(&"httprealm".to_string()) {
        "Firefox CSV"
    } else if headers.contains(&"otpauth".to_string()) && headers.contains(&"archived".to_string()) {
        "1Password CSV"
    } else {
        "CSV"
    };

    let mut vaults: Vec<ImportedVault> = vec![ImportedVault { name: "Imported".into(), items: vec![] }];
    let mut warnings = Vec::new();
    for (line, record) in reader.records().enumerate() {
        let record = match record {
            Ok(r) => r,
            Err(e) => {
                warnings.push(format!("row {}: {e}", line + 2));
                continue;
            }
        };
        let get = |c: Option<usize>| -> String {
            c.and_then(|i| record.get(i)).map(|s| s.trim().to_string()).unwrap_or_default()
        };
        let (title, url, user, email, pass, notes, totp) =
            (get(c_title), get(c_url), get(c_user), get(c_email), get(c_pass), get(c_notes), get(c_totp));
        if [&title, &url, &user, &pass, &notes, &totp].iter().all(|s| s.is_empty()) {
            continue;
        }
        if url.starts_with("chrome://") {
            continue; // Firefox internal entries
        }
        let kind = get(c_type).to_lowercase();
        let lastpass_note = url == "http://sn";
        let category = if kind == "note" || kind == "securenote" || kind == "secure note" || lastpass_note {
            Category::SecureNote
        } else if let Some(c) = Category::parse(&kind).filter(|c| *c != Category::Login && *c != Category::Password) {
            c
        } else if pass.is_empty() && user.is_empty() && url.is_empty() && !notes.is_empty() {
            Category::SecureNote
        } else {
            Category::Login
        };
        let title = if !title.is_empty() { title } else { url_host(&url).unwrap_or_else(|| "Untitled".into()) };
        let mut item = Item::new(category, &title);
        if category == Category::Login {
            item.set_value("username", if user.is_empty() { &email } else { &user });
            item.set_value("password", &pass);
            if !totp.is_empty() {
                item.set_value("totp", &totp);
            }
            if !user.is_empty() && !email.is_empty() && email != user {
                item.fields.push(Field::new("email", "email", FieldKind::Email, &email));
            }
        } else if !pass.is_empty() {
            item.fields.push(Field::new("password", "password", FieldKind::Concealed, &pass));
        }
        if !url.is_empty() && !lastpass_note {
            for u in url.split(['\n', ' ']).filter(|u| !u.trim().is_empty()) {
                item.urls.push(u.trim().to_string());
            }
            if url.contains(',') && !url.contains("://") {
                item.urls = url.split(',').map(|u| u.trim().to_string()).collect();
            }
        }
        item.notes = notes;
        let fav = get(c_fav).to_lowercase();
        item.favorite = matches!(fav.as_str(), "1" | "true" | "yes" | "y");
        let mut tags: Vec<String> =
            get(c_tags).split([',', ';']).map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect();
        let folder = get(c_folder);
        if !folder.is_empty() {
            tags.push(folder.replace('\\', "/"));
        }
        if matches!(get(c_archived).to_lowercase().as_str(), "true" | "1" | "yes") {
            tags.push("archived".into());
        }
        item.tags = tags;
        for line in get(c_fields).lines() {
            if let Some((k, v)) = line.split_once(':') {
                if !k.trim().is_empty() && !v.trim().is_empty() {
                    item.fields.push(Field::custom(k.trim(), FieldKind::Text, v.trim()));
                }
            }
        }
        if let Some(ts) = parse_date(&get(c_created)) {
            item.created_at = ts;
        }
        if let Some(ts) = parse_date(&get(c_pw_changed)) {
            item.password_changed_at = Some(ts);
            item.updated_at = ts;
        }
        vaults[0].items.push(item);
    }
    Ok(ImportResult { source: source.into(), vaults, warnings })
}

// ---------------------------------------------------------------------------
// Bitwarden JSON
// ---------------------------------------------------------------------------

fn s(v: &Value, key: &str) -> String {
    match v.get(key) {
        Some(Value::String(s)) => s.trim().to_string(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

fn import_bitwarden(data: &[u8]) -> Result<ImportResult> {
    let root: Value = serde_json::from_slice(data)?;
    if root.get("encrypted").and_then(Value::as_bool) == Some(true) {
        return Err(Error::Unsupported(
            "encrypted Bitwarden exports cannot be read; export as unencrypted JSON".into(),
        ));
    }
    let folders: HashMap<String, String> = root
        .get("folders")
        .and_then(Value::as_array)
        .map(|a| a.iter().map(|f| (s(f, "id"), s(f, "name"))).collect())
        .unwrap_or_default();
    let mut items = Vec::new();
    let mut warnings = Vec::new();
    for bw in root.get("items").and_then(Value::as_array).cloned().unwrap_or_default() {
        let kind = bw.get("type").and_then(Value::as_i64).unwrap_or(1);
        let category = match kind {
            1 => Category::Login,
            2 => Category::SecureNote,
            3 => Category::CreditCard,
            4 => Category::Identity,
            5 => Category::SshKey,
            _ => {
                warnings.push(format!("skipped unsupported item type {kind}: {}", s(&bw, "name")));
                continue;
            }
        };
        let mut item = Item::new(category, &s(&bw, "name"));
        item.notes = s(&bw, "notes");
        item.favorite = bw.get("favorite").and_then(Value::as_bool).unwrap_or(false);
        if let Some(name) = folders.get(&s(&bw, "folderId")) {
            item.tags.push(name.clone());
        }
        if let Some(ts) = parse_date(&s(&bw, "creationDate")) {
            item.created_at = ts;
        }
        if let Some(ts) = parse_date(&s(&bw, "revisionDate")) {
            item.updated_at = ts;
        }
        match category {
            Category::Login => {
                let login = bw.get("login").cloned().unwrap_or(Value::Null);
                item.set_value("username", &s(&login, "username"));
                item.set_value("password", &s(&login, "password"));
                item.set_value("totp", &s(&login, "totp"));
                if let Some(ts) = parse_date(&s(&login, "passwordRevisionDate")) {
                    item.password_changed_at = Some(ts);
                }
                for uri in login.get("uris").and_then(Value::as_array).cloned().unwrap_or_default() {
                    let u = s(&uri, "uri");
                    if !u.is_empty() {
                        item.urls.push(u);
                    }
                }
            }
            Category::CreditCard => {
                let card = bw.get("card").cloned().unwrap_or(Value::Null);
                item.set_value("cardholder", &s(&card, "cardholderName"));
                item.set_value("type", &s(&card, "brand"));
                item.set_value("number", &s(&card, "number"));
                item.set_value("cvv", &s(&card, "code"));
                let (m, y) = (s(&card, "expMonth"), s(&card, "expYear"));
                if !m.is_empty() && !y.is_empty() {
                    item.set_value("expiry", &format!("{:0>2}/{}", m, y));
                }
            }
            Category::Identity => {
                let id = bw.get("identity").cloned().unwrap_or(Value::Null);
                item.set_value("first_name", &s(&id, "firstName"));
                item.set_value("last_name", &s(&id, "lastName"));
                item.set_value("email", &s(&id, "email"));
                item.set_value("phone", &s(&id, "phone"));
                item.set_value("company", &s(&id, "company"));
                let address: Vec<String> = ["address1", "address2", "address3"]
                    .iter()
                    .map(|k| s(&id, k))
                    .chain([format!("{} {}", s(&id, "postalCode"), s(&id, "city")).trim().to_string()])
                    .chain([s(&id, "state"), s(&id, "country")])
                    .filter(|l| !l.is_empty())
                    .collect();
                item.set_value("address", &address.join("\n"));
                for (k, label) in [
                    ("username", "username"),
                    ("ssn", "social security number"),
                    ("passportNumber", "passport number"),
                    ("licenseNumber", "license number"),
                ] {
                    let v = s(&id, k);
                    if !v.is_empty() {
                        item.fields.push(Field::custom(label, FieldKind::Text, &v));
                    }
                }
            }
            Category::SshKey => {
                let key = bw.get("sshKey").cloned().unwrap_or(Value::Null);
                item.set_value("private_key", &s(&key, "privateKey"));
                item.set_value("public_key", &s(&key, "publicKey"));
                item.set_value("fingerprint", &s(&key, "keyFingerprint"));
            }
            _ => {}
        }
        for f in bw.get("fields").and_then(Value::as_array).cloned().unwrap_or_default() {
            let kind = match f.get("type").and_then(Value::as_i64).unwrap_or(0) {
                1 => FieldKind::Concealed,
                _ => FieldKind::Text,
            };
            let (name, value) = (s(&f, "name"), s(&f, "value"));
            if !name.is_empty() || !value.is_empty() {
                item.fields.push(Field::custom(&name, kind, &value));
            }
        }
        for h in bw.get("passwordHistory").and_then(Value::as_array).cloned().unwrap_or_default() {
            let pw = s(&h, "password");
            if !pw.is_empty() {
                item.password_history.push(PasswordHistoryEntry {
                    value: pw,
                    changed_at: parse_date(&s(&h, "lastUsedDate")).unwrap_or(0),
                });
            }
        }
        items.push(item);
    }
    Ok(ImportResult {
        source: "Bitwarden".into(),
        vaults: vec![ImportedVault { name: "Bitwarden".into(), items }],
        warnings,
    })
}

// ---------------------------------------------------------------------------
// 1Password 1PUX
// ---------------------------------------------------------------------------

fn category_from_1password(uuid: &str) -> Category {
    match uuid {
        "001" => Category::Login,
        "002" => Category::CreditCard,
        "003" => Category::SecureNote,
        "004" => Category::Identity,
        "005" => Category::Password,
        "006" => Category::Document,
        "100" => Category::SoftwareLicense,
        "101" => Category::BankAccount,
        "102" => Category::Database,
        "103" => Category::DriverLicense,
        "105" => Category::Membership,
        "106" => Category::Passport,
        "107" => Category::RewardProgram,
        "109" => Category::WirelessRouter,
        "110" => Category::Server,
        "111" => Category::EmailAccount,
        "112" => Category::ApiCredential,
        "114" => Category::SshKey,
        "115" => Category::CryptoWallet,
        _ => Category::SecureNote,
    }
}

/// Map 1Password field ids onto 2Secret template field ids.
fn map_1password_field(category: Category, id: &str) -> Option<&'static str> {
    Some(match (category, id) {
        (Category::CreditCard, "cardholder") => "cardholder",
        (Category::CreditCard, "type") => "type",
        (Category::CreditCard, "ccnum") => "number",
        (Category::CreditCard, "cvv") => "cvv",
        (Category::CreditCard, "expiry") => "expiry",
        (Category::CreditCard, "pin") => "pin",
        (Category::Identity, "firstname") => "first_name",
        (Category::Identity, "lastname") => "last_name",
        (Category::Identity, "birthdate") => "birth_date",
        (Category::Identity, "email") => "email",
        (Category::Identity, "defphone") => "phone",
        (Category::Identity, "address") => "address",
        (Category::Identity, "company") => "company",
        (Category::BankAccount, "bankName") => "bank_name",
        (Category::BankAccount, "owner") => "owner",
        (Category::BankAccount, "iban") => "iban",
        (Category::BankAccount, "swift") => "bic",
        (Category::BankAccount, "accountNo") => "account_number",
        (Category::BankAccount, "telephonePin") => "pin",
        (Category::SoftwareLicense, "reg_code") => "license_key",
        (Category::SoftwareLicense, "reg_name") => "licensed_to",
        (Category::SoftwareLicense, "reg_email") => "registered_email",
        (Category::SoftwareLicense, "product_version") => "version",
        (Category::Database, "database_type") => "database_type",
        (Category::Database, "hostname") => "server",
        (Category::Database, "port") => "port",
        (Category::Database, "database") => "database",
        (Category::Database, "username") => "username",
        (Category::Database, "password") => "password",
        (Category::Server, "url") => "url",
        (Category::Server, "username") => "username",
        (Category::Server, "password") => "password",
        (Category::WirelessRouter, "network_name") => "network_name",
        (Category::WirelessRouter, "wireless_password") => "wireless_password",
        (Category::WirelessRouter, "wireless_security") => "security",
        (Category::WirelessRouter, "name") => "base_station_name",
        (Category::WirelessRouter, "password") => "base_station_password",
        (Category::WirelessRouter, "server") => "server_ip",
        (Category::ApiCredential, "username") => "username",
        (Category::ApiCredential, "credential") => "credential",
        (Category::ApiCredential, "type") => "type",
        (Category::ApiCredential, "hostname") => "hostname",
        (Category::ApiCredential, "expires") => "expires",
        (Category::EmailAccount, "pop_username") => "username",
        (Category::EmailAccount, "pop_password") => "password",
        (Category::EmailAccount, "pop_server") => "imap_server",
        (Category::EmailAccount, "smtp_server") => "smtp_server",
        (Category::Passport, "fullname") => "full_name",
        (Category::Passport, "number") => "number",
        (Category::Passport, "nationality") => "nationality",
        (Category::Passport, "issuing_country") => "issuing_country",
        (Category::Passport, "birthdate") => "date_of_birth",
        (Category::Passport, "issue_date") => "issued_on",
        (Category::Passport, "expiry_date") => "expiry_date",
        (Category::DriverLicense, "fullname") => "full_name",
        (Category::DriverLicense, "number") => "number",
        (Category::DriverLicense, "class") => "license_class",
        (Category::DriverLicense, "country") => "country",
        (Category::DriverLicense, "birthdate") => "date_of_birth",
        (Category::DriverLicense, "expiry_date") => "expiry_date",
        (Category::Membership, "org_name") => "group",
        (Category::Membership, "member_name") => "member_name",
        (Category::Membership, "membership_no") => "member_id",
        (Category::Membership, "expiry_date") => "expiry_date",
        (Category::Membership, "pin") => "pin",
        (Category::RewardProgram, "company_name") => "company_name",
        (Category::RewardProgram, "member_name") => "member_name",
        (Category::RewardProgram, "membership_no") => "member_id",
        (Category::RewardProgram, "pin") => "pin",
        (Category::CryptoWallet, "recoveryPhrase") => "recovery_phrase",
        (Category::CryptoWallet, "password") => "password",
        (Category::CryptoWallet, "walletAddress") => "wallet_address",
        (_, "password") => "password",
        (_, "username") => "username",
        _ => return None,
    })
}

/// Convert a 1PUX field value object into (kind, text).
fn onepux_value(value: &Value) -> Option<(FieldKind, String)> {
    let obj = value.as_object()?;
    let (k, v) = obj.iter().next()?;
    let str_of = |v: &Value| v.as_str().map(|s| s.to_string()).unwrap_or_default();
    Some(match k.as_str() {
        "concealed" | "creditCardNumber" => (FieldKind::Concealed, str_of(v)),
        "totp" => (FieldKind::Totp, str_of(v)),
        "url" => (FieldKind::Url, str_of(v)),
        "phone" => (FieldKind::Phone, str_of(v)),
        "email" => (FieldKind::Email, v.get("email_address").map(str_of).unwrap_or_else(|| str_of(v))),
        "date" => {
            let ts = v.as_i64()?;
            (FieldKind::Date, crate::util::format_date(ts))
        }
        "monthYear" => {
            let n = v.as_i64()?;
            (FieldKind::MonthYear, format!("{:02}/{}", n % 100, n / 100))
        }
        "address" => {
            let parts: Vec<String> = ["street", "city", "zip", "state", "country"]
                .iter()
                .filter_map(|k| v.get(*k).and_then(Value::as_str))
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect();
            (FieldKind::Multiline, parts.join("\n"))
        }
        "sshKey" => (FieldKind::Concealed, v.get("privateKey").map(str_of).unwrap_or_default()),
        "file" | "reference" => return None,
        _ => match v {
            Value::String(s) => (FieldKind::Text, s.clone()),
            Value::Number(n) => (FieldKind::Text, n.to_string()),
            Value::Bool(b) => (FieldKind::Text, b.to_string()),
            _ => return None,
        },
    })
}

fn import_1pux(data: &[u8]) -> Result<ImportResult> {
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(data))
        .map_err(|e| Error::Import(format!("not a valid .1pux file: {e}")))?;
    let mut json = String::new();
    zip.by_name("export.data")
        .map_err(|_| Error::Import("export.data missing from .1pux file".into()))?
        .read_to_string(&mut json)?;
    let root: Value = serde_json::from_str(&json)?;
    let mut vaults = Vec::new();
    let mut warnings = Vec::new();
    for account in root.get("accounts").and_then(Value::as_array).cloned().unwrap_or_default() {
        for vault in account.get("vaults").and_then(Value::as_array).cloned().unwrap_or_default() {
            let name = vault
                .get("attrs")
                .map(|a| s(a, "name"))
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| "1Password".into());
            let mut out = ImportedVault { name, items: vec![] };
            for op in vault.get("items").and_then(Value::as_array).cloned().unwrap_or_default() {
                match convert_1pux_item(&op) {
                    Some(item) => out.items.push(item),
                    None => warnings.push(format!("skipped an unreadable item in vault '{}'", out.name)),
                }
            }
            vaults.push(out);
        }
    }
    Ok(ImportResult { source: "1Password".into(), vaults, warnings })
}

fn convert_1pux_item(op: &Value) -> Option<Item> {
    let overview = op.get("overview")?;
    let details = op.get("details").cloned().unwrap_or(Value::Null);
    let category = category_from_1password(&s(op, "categoryUuid"));
    let mut item = Item::new(category, &s(overview, "title"));
    // Start from an empty template: 1Password provides the fields.
    item.fields.clear();
    item.favorite = op.get("favIndex").and_then(Value::as_i64).unwrap_or(0) > 0;
    item.created_at = op.get("createdAt").and_then(Value::as_i64).unwrap_or(0);
    item.updated_at = op.get("updatedAt").and_then(Value::as_i64).unwrap_or(0);
    if s(op, "state") == "archived" {
        item.tags.push("archived".into());
    }
    for t in overview.get("tags").and_then(Value::as_array).cloned().unwrap_or_default() {
        if let Some(t) = t.as_str() {
            item.tags.push(t.to_string());
        }
    }
    let mut urls: Vec<String> = overview
        .get("urls")
        .and_then(Value::as_array)
        .map(|a| a.iter().map(|u| s(u, "url")).filter(|u| !u.is_empty()).collect())
        .unwrap_or_default();
    let main = s(overview, "url");
    if !main.is_empty() && !urls.contains(&main) {
        urls.insert(0, main);
    }
    item.urls = urls;
    item.notes = s(&details, "notesPlain");

    for lf in details.get("loginFields").and_then(Value::as_array).cloned().unwrap_or_default() {
        let value = s(&lf, "value");
        match s(&lf, "designation").as_str() {
            "username" => item.set_value("username", &value),
            "password" => item.set_value("password", &value),
            _ => {}
        }
    }
    let pw = s(&details, "password");
    if !pw.is_empty() {
        item.set_value("password", &pw);
    }
    for section in details.get("sections").and_then(Value::as_array).cloned().unwrap_or_default() {
        let section_title = s(&section, "title");
        for f in section.get("fields").and_then(Value::as_array).cloned().unwrap_or_default() {
            let Some((kind, value)) = f.get("value").and_then(onepux_value) else {
                continue;
            };
            if value.is_empty() {
                continue;
            }
            let id = s(&f, "id");
            let label = s(&f, "title");
            if kind == FieldKind::Totp && item.value("totp").is_none() {
                item.fields.push(Field::new("totp", "one-time password", FieldKind::Totp, &value));
                continue;
            }
            match map_1password_field(category, &id) {
                Some(key) if item.value(key).is_none() => item.set_value(key, &value),
                _ => {
                    let mut field = Field::custom(if label.is_empty() { &id } else { &label }, kind, &value);
                    field.section = section_title.clone();
                    item.fields.push(field);
                }
            }
        }
    }
    // Make sure the template fields exist (empty) for a familiar editor.
    for t in category.template() {
        if item.field(&t.id).is_none() {
            item.fields.push(t);
        }
    }
    for h in details.get("passwordHistory").and_then(Value::as_array).cloned().unwrap_or_default() {
        let v = s(&h, "value");
        if !v.is_empty() {
            item.password_history.push(PasswordHistoryEntry {
                value: v,
                changed_at: h.get("time").and_then(Value::as_i64).unwrap_or(0),
            });
        }
    }
    Some(item)
}

// ---------------------------------------------------------------------------
// KeePass 2 XML
// ---------------------------------------------------------------------------

fn import_keepass_xml(data: &[u8]) -> Result<ImportResult> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let s = text(data)?;
    let mut reader = Reader::from_str(&s);
    reader.config_mut().trim_text(true);

    let mut items = Vec::new();
    let mut groups: Vec<String> = Vec::new();
    let mut path: Vec<String> = Vec::new();
    let mut entry: Option<Vec<(String, String)>> = None;
    let mut cur_key = String::new();
    let mut cur_value = String::new();
    let mut in_history = 0usize;
    let mut recycle_bin_depth: Option<usize> = None;
    let mut buf_text = String::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                path.push(name.clone());
                buf_text.clear();
                match name.as_str() {
                    "Group" => groups.push(String::new()),
                    "Entry" if in_history == 0 => entry = Some(Vec::new()),
                    "History" => in_history += 1,
                    "String" => {
                        cur_key.clear();
                        cur_value.clear();
                    }
                    _ => {}
                }
            }
            Ok(Event::Empty(e)) => {
                let _ = e;
            }
            Ok(Event::Text(t)) => {
                buf_text.push_str(&t.unescape().map(|c| c.into_owned()).unwrap_or_default());
            }
            Ok(Event::CData(t)) => {
                buf_text.push_str(&String::from_utf8_lossy(&t.into_inner()));
            }
            Ok(Event::End(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                let parent = path.len().checked_sub(2).and_then(|i| path.get(i)).cloned();
                match name.as_str() {
                    "Name" if parent.as_deref() == Some("Group") => {
                        if let Some(g) = groups.last_mut() {
                            *g = buf_text.clone();
                        }
                        if buf_text == "Recycle Bin" && recycle_bin_depth.is_none() {
                            recycle_bin_depth = Some(groups.len());
                        }
                    }
                    "Key" if parent.as_deref() == Some("String") => cur_key = buf_text.clone(),
                    "Value" if parent.as_deref() == Some("String") => cur_value = buf_text.clone(),
                    "String" => {
                        if in_history == 0 {
                            if let Some(e) = entry.as_mut() {
                                e.push((cur_key.clone(), cur_value.clone()));
                            }
                        }
                    }
                    "History" => in_history = in_history.saturating_sub(1),
                    "Entry" if in_history == 0 => {
                        if let Some(fields) = entry.take() {
                            if recycle_bin_depth.is_none() {
                                // Skip the root group name in the tag path.
                                let tag = groups
                                    .iter()
                                    .skip(1)
                                    .filter(|g| !g.is_empty())
                                    .cloned()
                                    .collect::<Vec<_>>()
                                    .join("/");
                                items.push(keepass_entry_to_item(fields, &tag));
                            }
                        }
                    }
                    "Group" => {
                        if recycle_bin_depth == Some(groups.len()) {
                            recycle_bin_depth = None;
                        }
                        groups.pop();
                    }
                    _ => {}
                }
                path.pop();
                buf_text.clear();
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(Error::Import(format!("invalid KeePass XML: {e}"))),
            _ => {}
        }
    }
    Ok(ImportResult {
        source: "KeePass".into(),
        vaults: vec![ImportedVault { name: "KeePass".into(), items }],
        warnings: vec![],
    })
}

fn keepass_entry_to_item(fields: Vec<(String, String)>, tag: &str) -> Item {
    let get = |k: &str| fields.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone()).unwrap_or_default();
    let title = get("Title");
    let (user, pass, url, notes) = (get("UserName"), get("Password"), get("URL"), get("Notes"));
    let category = if user.is_empty() && pass.is_empty() && url.is_empty() && !notes.is_empty() {
        Category::SecureNote
    } else {
        Category::Login
    };
    let mut item = Item::new(category, &title);
    if category == Category::Login {
        item.set_value("username", &user);
        item.set_value("password", &pass);
    }
    if !url.is_empty() {
        item.urls.push(url);
    }
    item.notes = notes;
    if !tag.is_empty() {
        item.tags.push(tag.to_string());
    }
    for (k, v) in &fields {
        if v.is_empty() || ["Title", "UserName", "Password", "URL", "Notes"].contains(&k.as_str()) {
            continue;
        }
        if k == "otp" || k == "TOTP Seed" || k.eq_ignore_ascii_case("totp") {
            item.set_value("totp", v);
        } else if k == "TOTP Settings" {
            continue;
        } else {
            item.fields.push(Field::custom(k, FieldKind::Text, v));
        }
    }
    item
}

// ---------------------------------------------------------------------------
// Adding imported data to a session
// ---------------------------------------------------------------------------

/// Summary of an import into the session.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportSummary {
    pub imported: usize,
    pub skipped_duplicates: usize,
    pub vaults_created: usize,
}

fn fingerprint(item: &Item) -> String {
    format!(
        "{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}",
        item.title.to_lowercase(),
        item.username().unwrap_or(""),
        item.password().unwrap_or(""),
        item.primary_url().unwrap_or(""),
        item.notes
    )
}

impl Session {
    /// Add imported items. With `target_vault` everything goes into that vault;
    /// otherwise each source vault is matched by name or created.
    /// Items identical to an existing item are skipped.
    pub fn import(&mut self, result: ImportResult, target_vault: Option<&str>) -> Result<ImportSummary> {
        let mut summary = ImportSummary::default();
        for source in result.vaults {
            let vault_id = match target_vault {
                Some(v) => self.find_vault(v)?.id,
                None => match self.find_vault(&source.name) {
                    Ok(v) if v.role.can_write() => v.id,
                    _ => {
                        summary.vaults_created += 1;
                        self.create_vault(&source.name, "Imported")?
                    }
                },
            };
            let mut existing: std::collections::HashSet<String> =
                self.all_items().filter(|(v, _)| *v == vault_id).map(|(_, i)| fingerprint(i)).collect();
            for mut item in source.items {
                let fp = fingerprint(&item);
                if existing.contains(&fp) {
                    summary.skipped_duplicates += 1;
                    continue;
                }
                existing.insert(fp);
                let created = item.created_at;
                let updated = item.updated_at;
                let pw_changed = item.password_changed_at;
                item.id = String::new();
                let id = self.add_item(&vault_id, item)?;
                // Preserve original timestamps where known.
                if let Some(mut stored) = self.item(&id).cloned() {
                    if created > 0 {
                        stored.created_at = created;
                    }
                    stored.password_changed_at = pw_changed.or(stored.password_changed_at);
                    let _ = updated;
                    self.restore_timestamps(stored)?;
                }
                summary.imported += 1;
            }
        }
        Ok(summary)
    }

    fn restore_timestamps(&mut self, item: Item) -> Result<()> {
        let vault =
            self.item_vault(&item.id).map(|s| s.to_string()).ok_or_else(|| Error::not_found(item.id.clone()))?;
        let data = self.encrypt_item(&vault, &item)?;
        if let Some(rec) = self.profile_mut().item_mut(&item.id) {
            rec.data = Some(data);
        }
        self.reload()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::tests::new_session;

    #[test]
    fn csv_variants() {
        let chrome = "name,url,username,password,note\nGitHub,https://github.com/login,octo,pw1,\n";
        let r = import(chrome.as_bytes(), ImportFormat::Csv, None).unwrap();
        assert_eq!(r.item_count(), 1);
        let i = &r.vaults[0].items[0];
        assert_eq!(i.title, "GitHub");
        assert_eq!(i.password(), Some("pw1"));

        let firefox = "\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\",\"timeLastUsed\",\"timePasswordChanged\"\n\"https://www.mozilla.org\",\"me\",\"fx\",,\"\",\"{x}\",\"1700000000000\",\"1700000000000\",\"1700000000000\"\n\"chrome://FirefoxAccounts\",\"a\",\"b\",,,,,,\n";
        let r = import(firefox.as_bytes(), ImportFormat::Csv, None).unwrap();
        assert_eq!(r.source, "Firefox CSV");
        assert_eq!(r.item_count(), 1);
        assert_eq!(r.vaults[0].items[0].title, "mozilla.org");
        assert_eq!(r.vaults[0].items[0].password_changed_at, Some(1_700_000_000));

        let lastpass = "url,username,password,totp,extra,name,grouping,fav\nhttp://sn,,,,my secret note,Note,Personal,0\nhttps://x.com,u,p,JBSWY3DPEHPK3PXP,,X,Social,1\n";
        let r = import(lastpass.as_bytes(), ImportFormat::Csv, None).unwrap();
        assert_eq!(r.source, "LastPass CSV");
        let items = &r.vaults[0].items;
        assert_eq!(items[0].category, Category::SecureNote);
        assert_eq!(items[0].notes, "my secret note");
        assert!(items[1].favorite);
        assert!(items[1].totp_secret().is_some());
        assert_eq!(items[1].tags, vec!["Social"]);

        let bw = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\nWork,1,login,Jira,,\"Team: blue\",0,https://jira.example.com,me,pw,\n,,note,Wifi,the code is 1234,,0,,,,\n";
        let r = import(bw.as_bytes(), ImportFormat::Csv, None).unwrap();
        assert_eq!(r.source, "Bitwarden CSV");
        let items = &r.vaults[0].items;
        assert_eq!(items[0].value("team"), Some("blue"));
        assert_eq!(items[1].category, Category::SecureNote);

        let op = "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\nAmazon,https://amazon.nl,me,pw,,true,false,\"shopping,nl\",\n";
        let r = import(op.as_bytes(), ImportFormat::Csv, None).unwrap();
        assert_eq!(r.source, "1Password CSV");
        assert_eq!(r.vaults[0].items[0].tags, vec!["nl", "shopping"]);

        assert!(import(b"a,b\n1,2\n", ImportFormat::Csv, None).is_err());
    }

    #[test]
    fn bitwarden_json() {
        let json = r#"{"encrypted":false,"folders":[{"id":"f1","name":"Banking"}],"items":[
            {"type":1,"name":"Bank","folderId":"f1","favorite":true,"notes":null,
             "login":{"username":"jan","password":"pw","totp":"JBSWY3DPEHPK3PXP","uris":[{"uri":"https://bank.nl"}]},
             "fields":[{"name":"PIN","value":"1234","type":1}],
             "passwordHistory":[{"lastUsedDate":"2023-01-01T00:00:00.000Z","password":"old"}]},
            {"type":3,"name":"Visa","card":{"cardholderName":"Jan","brand":"Visa","number":"4111111111111111","expMonth":"3","expYear":"2030","code":"123"}},
            {"type":4,"name":"Me","identity":{"firstName":"Jan","lastName":"Jansen","city":"Amsterdam","postalCode":"1000 AA","address1":"Damrak 1"}},
            {"type":2,"name":"Note","notes":"hello","secureNote":{"type":0}}
        ]}"#;
        let r = import(json.as_bytes(), ImportFormat::BitwardenJson, None).unwrap();
        let items = &r.vaults[0].items;
        assert_eq!(items.len(), 4);
        assert_eq!(items[0].tags, vec!["Banking"]);
        assert_eq!(items[0].value("PIN"), Some("1234"));
        assert_eq!(items[0].password_history[0].value, "old");
        assert_eq!(items[1].value("expiry"), Some("03/2030"));
        assert_eq!(items[2].value("address"), Some("Damrak 1\n1000 AA Amsterdam"));
        assert_eq!(items[3].notes, "hello");
        assert!(import(br#"{"encrypted":true,"items":[]}"#, ImportFormat::BitwardenJson, None).is_err());
    }

    #[test]
    fn onepux() {
        let export_data = r#"{"accounts":[{"attrs":{},"vaults":[{"attrs":{"name":"Private"},"items":[
            {"uuid":"a","favIndex":1,"createdAt":1600000000,"updatedAt":1600000001,"state":"active","categoryUuid":"001",
             "overview":{"title":"GitHub","url":"https://github.com","tags":["dev"]},
             "details":{"loginFields":[{"value":"octo","designation":"username"},{"value":"pw","designation":"password"}],
               "notesPlain":"n","sections":[{"title":"Security","fields":[{"title":"one-time password","id":"TOTP_x","value":{"totp":"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"}},
               {"title":"recovery email","id":"x1","value":{"email":{"email_address":"r@x.com","provider":null}}}]}],
               "passwordHistory":[{"value":"old","time":1500000000}]}},
            {"uuid":"b","favIndex":0,"createdAt":1600000000,"updatedAt":1600000000,"state":"archived","categoryUuid":"002",
             "overview":{"title":"Card"},
             "details":{"sections":[{"title":"","fields":[{"title":"number","id":"ccnum","value":{"creditCardNumber":"4111"}},
               {"title":"expiry","id":"expiry","value":{"monthYear":203004}}]}]}}
        ]}]}]}"#;
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut buf);
            let opts: zip::write::SimpleFileOptions = Default::default();
            zip.start_file("export.data", opts).unwrap();
            std::io::Write::write_all(&mut zip, export_data.as_bytes()).unwrap();
            zip.finish().unwrap();
        }
        let bytes = buf.into_inner();
        assert_eq!(detect("x.1pux", &bytes), Some(ImportFormat::OnePasswordPux));
        let r = import(&bytes, ImportFormat::OnePasswordPux, None).unwrap();
        assert_eq!(r.vaults[0].name, "Private");
        let gh = &r.vaults[0].items[0];
        assert_eq!(gh.username(), Some("octo"));
        assert!(gh.totp_secret().unwrap().starts_with("otpauth://"));
        assert_eq!(gh.value("recovery email"), Some("r@x.com"));
        assert!(gh.favorite);
        assert_eq!(gh.created_at, 1_600_000_000);
        let card = &r.vaults[0].items[1];
        assert_eq!(card.category, Category::CreditCard);
        assert_eq!(card.value("number"), Some("4111"));
        assert_eq!(card.value("expiry"), Some("04/2030"));
        assert_eq!(card.tags, vec!["archived"]);
    }

    #[test]
    fn keepass_xml() {
        let xml = r#"<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<KeePassFile><Root><Group><Name>Database</Name>
  <Entry><String><Key>Title</Key><Value>Router</Value></String><String><Key>UserName</Key><Value>admin</Value></String>
    <String><Key>Password</Key><Value ProtectInMemory="True">r&amp;ut3r</Value></String><String><Key>URL</Key><Value>http://192.168.1.1</Value></String>
    <String><Key>otp</Key><Value>otpauth://totp/x?secret=JBSWY3DPEHPK3PXP</Value></String>
    <History><Entry><String><Key>Title</Key><Value>Old</Value></String></Entry></History></Entry>
  <Group><Name>Email</Name><Entry><String><Key>Title</Key><Value>Mail</Value></String><String><Key>Password</Key><Value>m</Value></String><String><Key>Security Q</Key><Value>blue</Value></String></Entry></Group>
  <Group><Name>Recycle Bin</Name><Entry><String><Key>Title</Key><Value>Deleted</Value></String></Entry></Group>
</Group></Root></KeePassFile>"#;
        assert_eq!(detect("db.xml", xml.as_bytes()), Some(ImportFormat::KeePassXml));
        let r = import(xml.as_bytes(), ImportFormat::KeePassXml, None).unwrap();
        let items = &r.vaults[0].items;
        assert_eq!(items.len(), 2, "{items:?}");
        assert_eq!(items[0].password(), Some("r&ut3r"));
        assert!(items[0].totp_secret().is_some());
        assert_eq!(items[1].tags, vec!["Email"]);
        assert_eq!(items[1].value("Security Q"), Some("blue"));
    }

    #[test]
    fn roundtrip_2secret_export_and_dedupe() {
        let (mut s, _) = new_session();
        let v = s.default_vault_id().unwrap();
        s.add_item(&v, Item::login("A", "u", "p", Some("a.com"))).unwrap();
        s.add_item(&v, Item::new(Category::SecureNote, "Note")).unwrap();
        let export = s.export(None, false);
        assert_eq!(export.item_count(), 2);

        let plain = export.to_json();
        let r = import(plain.as_bytes(), detect("x.json", plain.as_bytes()).unwrap(), None).unwrap();
        assert_eq!(r.item_count(), 2);

        let enc = {
            // Use weak params to keep the test fast.
            let json = serde_json::to_vec(&export).unwrap();
            serde_json::to_string(
                &PasswordEnvelope::seal("pw", &json, crate::crypto::KdfParams::insecure_for_tests()).unwrap(),
            )
            .unwrap()
        };
        assert!(import(enc.as_bytes(), ImportFormat::TwoSecret, None).is_err());
        assert!(import(enc.as_bytes(), ImportFormat::TwoSecret, Some("bad")).is_err());
        let r2 = import(enc.as_bytes(), ImportFormat::TwoSecret, Some("pw")).unwrap();
        assert_eq!(r2.item_count(), 2);

        let summary = s.import(r2, None).unwrap();
        assert_eq!(summary.skipped_duplicates, 2);
        assert_eq!(summary.imported, 0);

        let (mut fresh, _) = new_session();
        let summary = fresh.import(r, None).unwrap();
        assert_eq!(summary.imported, 2);
        assert_eq!(fresh.item_count(), 2);

        let csv = export.to_csv().unwrap();
        assert!(csv.starts_with("title,url,username,password"));
        let r3 = import(csv.as_bytes(), ImportFormat::Csv, None).unwrap();
        assert_eq!(r3.item_count(), 2);
    }
}
