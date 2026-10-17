//! User interface translations (English and Dutch).
//!
//! Adding a language: add a variant to [`Lang`] and a column to [`TABLE`].

use std::collections::HashMap;
use std::sync::OnceLock;

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};
use twosecret_core::item::{Category, Field, FieldKind};
use twosecret_core::profile::Role;
use twosecret_core::watchtower::IssueKind;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lang {
    #[default]
    En,
    Nl,
}

impl Lang {
    pub const ALL: [Lang; 2] = [Lang::En, Lang::Nl];

    pub fn code(&self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::Nl => "nl",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Lang::En => "English",
            Lang::Nl => "Nederlands",
        }
    }

    pub fn from_code(code: &str) -> Lang {
        match code.to_lowercase().get(..2) {
            Some("nl") => Lang::Nl,
            _ => Lang::En,
        }
    }
}

/// The active language. Reading it in a component re-renders the component
/// when the language changes.
pub static LANG: GlobalSignal<Lang> = Signal::global(|| Lang::En);

type Entry = (&'static str, &'static str, &'static str);

fn table() -> &'static HashMap<&'static str, (&'static str, &'static str)> {
    static MAP: OnceLock<HashMap<&'static str, (&'static str, &'static str)>> = OnceLock::new();
    MAP.get_or_init(|| TABLE.iter().map(|(k, en, nl)| (*k, (*en, *nl))).collect())
}

/// Translate a key into the active language.
pub fn t(key: &str) -> &'static str {
    let lang = *LANG.read();
    lookup(lang, key).unwrap_or_else(|| {
        // Unknown keys are returned as-is (makes missing strings visible).
        Box::leak(key.to_string().into_boxed_str())
    })
}

fn lookup(lang: Lang, key: &str) -> Option<&'static str> {
    table().get(key).map(|(en, nl)| match lang {
        Lang::En => *en,
        Lang::Nl => *nl,
    })
}

/// Translation if the key exists.
pub fn t_opt(key: &str) -> Option<&'static str> {
    lookup(*LANG.read(), key)
}

pub fn category_name(c: Category) -> String {
    t_opt(&format!("cat.{}", c.id())).unwrap_or(c.name()).to_string()
}

/// Label of a field: translated for template fields, as typed for custom ones.
pub fn field_label(f: &Field) -> String {
    if !f.is_custom() {
        if let Some(s) = t_opt(&format!("field.{}", f.id)) {
            return s.to_string();
        }
    }
    if f.label.trim().is_empty() {
        t("edit.field_label").to_string()
    } else {
        f.label.clone()
    }
}

pub fn field_kind_name(k: FieldKind) -> &'static str {
    t(&format!("kind.{}", k.id()))
}

pub fn role_name(r: Role) -> &'static str {
    t(&format!("role.{}", r.id()))
}

pub fn issue_title(k: IssueKind) -> &'static str {
    t(&format!("issue.{}", k.id()))
}

pub fn issue_desc(k: IssueKind) -> &'static str {
    t(&format!("issue.{}.desc", k.id()))
}

#[rustfmt::skip]
static TABLE: &[Entry] = &[
    // Common
    ("common.back", "Back", "Terug"),
    ("common.cancel", "Cancel", "Annuleren"),
    ("common.change", "Change", "Wijzigen"),
    ("common.clear", "Clear", "Wissen"),
    ("common.close", "Close", "Sluiten"),
    ("common.copy", "Copy", "Kopiëren"),
    ("common.delete", "Delete", "Verwijderen"),
    ("common.download", "Download", "Downloaden"),
    ("common.edit", "Edit", "Bewerken"),
    ("common.email", "E-mail address", "E-mailadres"),
    ("common.hide", "Hide", "Verbergen"),
    ("common.master_password", "Master password", "Hoofdwachtwoord"),
    ("common.optional", "Optional", "Optioneel"),
    ("common.remove", "Remove", "Verwijderen"),
    ("common.reveal", "Show / hide", "Tonen / verbergen"),
    ("common.save", "Save", "Opslaan"),
    ("common.secret_key", "Secret Key", "Geheime sleutel"),
    ("common.server", "Server address", "Serveradres"),
    ("common.show", "Show", "Tonen"),
    ("common.turn_on", "Turn on", "Inschakelen"),
    ("common.turn_off", "Turn off", "Uitschakelen"),

    // Welcome & onboarding
    ("welcome.tagline", "Free, open-source password manager", "Gratis, open-source wachtwoordmanager"),
    ("welcome.title", "Welcome", "Welkom"),
    ("welcome.lead", "Keep all your passwords, cards, notes and secrets safe – end-to-end encrypted with your master password and Secret Key.", "Bewaar al je wachtwoorden, passen, notities en geheimen veilig – end-to-end versleuteld met je hoofdwachtwoord en geheime sleutel."),
    ("welcome.create", "Create a new account", "Nieuw account aanmaken"),
    ("welcome.create_desc", "Start fresh, synced through the 2Secret server or your own, or only on this device.", "Begin opnieuw, gesynchroniseerd via de 2Secret-server of je eigen server, of alleen op dit apparaat."),
    ("welcome.signin", "Sign in to an existing account", "Inloggen op een bestaand account"),
    ("welcome.signin_desc", "Use your Emergency Kit to add this device.", "Gebruik je noodkit om dit apparaat toe te voegen."),
    ("create.title", "Create your account", "Maak je account aan"),
    ("create.lead", "Your master password is never sent anywhere. Choose one you can remember – it cannot be recovered.", "Je hoofdwachtwoord wordt nooit verstuurd. Kies er een die je kunt onthouden – het kan niet worden hersteld."),
    ("create.name", "Your name", "Je naam"),
    ("create.confirm", "Repeat password", "Herhaal wachtwoord"),
    ("create.password_hint", "Tip: a passphrase of 4–6 random words is strong and easy to remember.", "Tip: een zin van 4–6 willekeurige woorden is sterk en makkelijk te onthouden."),
    ("create.invite", "Invite code", "Uitnodigingscode"),
    ("create.submit", "Create account", "Account aanmaken"),
    ("create.err_name", "Please enter your name.", "Vul je naam in."),
    ("create.err_email", "Please enter a valid e-mail address.", "Vul een geldig e-mailadres in."),
    ("create.err_short", "Use at least 12 characters.", "Gebruik minstens 12 tekens."),
    ("create.err_weak", "This password is too easy to guess. Choose a stronger one.", "Dit wachtwoord is te makkelijk te raden. Kies een sterker wachtwoord."),
    ("create.err_mismatch", "The passwords do not match.", "De wachtwoorden komen niet overeen."),
    ("create.err_server", "Enter the address of your 2Secret server.", "Vul het adres van je 2Secret-server in."),
    ("signin.title", "Sign in", "Inloggen"),
    ("signin.lead", "Enter the details from your Emergency Kit.", "Vul de gegevens uit je noodkit in."),
    ("signin.submit", "Sign in", "Inloggen"),
    ("signin.err_fields", "Please fill in all fields.", "Vul alle velden in."),
    ("newacc.title", "Save your Secret Key", "Bewaar je geheime sleutel"),
    ("newacc.lead", "Together with your master password, this Secret Key unlocks your account on new devices. It is stored on this device, but nowhere else.", "Samen met je hoofdwachtwoord ontgrendelt deze geheime sleutel je account op nieuwe apparaten. Hij staat op dit apparaat, maar nergens anders."),
    ("newacc.download_kit", "Download Emergency Kit", "Noodkit downloaden"),
    ("newacc.warning", "Print the Emergency Kit and keep it somewhere safe. If you lose your master password or Secret Key, nobody – not even the server owner – can recover your data.", "Print de noodkit en bewaar hem op een veilige plek. Als je je hoofdwachtwoord of geheime sleutel kwijtraakt, kan niemand – ook de serverbeheerder niet – je gegevens herstellen."),
    ("newacc.confirm", "I have saved my Emergency Kit", "Ik heb mijn noodkit bewaard"),
    ("newacc.continue", "Open my vault", "Open mijn kluis"),
    ("lock.unlock", "Unlock", "Ontgrendelen"),
    ("lock.lock_now", "Lock now", "Nu vergrendelen"),
    ("profiles.title", "Profiles", "Profielen"),
    ("profiles.add", "Add a profile", "Profiel toevoegen"),
    ("profiles.add_desc", "Another account, for example for work", "Nog een account, bijvoorbeeld voor je werk"),
    ("profiles.switch_to", "Switch to {name}", "Wissel naar {name}"),
    ("profiles.back_to", "Back to {name}", "Terug naar {name}"),
    ("profiles.remove", "Remove this profile from this device", "Dit profiel van dit apparaat verwijderen"),
    ("profiles.already_here", "This account is already on this device as a profile.", "Dit account staat al als profiel op dit apparaat."),
    ("lock.other_account", "Use a different account", "Ander account gebruiken"),
    ("lock.biometric", "Unlock with {kind}", "Ontgrendelen met {kind}"),
    ("lock.biometric_reason", "unlock your vault", "je kluis ontgrendelen"),
    ("lock.biometric_password_needed", "Enter your master password. 2Secret asks for it every 14 days, so you will not forget it.", "Vul je hoofdwachtwoord in. 2Secret vraagt er elke 14 dagen om, zodat je het niet vergeet."),
    ("lock.biometric_unavailable", "{kind} is not available right now. Enter your master password.", "{kind} is nu niet beschikbaar. Vul je hoofdwachtwoord in."),
    ("reauth.explain", "Your session on the sync server has ended. Enter your master password to sign in again.", "Je sessie op de synchronisatieserver is beëindigd. Vul je hoofdwachtwoord in om opnieuw in te loggen."),

    // Busy messages
    ("busy.creating", "Creating your account…", "Account wordt aangemaakt…"),
    ("busy.registering", "Connecting to the server…", "Verbinden met de server…"),
    ("busy.signing_in", "Signing in…", "Inloggen…"),
    ("busy.downloading", "Downloading your vaults…", "Kluizen worden gedownload…"),
    ("busy.unlocking", "Unlocking…", "Ontgrendelen…"),
    ("busy.changing_password", "Changing master password…", "Hoofdwachtwoord wijzigen…"),
    ("busy.importing", "Importing…", "Importeren…"),
    ("busy.exporting", "Exporting…", "Exporteren…"),
    ("busy.sharing", "Sharing vault…", "Kluis delen…"),
    ("busy.working", "One moment…", "Een moment…"),

    // Errors
    ("err.wrong_password", "Incorrect master password.", "Onjuist hoofdwachtwoord."),
    ("err.wrong_credentials", "Incorrect e-mail address, Secret Key or master password.", "Onjuist e-mailadres, geheime sleutel of hoofdwachtwoord."),
    ("err.secret_key", "This Secret Key is not valid. Check it for typos.", "Deze geheime sleutel is ongeldig. Controleer op typefouten."),
    ("err.permission", "You don't have permission to do that in this vault.", "Je hebt geen toestemming om dat in deze kluis te doen."),
    ("err.session_expired", "Your session has expired – please sign in again.", "Je sessie is verlopen – log opnieuw in."),
    ("err.network", "Could not reach the server", "Kan de server niet bereiken"),
    ("err.storage_quota", "The storage limit of the server is reached.", "De opslaglimiet van de server is bereikt."),
    ("create.where", "Where should your vault sync?", "Waar wil je je kluis synchroniseren?"),
    ("server.official", "2Secret server", "2Secret-server"),
    ("server.official_desc", "sync.2secret.app – nothing to set up. End-to-end encrypted: the server never sees your passwords.", "sync.2secret.app – niets zelf in te stellen. End-to-end versleuteld: de server ziet je wachtwoorden nooit."),
    ("server.custom", "Your own server", "Eigen server"),
    ("server.custom_desc", "A 2Secret server that you or your organisation runs.", "Een 2Secret-server van jezelf of je organisatie."),
    ("server.local", "Only on this device", "Alleen op dit apparaat"),
    ("server.local_desc", "No sync. You can connect to a server later in Settings.", "Geen synchronisatie. Je kunt later in Instellingen verbinden met een server."),
    ("sync.over_quota", "The storage limit of the server is reached: {n} changes are only on this device.", "De opslaglimiet van de server is bereikt: {n} wijzigingen staan alleen op dit apparaat."),
    ("settings.storage", "Storage on the server", "Opslag op de server"),
    ("settings.storage_of", "{used} of {quota}", "{used} van {quota}"),
    ("err.rate_limited", "Too many attempts. Please wait a few minutes.", "Te veel pogingen. Wacht een paar minuten."),
    ("err.not_linked", "This account is not connected to a server.", "Dit account is niet met een server verbonden."),
    ("err.save", "Could not save", "Opslaan mislukt"),
    ("err.clipboard", "Copying is not available here.", "Kopiëren is hier niet beschikbaar."),
    ("err.no_account", "No account found on this device.", "Geen account gevonden op dit apparaat."),
    ("err.no_vault", "There is no vault you can add items to.", "Er is geen kluis waaraan je items kunt toevoegen."),

    // Navigation
    ("nav.home", "Dashboard", "Dashboard"),
    ("nav.all", "All items", "Alle items"),
    ("nav.favorites", "Favorites", "Favorieten"),
    ("nav.watchtower", "Watchtower", "Watchtower"),
    ("nav.generator", "Password generator", "Wachtwoordgenerator"),
    ("nav.categories", "Categories", "Categorieën"),
    ("nav.vaults", "Vaults", "Kluizen"),
    ("nav.tags", "Tags", "Labels"),
    ("nav.trash", "Trash", "Prullenbak"),
    ("nav.settings", "Settings", "Instellingen"),

    // Sync
    ("sync.local", "Local only", "Alleen lokaal"),
    ("sync.syncing", "Syncing…", "Synchroniseren…"),
    ("sync.signed_out", "Signed out of server", "Uitgelogd bij server"),
    ("sync.error", "Sync failed – tap to retry", "Synchronisatie mislukt – tik om opnieuw te proberen"),
    ("sync.synced", "Synced", "Gesynchroniseerd"),
    ("sync.never", "Not synced yet", "Nog niet gesynchroniseerd"),
    ("sync.now", "Sync now", "Nu synchroniseren"),
    ("time.just_now", "just now", "zojuist"),
    ("time.min_ago", "min ago", "min geleden"),
    ("time.hours_ago", "h ago", "u geleden"),

    // List & items
    ("list.search", "Search", "Zoeken"),
    ("list.no_results", "No items match your search.", "Geen items gevonden."),
    ("list.empty", "Nothing here yet.", "Hier staat nog niets."),
    // One-time passwords from otpauth:// links
    ("code.setup_title", "Set up one-time password", "Eenmalig wachtwoord instellen"),
    ("code.setup_explain", "Add it to the login of this account. 2Secret then shows its codes and fills them, like the password.", "Voeg het toe aan de login van dit account. 2Secret laat dan de codes zien en vult ze in, net als het wachtwoord."),
    ("code.search", "Search logins", "Logins zoeken"),
    ("code.new_login", "New login", "Nieuwe login"),
    ("code.replaces", "Replaces its one-time password", "Vervangt het eenmalige wachtwoord"),
    ("code.added", "One-time password added", "Eenmalig wachtwoord toegevoegd"),
    ("code.invalid", "This link holds no valid one-time password.", "Deze link bevat geen geldig eenmalig wachtwoord."),
    // Dashboard
    ("home.welcome", "Welcome", "Welkom"),
    ("home.morning", "Good morning, {name}", "Goedemorgen, {name}"),
    ("home.afternoon", "Good afternoon, {name}", "Goedemiddag, {name}"),
    ("home.evening", "Good evening, {name}", "Goedenavond, {name}"),
    ("home.search", "Search all items", "Zoek in alle items"),
    ("home.items", "Items", "Items"),
    ("home.security", "Security", "Beveiliging"),
    ("home.recent", "Recently changed", "Recent gewijzigd"),
    ("home.see_all", "See all", "Alles bekijken"),
    ("home.no_favorites", "Mark items with a star to find them here quickly.", "Geef items een ster om ze hier snel terug te vinden."),
    ("home.breach_hint", "Not yet checked against known data breaches", "Nog niet gecontroleerd op bekende datalekken"),
    ("home.shared", "Shared", "Gedeeld"),
    ("home.empty_title", "Your vault is still empty", "Je kluis is nog leeg"),
    ("home.empty_desc", "Add your first login, card or note, or import your passwords from another password manager.", "Voeg je eerste login, kaart of notitie toe, of importeer je wachtwoorden uit een andere wachtwoordmanager."),
    ("list.trash_empty", "The trash is empty.", "De prullenbak is leeg."),
    ("trash.empty", "Empty trash", "Prullenbak legen"),
    ("detail.nothing_selected", "Select an item to see its details.", "Selecteer een item om de details te zien."),
    ("item.new", "New item", "Nieuw item"),
    ("item.new_short", "New", "Nieuw"),
    ("item.favorite", "Favorite", "Favoriet"),
    ("item.restore", "Restore", "Terugzetten"),
    ("item.duplicate", "Duplicate", "Dupliceren"),
    ("item.move", "Move to vault…", "Verplaatsen naar kluis…"),
    ("item.move_none", "There is no other vault to move this item to.", "Er is geen andere kluis om dit item naartoe te verplaatsen."),
    ("item.trash", "Move to trash", "Naar prullenbak"),
    ("item.delete_forever", "Delete permanently", "Definitief verwijderen"),
    ("item.delete_warning", "This item will be deleted on all your devices. This cannot be undone.", "Dit item wordt op al je apparaten verwijderd. Dit kan niet ongedaan worden gemaakt."),
    ("item.in_trash", "This item is in the trash.", "Dit item staat in de prullenbak."),
    ("item.open", "Open website", "Website openen"),
    ("item.invalid_totp", "This is not a valid one-time password secret.", "Dit is geen geldige code voor eenmalige wachtwoorden."),
    ("item.password_history", "Password history", "Wachtwoordgeschiedenis"),
    ("item.modified", "Modified", "Gewijzigd"),
    ("item.created", "created", "aangemaakt"),
    ("item.password_changed", "Password changed", "Wachtwoord gewijzigd"),

    // Editor
    ("edit.new_title", "New item", "Nieuw item"),
    ("edit.edit_title", "Edit item", "Item bewerken"),
    ("edit.add_field", "Add field", "Veld toevoegen"),
    ("edit.add_website", "Add website", "Website toevoegen"),
    ("edit.field_label", "Label", "Naam"),
    ("edit.tags_hint", "Comma separated, e.g. work, finance", "Gescheiden door komma's, bijv. werk, financiën"),
    ("edit.totp_hint", "otpauth://… or setup key", "otpauth://… of instelsleutel"),
    ("edit.attach_hint", "Files up to 5 MB are encrypted and stored with the item.", "Bestanden tot 5 MB worden versleuteld en bij het item opgeslagen."),
    ("edit.err_title", "Give the item a title.", "Geef het item een titel."),
    ("edit.generate_ssh", "Generate Ed25519 key", "Ed25519-sleutel genereren"),

    // Fields
    ("field.username", "username", "gebruikersnaam"),
    ("field.password", "password", "wachtwoord"),
    ("field.totp", "one-time password", "eenmalig wachtwoord"),
    ("field.website", "website", "website"),
    ("field.websites", "Websites", "Websites"),
    ("field.notes", "Notes", "Notities"),
    ("field.tags", "Tags", "Labels"),
    ("field.attachments", "Attachments", "Bijlagen"),
    ("field.cardholder", "cardholder name", "naam kaarthouder"),
    ("field.type", "type", "type"),
    ("field.number", "number", "nummer"),
    ("field.expiry", "expiry date", "vervaldatum"),
    ("field.cvv", "verification number", "verificatiecode"),
    ("field.pin", "PIN", "pincode"),
    ("field.first_name", "first name", "voornaam"),
    ("field.last_name", "last name", "achternaam"),
    ("field.birth_date", "birth date", "geboortedatum"),
    ("field.email", "email", "e-mail"),
    ("field.phone", "phone", "telefoon"),
    ("field.address", "address", "adres"),
    ("field.company", "company", "bedrijf"),
    ("field.bank_name", "bank name", "naam bank"),
    ("field.owner", "name on account", "tenaamstelling"),
    ("field.iban", "IBAN", "IBAN"),
    ("field.bic", "BIC / SWIFT", "BIC / SWIFT"),
    ("field.account_number", "account number", "rekeningnummer"),
    ("field.recovery_phrase", "recovery phrase", "herstelzin"),
    ("field.wallet_address", "wallet address", "walletadres"),
    ("field.network", "network", "netwerk"),
    ("field.license_key", "license key", "licentiesleutel"),
    ("field.licensed_to", "licensed to", "gelicentieerd aan"),
    ("field.registered_email", "registered email", "geregistreerd e-mailadres"),
    ("field.version", "version", "versie"),
    ("field.purchase_date", "purchase date", "aankoopdatum"),
    ("field.private_key", "private key", "privésleutel"),
    ("field.public_key", "public key", "publieke sleutel"),
    ("field.fingerprint", "fingerprint", "vingerafdruk"),
    ("field.key_type", "key type", "sleuteltype"),
    ("field.passphrase", "passphrase", "wachtwoordzin"),
    ("field.credential", "credential", "sleutel / token"),
    ("field.hostname", "hostname", "hostnaam"),
    ("field.expires", "expires", "verloopt"),
    ("field.database_type", "type", "type"),
    ("field.server", "server", "server"),
    ("field.port", "port", "poort"),
    ("field.database", "database", "database"),
    ("field.url", "URL", "URL"),
    ("field.hosting_provider", "hosting provider", "hostingprovider"),
    ("field.network_name", "network name", "netwerknaam"),
    ("field.wireless_password", "wireless password", "wifi-wachtwoord"),
    ("field.security", "security", "beveiliging"),
    ("field.base_station_name", "base station name", "naam basisstation"),
    ("field.base_station_password", "base station password", "wachtwoord basisstation"),
    ("field.server_ip", "server / IP address", "server / IP-adres"),
    ("field.imap_server", "IMAP server", "IMAP-server"),
    ("field.smtp_server", "SMTP server", "SMTP-server"),
    ("field.full_name", "full name", "volledige naam"),
    ("field.nationality", "nationality", "nationaliteit"),
    ("field.issuing_country", "issuing country", "land van afgifte"),
    ("field.date_of_birth", "date of birth", "geboortedatum"),
    ("field.issued_on", "issued on", "afgegeven op"),
    ("field.expiry_date", "expiry date", "vervaldatum"),
    ("field.license_class", "license class", "rijbewijscategorie"),
    ("field.country", "country", "land"),
    ("field.group", "group", "organisatie"),
    ("field.member_name", "member name", "naam lid"),
    ("field.member_id", "member ID", "lidnummer"),
    ("field.company_name", "company name", "bedrijfsnaam"),

    // Field kinds
    ("kind.text", "Text", "Tekst"),
    ("kind.concealed", "Password", "Wachtwoord"),
    ("kind.email", "E-mail", "E-mail"),
    ("kind.url", "URL", "URL"),
    ("kind.phone", "Phone", "Telefoon"),
    ("kind.date", "Date", "Datum"),
    ("kind.month_year", "Month/year", "Maand/jaar"),
    ("kind.totp", "One-time password", "Eenmalig wachtwoord"),
    ("kind.multiline", "Multi-line text", "Tekst (meerdere regels)"),

    // Categories
    ("cat.login", "Login", "Login"),
    ("cat.password", "Password", "Wachtwoord"),
    ("cat.secure_note", "Secure Note", "Beveiligde notitie"),
    ("cat.credit_card", "Credit Card", "Creditcard"),
    ("cat.identity", "Identity", "Identiteit"),
    ("cat.bank_account", "Bank Account", "Bankrekening"),
    ("cat.crypto_wallet", "Crypto Wallet", "Crypto-wallet"),
    ("cat.software_license", "Software License", "Softwarelicentie"),
    ("cat.ssh_key", "SSH Key", "SSH-sleutel"),
    ("cat.api_credential", "API Credential", "API-sleutel"),
    ("cat.database", "Database", "Database"),
    ("cat.server", "Server", "Server"),
    ("cat.wireless_router", "Wireless Router", "Wifi-router"),
    ("cat.email_account", "Email Account", "E-mailaccount"),
    ("cat.passport", "Passport", "Paspoort"),
    ("cat.driver_license", "Driver License", "Rijbewijs"),
    ("cat.membership", "Membership", "Lidmaatschap"),
    ("cat.reward_program", "Reward Program", "Spaarprogramma"),
    ("cat.document", "Document", "Document"),

    // Roles
    ("role.viewer", "Can view", "Kan bekijken"),
    ("role.editor", "Can edit", "Kan bewerken"),
    ("role.manager", "Can manage", "Kan beheren"),
    ("role.owner", "Owner", "Eigenaar"),

    // Vaults & sharing
    ("vault.personal", "Personal", "Persoonlijk"),
    ("vault.vault", "Vault", "Kluis"),
    ("passkey.title", "Passkeys", "Passkeys"),
    ("passkey.remove", "Remove passkey", "Passkey verwijderen"),
    ("passkey.removed", "Passkey removed", "Passkey verwijderd"),
    ("passkey.save_title", "Save passkey?", "Passkey opslaan?"),
    ("passkey.save_lead", "{site} wants to create a passkey for {user}. 2Secret keeps it end-to-end encrypted and syncs it to your devices.", "{site} wil een passkey maken voor {user}. 2Secret bewaart hem end-to-end versleuteld en synchroniseert hem naar je apparaten."),
    ("passkey.save_in", "Save in", "Opslaan in"),
    ("passkey.new_login", "New login", "Nieuwe login"),
    ("passkey.save", "Save passkey", "Passkey opslaan"),
    ("passkey.exists", "2Secret already has a passkey for this account.", "2Secret heeft al een passkey voor dit account."),
    ("passkey.use_title", "Sign in with a passkey", "Inloggen met een passkey"),
    ("passkey.use_lead", "Choose the account to sign in to {site} with.", "Kies het account waarmee je inlogt op {site}."),
    ("passkey.none", "2Secret has no passkey for {site}.", "2Secret heeft geen passkey voor {site}."),
    ("passkey.other_device", "Use another device or security key", "Ander apparaat of beveiligingssleutel gebruiken"),
    ("passkey.not_allowed", "This website may not use passkeys this way.", "Deze website mag op deze manier geen passkeys gebruiken."),
    ("passkey.waiting", "{site} is waiting for a passkey. Unlock 2Secret to continue.", "{site} wacht op een passkey. Ontgrendel 2Secret om verder te gaan."),
    ("settings.passkeys", "Passkeys in this browser", "Passkeys in deze browser"),
    ("settings.passkeys_desc", "Offer to save new passkeys in 2Secret and to sign in with them.", "Bied aan om nieuwe passkeys in 2Secret te bewaren en ermee in te loggen."),
    ("vault.new", "New vault", "Nieuwe kluis"),
    ("vault.edit", "Edit vault", "Kluis bewerken"),
    ("vault.share", "Share", "Delen"),
    ("vault.delete", "Delete vault", "Kluis verwijderen"),
    ("vault.leave", "Leave vault", "Kluis verlaten"),
    ("vault.name", "Name", "Naam"),
    ("vault.icon", "Icon", "Icoon"),
    ("vault.icon_shared", "Everyone with access to this vault sees this icon.", "Iedereen met toegang tot deze kluis ziet dit icoon."),
    ("vault.description", "Description", "Omschrijving"),
    ("vault.items", "items", "items"),
    ("vault.members", "people", "personen"),
    ("vault.delete_warning", "The vault and all its items are deleted for everyone who has access. This cannot be undone.", "De kluis en alle items worden verwijderd voor iedereen die toegang heeft. Dit kan niet ongedaan worden gemaakt."),
    ("vault.leave_warning", "You will lose access to this shared vault and its items on all your devices.", "Je verliest op al je apparaten de toegang tot deze gedeelde kluis en de items."),
    ("share.explain", "People need a 2Secret account on the same server. The vault key is encrypted to their public key – compare the fingerprint with them to be sure.", "Mensen hebben een 2Secret-account op dezelfde server nodig. De kluissleutel wordt versleuteld met hun publieke sleutel – vergelijk de vingerafdruk met hen voor zekerheid."),
    ("share.needs_server", "Sharing requires a sync server. Connect your account to a server first.", "Delen vereist een synchronisatieserver. Verbind je account eerst met een server."),
    ("share.shared_with", "Shared with", "Gedeeld met"),
    ("share.removed", "Access removed – the vault has a new key", "Toegang ingetrokken – de kluis heeft een nieuwe sleutel"),
    ("share.rotate", "Replace vault key", "Kluissleutel vervangen"),
    ("share.rotate_desc", "Removing someone gives the vault a new key automatically. Replace it yourself after someone left the vault on their own.", "Iemand verwijderen geeft de kluis automatisch een nieuwe sleutel. Vervang hem zelf als iemand de kluis zelf heeft verlaten."),
    ("share.rotated", "The vault has a new key", "De kluis heeft een nieuwe sleutel"),

    // Generator
    ("gen.random", "Random", "Willekeurig"),
    ("gen.memorable", "Memorable", "Makkelijk te onthouden"),
    ("gen.pin", "PIN", "Pincode"),
    ("gen.copy", "Copy password", "Wachtwoord kopiëren"),
    ("gen.regenerate", "New", "Nieuw"),
    ("gen.generate", "Generate password", "Wachtwoord genereren"),
    ("gen.length", "Length", "Lengte"),
    ("gen.words", "Words", "Woorden"),
    ("gen.separator", "Separator", "Scheidingsteken"),
    ("gen.uppercase", "Uppercase letters (A-Z)", "Hoofdletters (A-Z)"),
    ("gen.lowercase", "Lowercase letters (a-z)", "Kleine letters (a-z)"),
    ("gen.digits", "Digits (0-9)", "Cijfers (0-9)"),
    ("gen.symbols", "Symbols (!@#…)", "Symbolen (!@#…)"),
    ("gen.ambiguous", "Avoid look-alike characters (l, 1, O, 0)", "Vermijd gelijkende tekens (l, 1, O, 0)"),
    ("gen.capitalize", "Capitalize words", "Woorden met hoofdletter"),
    ("gen.number", "Include a number", "Voeg een cijfer toe"),
    ("gen.history", "Recently copied", "Recent gekopieerd"),

    // Strength
    ("strength.terrible", "Terrible", "Zeer zwak"),
    ("strength.weak", "Weak", "Zwak"),
    ("strength.fair", "Fair", "Redelijk"),
    ("strength.good", "Good", "Goed"),
    ("strength.fantastic", "Fantastic", "Uitstekend"),

    // Watchtower
    ("wt.fantastic", "Fantastic", "Uitstekend"),
    ("wt.very_good", "Very good", "Zeer goed"),
    ("wt.good", "Good", "Goed"),
    ("wt.fair", "Fair", "Matig"),
    ("wt.poor", "Needs attention", "Aandacht nodig"),
    ("wt.items_checked", "items checked", "items gecontroleerd"),
    ("wt.explain", "Watchtower checks your items for weak, reused and old passwords, unsecured websites and expiring cards or documents. All checks run on this device.", "Watchtower controleert je items op zwakke, hergebruikte en oude wachtwoorden, onbeveiligde websites en verlopende passen of documenten. Alle controles gebeuren op dit apparaat."),
    ("wt.none", "No problems found.", "Geen problemen gevonden."),
    ("wt.breach_title", "Check for data breaches", "Controleren op datalekken"),
    ("wt.breach_desc", "Compares your passwords with Have I Been Pwned. Only the first 5 characters of a hash are sent – your passwords never leave this device.", "Vergelijkt je wachtwoorden met Have I Been Pwned. Alleen de eerste 5 tekens van een hash worden verstuurd – je wachtwoorden verlaten dit apparaat nooit."),
    ("wt.breach_check", "Check now", "Nu controleren"),
    ("wt.breach_again", "Check again", "Opnieuw controleren"),
    ("wt.breach_done", "Breach check complete – compromised passwords", "Lekcontrole klaar – gelekte wachtwoorden"),
    ("wt.breached_item", "This password appeared in a data breach. Change it now.", "Dit wachtwoord kwam voor in een datalek. Wijzig het direct."),
    ("wt.weak_item", "This password is weak and easy to guess.", "Dit wachtwoord is zwak en makkelijk te raden."),
    ("wt.reused_item", "This password is also used by other items", "Dit wachtwoord wordt ook door andere items gebruikt"),
    ("issue.breached", "Compromised passwords", "Gelekte wachtwoorden"),
    ("issue.breached.desc", "Passwords found in known data breaches.", "Wachtwoorden die in bekende datalekken voorkomen."),
    ("issue.weak", "Weak passwords", "Zwakke wachtwoorden"),
    ("issue.weak.desc", "Passwords that are easy to guess.", "Wachtwoorden die makkelijk te raden zijn."),
    ("issue.reused", "Reused passwords", "Hergebruikte wachtwoorden"),
    ("issue.reused.desc", "The same password used for more than one item.", "Hetzelfde wachtwoord voor meerdere items."),
    ("issue.expired", "Expired items", "Verlopen items"),
    ("issue.expired.desc", "Cards and documents past their expiry date.", "Passen en documenten waarvan de vervaldatum is verstreken."),
    ("issue.insecure_website", "Unsecured websites", "Onbeveiligde websites"),
    ("issue.insecure_website.desc", "Logins for websites without HTTPS.", "Logins voor websites zonder HTTPS."),
    ("issue.expiring_soon", "Expiring soon", "Verlopen binnenkort"),
    ("issue.expiring_soon.desc", "Cards and documents that expire within 60 days.", "Passen en documenten die binnen 60 dagen verlopen."),
    ("issue.old", "Old passwords", "Oude wachtwoorden"),
    ("issue.old.desc", "Passwords not changed in more than three years.", "Wachtwoorden die al meer dan drie jaar niet zijn gewijzigd."),

    // Settings
    ("settings.account", "Account", "Account"),
    ("settings.emergency_kit", "Emergency Kit", "Noodkit"),
    ("settings.emergency_kit_desc", "A printable sheet with your sign-in details and Secret Key.", "Een printbaar overzicht met je inloggegevens en geheime sleutel."),
    ("settings.change_password", "Change master password", "Hoofdwachtwoord wijzigen"),
    ("settings.change_password_desc", "Your data stays encrypted; other devices need the new password.", "Je gegevens blijven versleuteld; andere apparaten hebben het nieuwe wachtwoord nodig."),
    ("settings.change_password_info", "After the change, other devices are signed out and need the new master password.", "Na de wijziging worden andere apparaten uitgelogd en hebben ze het nieuwe hoofdwachtwoord nodig."),
    ("settings.current_password", "Current master password", "Huidig hoofdwachtwoord"),
    ("settings.new_password", "New master password", "Nieuw hoofdwachtwoord"),
    ("settings.fingerprint", "Public key fingerprint", "Vingerafdruk publieke sleutel"),
    ("settings.sync", "Sync", "Synchronisatie"),
    ("settings.local_only", "Local-only account", "Alleen lokaal account"),
    ("settings.local_only_desc", "Connect to a self-hosted 2Secret server to sync between devices and share vaults.", "Verbind met een zelfgehoste 2Secret-server om tussen apparaten te synchroniseren en kluizen te delen."),
    ("settings.connect", "Connect to server", "Verbinden met server"),
    ("settings.pending", "changes waiting to upload", "wijzigingen wachten op upload"),
    ("settings.sign_in_again", "Sign in again", "Opnieuw inloggen"),
    ("settings.devices", "Devices", "Apparaten"),
    ("settings.devices_desc", "Devices signed in to your account.", "Apparaten die op je account zijn ingelogd."),
    ("settings.this_device", "this device", "dit apparaat"),
    ("settings.last_used", "Last used", "Laatst gebruikt"),
    ("settings.sign_out_device", "Sign out", "Uitloggen"),
    ("settings.sign_out", "Sign out of server", "Uitloggen bij server"),
    ("settings.sign_out_desc", "Stops syncing. Your data stays available on this device.", "Stopt met synchroniseren. Je gegevens blijven op dit apparaat beschikbaar."),
    ("settings.security", "Security", "Beveiliging"),
    ("settings.auto_lock", "Lock automatically", "Automatisch vergrendelen"),
    ("settings.auto_lock_desc", "Lock 2Secret after a period of inactivity.", "Vergrendel 2Secret na een periode zonder activiteit."),
    ("settings.biometric", "Unlock with {kind}", "Ontgrendelen met {kind}"),
    ("settings.biometric_desc", "Use {kind} instead of typing your master password. It is still needed every 14 days.", "Gebruik {kind} in plaats van je hoofdwachtwoord te typen. Dat blijft elke 14 dagen nodig."),
    ("settings.biometric_reason", "turn on unlocking with biometrics", "ontgrendelen met biometrie inschakelen"),
    ("settings.biometric_on", "{kind} unlock is on", "Ontgrendelen met {kind} staat aan"),
    ("settings.biometric_off", "{kind} unlock is off", "Ontgrendelen met {kind} staat uit"),
    ("settings.biometric_unavailable", "{kind} is not set up on this device.", "{kind} is niet ingesteld op dit apparaat."),
    ("settings.photo_add", "Add photo", "Foto toevoegen"),
    ("settings.photo_change", "Change photo", "Foto wijzigen"),
    ("settings.photo_desc", "Your profile photo, end-to-end encrypted and synced to your devices.", "Je profielfoto, end-to-end versleuteld en gesynchroniseerd naar je apparaten."),
    ("settings.photo_saved", "Photo saved", "Foto bewaard"),
    ("settings.photo_invalid", "That file is not a photo 2Secret can read (JPEG, PNG, WebP or GIF).", "Dat bestand is geen foto die 2Secret kan lezen (JPEG, PNG, WebP of GIF)."),
    ("settings.start_screen", "Start screen", "Startscherm"),
    ("settings.start_screen_desc", "What you see after unlocking.", "Wat je ziet na het ontgrendelen."),
    ("settings.website_icons", "Website icons", "Website-icoontjes"),
    ("settings.website_icons_desc", "Show the icon of a login's website. 2Secret fetches it straight from that website (never through another service) when you save the login, and keeps it encrypted with the login.", "Toon het icoontje van de website van een login. 2Secret haalt het rechtstreeks bij die website op (nooit via een andere dienst) als je de login bewaart, en bewaart het versleuteld bij de login."),
    ("settings.website_icons_all", "Fetch for all logins", "Ophalen voor alle logins"),
    ("settings.website_icons_started", "Fetching website icons…", "Website-icoontjes worden opgehaald…"),
    ("settings.autofill", "AutoFill in Safari and other apps", "Automatisch invullen in Safari en andere apps"),
    ("settings.autofill_desc_ios", "Turn on 2Secret in Settings → General → AutoFill & Passwords. It fills passwords and passkeys while unlocking with Face ID or Touch ID is on.", "Zet 2Secret aan in Instellingen → Algemeen → Automatisch invullen en wachtwoorden. Het vult wachtwoorden en passkeys in zolang ontgrendelen met Face ID of Touch ID aanstaat."),
    ("settings.autofill_desc_macos", "Turn on 2Secret in System Settings → General → AutoFill & Passwords (macOS 14: Passwords → Password Options). It fills passwords and passkeys while unlocking with Touch ID is on.", "Zet 2Secret aan in Systeeminstellingen → Algemeen → Automatisch invullen en wachtwoorden (macOS 14: Wachtwoorden → Wachtwoordopties). Het vult wachtwoorden en passkeys in zolang ontgrendelen met Touch ID aanstaat."),
    ("settings.clipboard", "Clear clipboard", "Klembord wissen"),
    ("settings.clipboard_desc", "Remove copied secrets from the clipboard after a while.", "Verwijder gekopieerde geheimen na een tijdje van het klembord."),
    ("settings.never", "Never", "Nooit"),
    ("settings.appearance", "Appearance", "Weergave"),
    ("settings.language", "Language", "Taal"),
    ("settings.theme", "Theme", "Thema"),
    ("settings.theme_system", "System", "Systeem"),
    ("settings.theme_light", "Light", "Licht"),
    ("settings.theme_dark", "Dark", "Donker"),
    ("settings.import", "Import", "Importeren"),
    ("settings.export", "Backup & export", "Back-up en export"),
    ("backup.last", "Last backup on this device", "Laatste back-up op dit apparaat"),
    ("backup.never", "Never", "Nog nooit"),
    ("backup.remind", "Backup reminder", "Herinnering voor een back-up"),
    ("backup.remind_desc", "2Secret reminds you when your last backup is this old.", "2Secret herinnert je eraan als je laatste back-up zo oud is."),
    ("backup.every_2_weeks", "Every 2 weeks", "Elke 2 weken"),
    ("backup.every_month", "Every month", "Elke maand"),
    ("backup.every_3_months", "Every 3 months", "Elke 3 maanden"),
    ("backup.explain", "A backup is a copy of all your vaults in one file, encrypted with a password you choose. Keep it somewhere safe, for example on a USB stick. If a device is lost or a server stops for good, you can import it again (Settings → Import), on any device.", "Een back-up is een kopie van al je kluizen in één bestand, versleuteld met een wachtwoord dat je zelf kiest. Bewaar hem op een veilige plek, bijvoorbeeld op een usb-stick. Raakt een apparaat kwijt of stopt een server voorgoed, dan kun je hem op elk apparaat weer importeren (Instellingen → Importeren)."),
    ("backup.password_hint", "Choose a strong password you will remember: without it the backup cannot be opened, also not by 2Secret.", "Kies een sterk wachtwoord dat je onthoudt: zonder dat wachtwoord kan niemand de back-up openen, ook 2Secret niet."),
    ("backup.make", "Make a backup", "Back-up maken"),
    ("backup.later", "Later", "Later"),
    ("backup.reminder_title", "Time for a backup", "Tijd voor een back-up"),
    ("backup.reminder_never", "You have not made a backup of your vaults on this device yet. Keep your own encrypted copy, in case a device or server fails.", "Je hebt op dit apparaat nog geen back-up van je kluizen gemaakt. Bewaar zelf een versleutelde kopie, voor als een apparaat of server uitvalt."),
    ("backup.reminder_since", "Your last backup is from {date}. Make a new one so your recent changes are in it too.", "Je laatste back-up is van {date}. Maak een nieuwe, zodat ook je recente wijzigingen erin staan."),
    ("settings.about", "About", "Over"),
    ("settings.danger", "Danger zone", "Gevarenzone"),
    ("settings.delete_account", "Delete server account", "Serveraccount verwijderen"),
    ("settings.delete_account_desc", "Permanently deletes your account and vaults you own from the server. This device keeps a local copy.", "Verwijdert je account en kluizen die je bezit definitief van de server. Dit apparaat houdt een lokale kopie."),
    ("settings.delete_account_confirm", "Delete my account permanently", "Mijn account definitief verwijderen"),
    ("settings.forget", "Remove from this device", "Verwijderen van dit apparaat"),
    ("settings.forget_desc", "Removes the account and all its data from this device.", "Verwijdert het account en alle gegevens van dit apparaat."),
    ("settings.forget_button", "Remove", "Verwijderen"),
    ("forget.local_warning", "This is a local-only account. Unless you exported it, all its data will be lost forever.", "Dit is een alleen-lokaal account. Tenzij je het hebt geëxporteerd, gaan alle gegevens voorgoed verloren."),
    ("forget.server_info", "Your data stays safe on the sync server. You can sign in again with your Emergency Kit.", "Je gegevens blijven veilig op de synchronisatieserver. Je kunt opnieuw inloggen met je noodkit."),

    // Import / export
    ("import.desc", "Import from 1Password (.1pux, .csv), Bitwarden (.json, .csv), LastPass, Chrome, Edge, Firefox, Safari, KeePass (.xml), KeePassXC, Dashlane or a 2Secret export.", "Importeer uit 1Password (.1pux, .csv), Bitwarden (.json, .csv), LastPass, Chrome, Edge, Firefox, Safari, KeePass (.xml), KeePassXC, Dashlane of een 2Secret-export."),
    ("import.format", "Format", "Formaat"),
    ("import.auto", "Detect automatically", "Automatisch herkennen"),
    ("import.target", "Import into", "Importeren in"),
    ("import.target_auto", "Keep the vaults from the file", "Kluizen uit het bestand behouden"),
    ("import.password", "Password of the export", "Wachtwoord van de export"),
    ("import.run", "Import", "Importeren"),
    ("import.imported", "items imported", "items geïmporteerd"),
    ("import.duplicates", "duplicates skipped", "dubbele overgeslagen"),
    ("import.warnings", "entries could not be imported", "items konden niet worden geïmporteerd"),
    ("import.unknown_format", "The file format was not recognised. Choose it manually.", "Het bestandsformaat is niet herkend. Kies het handmatig."),
    ("export.encrypted", "Encrypted 2Secret backup (recommended)", "Versleutelde 2Secret-back-up (aanbevolen)"),
    ("export.json", "2Secret JSON (unencrypted)", "2Secret JSON (onversleuteld)"),
    ("export.csv", "CSV (unencrypted)", "CSV (onversleuteld)"),
    ("export.password", "Password for the backup", "Wachtwoord voor de back-up"),
    ("export.plain_warning", "Unencrypted exports contain all your secrets in plain text. Delete the file as soon as you no longer need it.", "Onversleutelde exports bevatten al je geheimen als leesbare tekst. Verwijder het bestand zodra je het niet meer nodig hebt."),
    ("export.run", "Export", "Exporteren"),

    // About
    ("update.title", "Updates", "Updates"),
    ("update.check", "Check now", "Nu controleren"),
    ("update.checking", "Checking for updates…", "Zoeken naar updates…"),
    ("update.idle", "Not checked yet.", "Nog niet gecontroleerd."),
    ("update.up_to_date", "2Secret is up to date.", "2Secret is up-to-date."),
    ("update.available", "2Secret {version} is available.", "2Secret {version} is beschikbaar."),
    ("update.downloading", "Downloading 2Secret {version}…", "2Secret {version} wordt gedownload…"),
    ("update.ready", "2Secret {version} has been downloaded and is installed when 2Secret starts again.", "2Secret {version} is gedownload en wordt geïnstalleerd zodra 2Secret opnieuw start."),
    ("update.failed", "Updating failed:", "Bijwerken mislukt:"),
    ("update.install", "Install", "Installeren"),
    ("update.download", "Download", "Downloaden"),
    ("update.restart", "Restart now", "Nu herstarten"),
    ("update.whats_new", "What's new", "Wat is er nieuw"),
    ("update.manual", "2Secret cannot replace itself in this installation: download the new version and install it.", "2Secret kan zichzelf in deze installatie niet vervangen: download de nieuwe versie en installeer die."),
    ("update.auto_install", "Update automatically", "Automatisch bijwerken"),
    ("update.auto_install_desc", "Checks once a day and installs new versions when 2Secret starts. Only updates signed by 2Secret are installed. Checking contacts GitHub, where 2Secret is published.", "Controleert dagelijks en installeert nieuwe versies wanneer 2Secret start. Alleen updates met de handtekening van 2Secret worden geïnstalleerd. Voor de controle maakt 2Secret verbinding met GitHub, waar 2Secret gepubliceerd wordt."),
    ("update.auto_notify", "Check for updates automatically", "Automatisch op updates controleren"),
    ("update.auto_notify_desc", "Checks once a day and lets you know when a new version is available. Checking contacts GitHub, where 2Secret is published.", "Controleert dagelijks en meldt het als er een nieuwe versie is. Voor de controle maakt 2Secret verbinding met GitHub, waar 2Secret gepubliceerd wordt."),
    ("update.toast_ready", "2Secret {version} has been downloaded and is installed when 2Secret starts again.", "2Secret {version} is gedownload en wordt geïnstalleerd zodra 2Secret opnieuw start."),
    ("update.toast_available", "2Secret {version} is available (Settings → Updates).", "2Secret {version} is beschikbaar (Instellingen → Updates)."),
    ("update.no_file", "This version has no download for this device.", "Deze versie heeft geen download voor dit apparaat."),
    ("update.gone", "The downloaded update is missing or damaged; check again.", "De gedownloade update ontbreekt of is beschadigd; controleer opnieuw."),
    ("update.interrupted", "The update could not be installed. Download the new version from the website instead.", "De update kon niet worden geïnstalleerd. Download de nieuwe versie via de website."),
    ("about.text", "2Secret is free and open-source. Your data is encrypted on your device with XChaCha20-Poly1305; keys are derived from your master password (Argon2id) combined with your Secret Key. The sync server only ever sees encrypted data.", "2Secret is gratis en open source. Je gegevens worden op je apparaat versleuteld met XChaCha20-Poly1305; sleutels worden afgeleid van je hoofdwachtwoord (Argon2id) gecombineerd met je geheime sleutel. De synchronisatieserver ziet alleen versleutelde gegevens."),

    // Browser extension
    ("ext.fill", "Fill", "Invullen"),
    ("ext.suggestions", "Suggestions for", "Suggesties voor"),
    ("ext.nothing_to_fill", "No login form found on this page.", "Geen inlogformulier gevonden op deze pagina."),
    (
        "ext.wrong_site",
        "This item is not saved for this website. Add the website to the item to fill it here.",
        "Dit item hoort niet bij deze website. Voeg de website toe aan het item om hier in te vullen.",
    ),

    // Toasts
    ("toast.copied", "copied", "gekopieerd"),
    ("toast.saved", "Saved", "Opgeslagen"),
    ("toast.saved_to", "Saved:", "Opgeslagen:"),
    ("toast.synced", "Synced", "Gesynchroniseerd"),
    ("toast.trashed", "Moved to trash", "Naar prullenbak verplaatst"),
    ("toast.restored", "Restored", "Teruggezet"),
    ("toast.duplicated", "Duplicated", "Gedupliceerd"),
    ("toast.moved", "Moved", "Verplaatst"),
    ("toast.deleted_items", "items deleted", "items verwijderd"),
    ("toast.password_changed", "Master password changed", "Hoofdwachtwoord gewijzigd"),
    ("toast.connected", "Connected to the server", "Verbonden met de server"),
    ("toast.device_removed", "Device signed out", "Apparaat uitgelogd"),
    ("toast.account_deleted", "Server account deleted", "Serveraccount verwijderd"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_duplicate_keys() {
        let mut keys: Vec<&str> = TABLE.iter().map(|e| e.0).collect();
        let n = keys.len();
        keys.sort();
        keys.dedup();
        assert_eq!(n, keys.len(), "duplicate translation keys");
    }

    #[test]
    fn dynamic_keys_exist() {
        let map = table();
        for c in Category::ALL {
            assert!(map.contains_key(format!("cat.{}", c.id()).as_str()), "{c:?}");
            for f in c.template() {
                assert!(map.contains_key(format!("field.{}", f.id).as_str()), "field.{}", f.id);
            }
        }
        for k in FieldKind::ALL {
            assert!(map.contains_key(format!("kind.{}", k.id()).as_str()));
        }
        for k in IssueKind::ALL {
            assert!(map.contains_key(format!("issue.{}", k.id()).as_str()));
            assert!(map.contains_key(format!("issue.{}.desc", k.id()).as_str()));
        }
    }

    #[test]
    fn all_used_keys_exist() {
        let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut missing = Vec::new();
        let mut stack = vec![src_dir];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                let text = std::fs::read_to_string(&path).unwrap().replace("\\\"", "\"");
                for part in text.split("t(\"").skip(1) {
                    let key: String = part.chars().take_while(|c| *c != '"').collect();
                    if key.contains('.') && !key.contains('{') && !table().contains_key(key.as_str()) {
                        missing.push(key);
                    }
                }
            }
        }
        assert!(missing.is_empty(), "missing translations: {missing:?}");
    }
}
