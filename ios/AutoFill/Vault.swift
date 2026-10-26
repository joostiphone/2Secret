import AuthenticationServices
import CryptoKit
import Foundation
import LocalAuthentication
import Security
#if os(macOS)
import AppKit
#else
import UIKit
#endif

/// What the 2Secret app shares with AutoFill (crates/core/src/autofill.rs).
struct AutofillCache: Decodable {
    let version: Int
    let accountId: String
    let passwordEnteredAt: Int64
    let logins: [Login]
}

struct Login: Decodable {
    let id: String
    let title: String
    let username: String
    let password: String
    /// Registrable domains of the login's websites, e.g. "example.co.uk".
    let domains: [String]
    /// Websites whose host is itself a public suffix, e.g. "github.io": that
    /// host only, never a subdomain (someone else's site).
    let exactHosts: [String]?
    let passkeys: [Passkey]
    /// The login's one-time password, if it has one.
    let totp: OneTimePassword?
    /// The website's icon as a `data:image/…;base64,…` URL, when the app has one.
    let icon: String?

    /// Whether the login is for the page or app: one of its domains is among
    /// `candidates` (see `Vault.candidates`), or an exact host is in `hosts`.
    func isFor(candidates: Set<String>, hosts: Set<String>) -> Bool {
        !Set(domains).isDisjoint(with: candidates) || !Set(exactHosts ?? []).isDisjoint(with: hosts)
    }
}

struct Passkey: Decodable {
    let credentialId: String
    let rpId: String
    let userHandle: String
    let userName: String
    /// PKCS #8, base64url.
    let privateKey: String
}

/// A time-based one-time password (RFC 6238), like `Totp` in the Rust core.
struct OneTimePassword: Decodable {
    /// The shared secret, base64url.
    let secret: String
    /// "SHA1", "SHA256" or "SHA512".
    let algorithm: String
    let digits: Int
    let period: Int
    /// Steam Guard: five characters from Steam's alphabet instead of digits.
    let steam: Bool

    private static let steamAlphabet = Array("23456789BCDFGHJKMNPQRTVWXY")

    /// The code valid at `date`, like `Totp::code_at`.
    func code(at date: Date = Date()) -> String? {
        guard let bytes = Vault.data(base64url: secret), period > 0, (1 ... 10).contains(digits) else { return nil }
        let counter = UInt64(max(0, date.timeIntervalSince1970)) / UInt64(period)
        let message = withUnsafeBytes(of: counter.bigEndian) { Data($0) }
        let key = SymmetricKey(data: bytes)
        let hash: [UInt8]
        switch algorithm {
        case "SHA256":
            hash = Array(HMAC<SHA256>.authenticationCode(for: message, using: key))
        case "SHA512":
            hash = Array(HMAC<SHA512>.authenticationCode(for: message, using: key))
        default:
            hash = Array(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: key))
        }
        let offset = Int(hash[hash.count - 1] & 0x0F)
        var value = UInt32(hash[offset] & 0x7F) << 24 | UInt32(hash[offset + 1]) << 16
            | UInt32(hash[offset + 2]) << 8 | UInt32(hash[offset + 3])
        if steam {
            var out = ""
            for _ in 0 ..< 5 {
                out.append(Self.steamAlphabet[Int(value % UInt32(Self.steamAlphabet.count))])
                value /= UInt32(Self.steamAlphabet.count)
            }
            return out
        }
        var modulo: UInt64 = 1
        for _ in 0 ..< digits {
            modulo *= 10
        }
        let number = String(UInt64(value) % modulo)
        return String(repeating: "0", count: digits - number.count) + number
    }
}

enum VaultError: Error {
    /// No cache yet: biometric unlock is off, or the app was not opened.
    case notSetUp
    /// The master password was not entered for 14 days.
    case passwordNeeded
    case cancelled
    case failed(String)
}

/// Shared by the iOS (ios/AutoFill) and macOS (macos/AutoFill) extensions.
enum Vault {
    #if os(macOS)
    /// "<Team ID>.io.github.joostiphone.twosecret" (app groups on macOS start
    /// with the Team ID), written into Info.plist by scripts/macos-sign.sh.
    static let appGroup = Bundle.main.object(forInfoDictionaryKey: "TwoSecretAppGroup") as? String ?? ""
    #else
    static let appGroup = "group.io.github.joostiphone.twosecret"
    #endif
    static let maxAge: Int64 = 14 * 86_400

    /// One context for the whole process: a Touch ID or Face ID given a
    /// moment ago is reused for up to five minutes, so two fills in a row ask
    /// once, as long as the system keeps the extension alive in between.
    private static let context: LAContext = {
        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = LATouchIDAuthenticationMaximumAllowableReuseDuration
        return context
    }()

    private static var container: URL? {
        guard !appGroup.isEmpty else { return nil }
        return FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup)
    }

    /// The theme the app uses (`system`, `light` or `dark`), which it writes
    /// next to the cache so the panel matches before the vault is unlocked.
    static func theme() -> String {
        guard let dir = container,
              let text = try? String(contentsOf: dir.appendingPathComponent("autofill.theme"), encoding: .utf8)
        else { return "system" }
        return text.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// The bytes of a website icon (`data:image/…;base64,…`), for the image
    /// types the panel shows. SVG is left out: UIKit cannot draw it.
    static func imageData(dataURL: String?) -> Data? {
        guard let dataURL, dataURL.hasPrefix("data:image/"), let marker = dataURL.range(of: ";base64,") else { return nil }
        let mime = String(dataURL[dataURL.index(dataURL.startIndex, offsetBy: 5) ..< marker.lowerBound])
        guard ["image/png", "image/jpeg", "image/gif", "image/webp", "image/x-icon"].contains(mime) else { return nil }
        return Data(base64Encoded: String(dataURL[marker.upperBound...]))
    }

    /// Read the cache. The key is in the keychain and only released after
    /// Face ID / Touch ID, so this shows the system prompt; call it off the
    /// main thread.
    static func load(reason: String) throws -> AutofillCache {
        guard let dir = container,
              let sealed = try? Data(contentsOf: dir.appendingPathComponent("autofill.cache"))
        else { throw VaultError.notSetUp }

        let context = Self.context
        context.localizedReason = reason
        context.localizedCancelTitle = L.cancel
        #if os(macOS)
        // Where the app keeps the key: access groups and Touch ID protection
        // need the data protection keychain, which macOS only uses when asked.
        let keychain: [CFString: Any] = [kSecUseDataProtectionKeychain: true]
        #else
        let keychain: [CFString: Any] = [:]
        #endif
        let query = keychain.merging([
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: "2Secret AutoFill",
            kSecAttrAccount: "cache-key",
            kSecAttrAccessGroup: appGroup,
            kSecReturnData: true,
            kSecUseAuthenticationContext: context,
        ]) { _, new in new }
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            break
        case errSecItemNotFound:
            throw VaultError.notSetUp
        case errSecUserCanceled:
            throw VaultError.cancelled
        default:
            throw VaultError.failed("keychain error \(status)")
        }
        guard let keyData = result as? Data, keyData.count == 32 else { throw VaultError.notSetUp }

        let json: Data
        do {
            let box = try ChaChaPoly.SealedBox(combined: sealed)
            json = try ChaChaPoly.open(box, using: SymmetricKey(data: keyData), authenticating: Data("2secret/v1/autofill".utf8))
        } catch {
            throw VaultError.notSetUp
        }
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        let cache = try decoder.decode(AutofillCache.self, from: json)
        let age = Int64(Date().timeIntervalSince1970) - cache.passwordEnteredAt
        guard age >= 0, age < maxAge else { throw VaultError.passwordNeeded }
        return cache
    }

    /// The domains a page or app may use logins of: its host and each parent
    /// domain (the logins only hold registrable domains, never "co.uk").
    static func candidates(_ identifiers: [ASCredentialServiceIdentifier]) -> Set<String> {
        var out = Set<String>()
        for id in identifiers {
            var host = id.identifier
            if id.type == .URL, let h = URL(string: id.identifier)?.host {
                host = h
            }
            var labels = host.lowercased().split(separator: ".").map(String.init)
            while labels.count >= 2 {
                out.insert(labels.joined(separator: "."))
                labels.removeFirst()
            }
        }
        return out
    }

    /// The hosts of a page or app themselves, for logins that only match
    /// exactly (`Login.exactHosts`).
    static func hosts(_ identifiers: [ASCredentialServiceIdentifier]) -> Set<String> {
        var out = Set<String>()
        for id in identifiers {
            var host = id.identifier
            if id.type == .URL, let h = URL(string: id.identifier)?.host {
                host = h
            }
            out.insert(host.lowercased())
        }
        return out
    }

    static func data(base64url text: String) -> Data? {
        var s = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while s.count % 4 != 0 { s += "=" }
        return Data(base64Encoded: s)
    }

    /// Sign in with a passkey, like `passkey::assert` in the Rust core.
    static func assertion(_ passkey: Passkey, clientDataHash: Data) throws -> ASPasskeyAssertionCredential {
        guard let der = data(base64url: passkey.privateKey),
              let credentialID = data(base64url: passkey.credentialId),
              let userHandle = data(base64url: passkey.userHandle)
        else { throw VaultError.failed("damaged passkey") }
        let key = try P256.Signing.PrivateKey(derRepresentation: der)
        var authenticatorData = Data(SHA256.hash(data: Data(passkey.rpId.utf8)))
        // User present, user verified (Face ID), backup eligible, backed up.
        authenticatorData.append(0x1D)
        authenticatorData.append(contentsOf: [0, 0, 0, 0])
        let signature = try key.signature(for: authenticatorData + clientDataHash)
        return ASPasskeyAssertionCredential(
            userHandle: userHandle,
            relyingParty: passkey.rpId,
            signature: signature.derRepresentation,
            clientDataHash: clientDataHash,
            authenticatorData: authenticatorData,
            credentialID: credentialID
        )
    }
}

/// English and Dutch, following the system language.
enum L {
    private static let dutch = Locale.preferredLanguages.first?.hasPrefix("nl") ?? false
    private static func t(_ en: String, _ nl: String) -> String { dutch ? nl : en }

    /// The reason in the system's Touch ID / Face ID dialog, which starts
    /// with "2Secret is trying to" (Dutch: "2Secret probeert").
    static func reason(host: String?) -> String {
        if let host, !host.isEmpty {
            return t("unlock your vault for \(host)", "je kluis te ontgrendelen voor \(host)")
        }
        return t("unlock your vault", "je kluis te ontgrendelen")
    }

    static func forSite(_ host: String) -> String { t("for \(host)", "voor \(host)") }
    static let cancel = t("Cancel", "Annuleren")
    static let close = t("Close", "Sluiten")
    static let search = t("Search", "Zoeken")
    #if os(macOS)
    static let unlocking = t("Unlocking with Touch ID…", "Ontgrendelen met Touch ID…")
    #else
    static let unlocking = t("Unlocking…", "Ontgrendelen…")
    #endif
    static let suggested = t("Suggested", "Voorgesteld")
    static let all = t("All logins", "Alle logins")
    static let passkeys = t("Passkeys", "Passkeys")
    static let nothing = t("No logins found.", "Geen logins gevonden.")
    static let noCodes = t(
        "No logins with a one-time password found. Add one to a login in 2Secret.",
        "Geen logins met een eenmalig wachtwoord gevonden. Voeg er een toe aan een login in 2Secret."
    )
    #if os(macOS)
    static let notSetUp = t(
        "Open 2Secret and turn on unlocking with Touch ID (Settings → Security) to use AutoFill.",
        "Open 2Secret en zet ontgrendelen met Touch ID aan (Instellingen → Beveiliging) om automatisch invullen te gebruiken."
    )
    #else
    static let notSetUp = t(
        "Open 2Secret and turn on unlocking with Face ID or Touch ID (Settings → Security) to use AutoFill.",
        "Open 2Secret en zet ontgrendelen met Face ID of Touch ID aan (Instellingen → Beveiliging) om automatisch invullen te gebruiken."
    )
    #endif
    static let passwordNeeded = t(
        "Open 2Secret and enter your master password. 2Secret asks for it every 14 days, so you will not forget it.",
        "Open 2Secret en vul je hoofdwachtwoord in. 2Secret vraagt er elke 14 dagen om, zodat je het niet vergeet."
    )
    #if os(macOS)
    static let configured = t(
        "2Secret can now fill passwords and passkeys. Turn on unlocking with Touch ID in the 2Secret app (Settings → Security), then open 2Secret once.",
        "2Secret kan nu wachtwoorden en passkeys invullen. Zet ontgrendelen met Touch ID aan in de 2Secret-app (Instellingen → Beveiliging) en open 2Secret één keer."
    )
    static let registerElsewhere = t(
        "Save new passkeys with the 2Secret browser extension in Chrome, Edge, Brave or Firefox. They then sync to this Mac and your other devices.",
        "Bewaar nieuwe passkeys met de 2Secret-browserextensie in Chrome, Edge, Brave of Firefox. Ze synchroniseren dan naar deze Mac en je andere apparaten."
    )
    #else
    static let configured = t(
        "2Secret can now fill passwords and passkeys. Turn on unlocking with Face ID or Touch ID in the 2Secret app (Settings → Security), then open 2Secret once.",
        "2Secret kan nu wachtwoorden en passkeys invullen. Zet ontgrendelen met Face ID of Touch ID aan in de 2Secret-app (Instellingen → Beveiliging) en open 2Secret één keer."
    )
    static let registerElsewhere = t(
        "Save new passkeys with the 2Secret browser extension on your computer. They then sync to this device.",
        "Bewaar nieuwe passkeys met de 2Secret-browserextensie op je computer. Ze synchroniseren dan naar dit apparaat."
    )
    #endif
}

#if os(macOS)
typealias BrandColor = NSColor
typealias BrandImage = NSImage
#else
typealias BrandColor = UIColor
typealias BrandImage = UIImage
#endif

/// The app's look (crates/app/src/style.css): its colours for light and dark,
/// and its logo. The colours follow the panel's appearance.
enum Brand {
    static let bg = color(light: 0xF4F5F8, dark: 0x11131A)
    static let panel = color(light: 0xFFFFFF, dark: 0x181B24)
    static let panel2 = color(light: 0xF8F9FB, dark: 0x1D2130)
    static let text = color(light: 0x1A1D26, dark: 0xE7E9EF)
    static let muted = color(light: 0x687083, dark: 0x959CB0)
    static let border = color(light: 0xE2E5EC, dark: 0x2A2F3E)
    static let accent = color(light: 0x3B5BDB, dark: 0x5C7CFA)
    static let accentSoft = color(light: 0xE7ECFF, dark: 0x232B4F)
    static let selected = color(light: 0xE5EBFF, dark: 0x27305A)
    static let selectedText = color(light: 0x2741B8, dark: 0xC5D0FF)
    static let radius: CGFloat = 10

    private static func channels(_ hex: UInt32) -> (CGFloat, CGFloat, CGFloat) {
        (CGFloat((hex >> 16) & 0xFF) / 255, CGFloat((hex >> 8) & 0xFF) / 255, CGFloat(hex & 0xFF) / 255)
    }

    #if os(macOS)
    private static func color(light: UInt32, dark: UInt32) -> NSColor {
        NSColor(name: nil) { appearance in
            let isDark = appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua
            let (r, g, b) = channels(isDark ? dark : light)
            return NSColor(srgbRed: r, green: g, blue: b, alpha: 1)
        }
    }

    /// The app icon, bundled with the extension (macos/project.yml).
    static let logo: NSImage? = Bundle.main.image(forResource: "icon-128")
    #else
    private static func color(light: UInt32, dark: UInt32) -> UIColor {
        UIColor { traits in
            let (r, g, b) = channels(traits.userInterfaceStyle == .dark ? dark : light)
            return UIColor(red: r, green: g, blue: b, alpha: 1)
        }
    }

    /// The app icon, bundled with the extension (ios/project.yml).
    static let logo: UIImage? = UIImage(named: "icon-128")
    #endif
}
