import AuthenticationServices
import CryptoKit
import Foundation
import LocalAuthentication
import Security

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
    let passkeys: [Passkey]
    /// The login's one-time password, if it has one.
    let totp: OneTimePassword?
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

    /// Read the cache. The key is in the keychain and only released after
    /// Face ID / Touch ID, so this shows the system prompt; call it off the
    /// main thread.
    static func load(reason: String) throws -> AutofillCache {
        guard !appGroup.isEmpty,
              let dir = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup),
              let sealed = try? Data(contentsOf: dir.appendingPathComponent("autofill.cache"))
        else { throw VaultError.notSetUp }

        let context = LAContext()
        context.localizedReason = reason
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

    static let reason = t("fill with 2Secret", "invullen met 2Secret")
    static let cancel = t("Cancel", "Annuleren")
    static let close = t("Close", "Sluiten")
    static let search = t("Search", "Zoeken")
    static let unlocking = t("Unlocking…", "Ontgrendelen…")
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
