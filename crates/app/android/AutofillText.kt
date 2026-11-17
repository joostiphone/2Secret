// What AutoFill says, in English and Dutch after the phone's language (the
// app's own texts are in crates/app/src/i18n.rs).
package dev.dioxus.main

import java.util.Locale

object AutofillText {
    private val dutch: Boolean get() = Locale.getDefault().language == "nl"

    private fun t(en: String, nl: String): String = if (dutch) nl else en

    val fillWith: String get() = t("Fill with 2Secret", "Invullen met 2Secret")

    /** Under "2Secret" in the fingerprint or face prompt. */
    fun reason(site: String): String =
        if (site.isEmpty()) {
            t("Unlock your vault", "Je kluis ontgrendelen")
        } else {
            t("Unlock your vault for $site", "Je kluis ontgrendelen voor $site")
        }

    val unlocking: String get() = t("Unlocking…", "Ontgrendelen…")
    val search: String get() = t("Search", "Zoeken")
    val suggested: String get() = t("Suggested", "Voorgesteld")
    val all: String get() = t("All logins", "Alle logins")
    val showAll: String get() = t("Show all logins", "Alle logins tonen")

    fun noneFor(site: String): String = t("No logins for $site.", "Geen logins voor $site.")

    val nothing: String get() = t("No logins found.", "Geen logins gevonden.")
    val cancel: String get() = t("Cancel", "Annuleren")
    val close: String get() = t("Close", "Sluiten")
    val tryAgain: String get() = t("Try again", "Probeer opnieuw")

    val notSetUp: String
        get() = t(
            "Open 2Secret and turn on unlocking with fingerprint or face (Settings → Security) to use AutoFill.",
            "Open 2Secret en zet ontgrendelen met vingerafdruk of gezicht aan (Instellingen → Beveiliging) om automatisch invullen te gebruiken.",
        )
    val keyGone: String
        get() = t(
            "The fingerprints or faces on this phone changed. Open 2Secret, enter your master password and turn on unlocking with fingerprint or face again.",
            "De vingerafdrukken of gezichten op deze telefoon zijn gewijzigd. Open 2Secret, vul je hoofdwachtwoord in en zet ontgrendelen met vingerafdruk of gezicht weer aan.",
        )
    val passwordNeeded: String
        get() = t(
            "Open 2Secret and enter your master password. 2Secret asks for it every 14 days, so you will not forget it.",
            "Open 2Secret en vul je hoofdwachtwoord in. 2Secret vraagt er elke 14 dagen om, zodat je het niet vergeet.",
        )
    val notNow: String
        get() = t(
            "Your fingerprint or face could not be asked just now.",
            "Je vingerafdruk of gezicht kon zojuist niet worden gevraagd.",
        )
    val lockout: String
        get() = t(
            "Fingerprint or face is locked after too many attempts. Unlock the phone with its PIN, pattern or password, then try again.",
            "Vingerafdruk of gezicht is geblokkeerd na te veel pogingen. Ontgrendel de telefoon met je pincode, patroon of wachtwoord en probeer het dan opnieuw.",
        )
    val unavailable: String
        get() = t(
            "Fingerprint or face is not available on this phone right now.",
            "Vingerafdruk of gezicht is nu niet beschikbaar op deze telefoon.",
        )

    fun failed(detail: String): String = t("Unlocking did not work ($detail).", "Ontgrendelen lukte niet ($detail).")
}
