// The login fields of a screen in another app or of a web page, as Android's
// AutoFill describes them (an AssistStructure), and whose they are.
package dev.dioxus.main

import android.annotation.TargetApi
import android.app.assist.AssistStructure
import android.os.Build
import android.text.InputType
import android.view.View
import android.view.autofill.AutofillId

@TargetApi(Build.VERSION_CODES.O)
class AutofillFields private constructor(
    val username: AutofillId?,
    val password: AutofillId?,
    /** The host of the web page the fields are on (lower case), or null in an app. */
    val webDomain: String?,
    /** The app that shows them (for a web page: the browser). */
    val packageName: String,
) {
    val ids: List<AutofillId> get() = listOfNotNull(username, password)

    fun isEmpty(): Boolean = username == null && password == null

    private enum class Kind { USERNAME, PASSWORD, TEXT, OTHER }

    /** What the walk through the screen found, with the web page of each. */
    private class Walk {
        var username: AutofillId? = null
        var usernameDomain: String? = null
        var password: AutofillId? = null
        var passwordDomain: String? = null
        var lastText: AutofillId? = null
        var lastTextDomain: String? = null
        var textBeforePassword: AutofillId? = null
        var textBeforePasswordDomain: String? = null
    }

    companion object {
        private val PASSWORD_WORDS = listOf("password", "passwd", "passwort", "wachtwoord", "kennwort", "contrase", "pwd")
        private val USERNAME_WORDS =
            listOf("user", "email", "e-mail", "mail", "login", "account", "gebruiker", "benutzer", "identifiant")
        private val OTHER_WORDS = listOf("search", "zoek", "captcha", "otp", "one-time", "2fa", "coupon", "promo")
        private val OTHER_HINTS = listOf("creditcard", "otp", "postal", "phone", "birth", "gift", "promo", "search")
        private val NOT_TEXT = setOf(
            "hidden", "submit", "button", "checkbox", "radio", "search", "number", "date", "file", "image",
            "reset", "range", "color", "url", "tel", "time", "month", "week", "datetime-local",
        )

        fun parse(structure: AssistStructure): AutofillFields {
            val walk = Walk()
            for (i in 0 until structure.windowNodeCount) {
                visit(structure.getWindowNodeAt(i).rootViewNode, null, walk)
            }
            var username = walk.username
            var domain = walk.usernameDomain
            if (walk.password != null) {
                domain = walk.passwordDomain
                // Never a user name field of another page (an embedded frame)
                // with the password; without a marked one, the text field
                // right before the password.
                if (username != null && walk.usernameDomain != walk.passwordDomain) username = null
                if (username == null && walk.textBeforePasswordDomain == walk.passwordDomain) {
                    username = walk.textBeforePassword
                }
            }
            return AutofillFields(username, walk.password, domain, structure.activityComponent?.packageName ?: "")
        }

        private fun visit(node: AssistStructure.ViewNode, inherited: String?, walk: Walk) {
            val domain = node.webDomain?.trim()?.trimEnd('.')?.lowercase()?.takeIf { it.isNotEmpty() } ?: inherited
            val id = node.autofillId
            if (id != null && node.autofillType == View.AUTOFILL_TYPE_TEXT && node.visibility == View.VISIBLE) {
                when (kind(node)) {
                    Kind.PASSWORD -> if (walk.password == null) {
                        walk.password = id
                        walk.passwordDomain = domain
                        walk.textBeforePassword = walk.lastText
                        walk.textBeforePasswordDomain = walk.lastTextDomain
                    }
                    Kind.USERNAME -> if (walk.username == null) {
                        walk.username = id
                        walk.usernameDomain = domain
                    }
                    Kind.TEXT -> if (walk.password == null) {
                        walk.lastText = id
                        walk.lastTextDomain = domain
                    }
                    Kind.OTHER -> {}
                }
            }
            for (i in 0 until node.childCount) visit(node.getChildAt(i), domain, walk)
        }

        private fun has(text: String, words: List<String>): Boolean = words.any { text.contains(it) }

        private fun kind(node: AssistStructure.ViewNode): Kind {
            // What the app or page says the field is for.
            val hints = node.autofillHints?.map { it.lowercase() }.orEmpty()
            if (hints.any { it.contains("password") }) return Kind.PASSWORD
            if (hints.any { it.contains("username") || it.contains("email") }) return Kind.USERNAME
            if (hints.any { hint -> OTHER_HINTS.any { hint.contains(it) } }) return Kind.OTHER

            // Web pages: the input element.
            val html = node.htmlInfo
            if (html != null) {
                if (html.tag.lowercase() != "input") return Kind.OTHER
                val attributes = html.attributes.orEmpty()
                    .associate { (it.first ?: "").lowercase() to (it.second ?: "").lowercase() }
                val type = attributes["type"].orEmpty()
                val autocomplete = attributes["autocomplete"].orEmpty()
                val words = listOf("name", "id", "placeholder", "aria-label")
                    .joinToString(" ") { attributes[it].orEmpty() }
                return when {
                    type == "password" -> Kind.PASSWORD
                    autocomplete.contains("one-time-code") || autocomplete.contains("cc-") -> Kind.OTHER
                    autocomplete.contains("username") || autocomplete.contains("email") || type == "email" -> Kind.USERNAME
                    type in NOT_TEXT || has(words, OTHER_WORDS) -> Kind.OTHER
                    has(words, USERNAME_WORDS) -> Kind.USERNAME
                    else -> Kind.TEXT
                }
            }

            // Apps: the input type, the view's id and its hint text.
            val inputType = node.inputType
            val type = inputType and InputType.TYPE_MASK_CLASS
            val variation = inputType and InputType.TYPE_MASK_VARIATION
            val text = type == InputType.TYPE_CLASS_TEXT
            val words = listOfNotNull(node.idEntry, node.hint).joinToString(" ").lowercase()
            return when {
                text && (variation == InputType.TYPE_TEXT_VARIATION_PASSWORD ||
                    variation == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD) -> Kind.PASSWORD
                has(words, OTHER_WORDS) -> Kind.OTHER
                type == InputType.TYPE_CLASS_NUMBER && variation == InputType.TYPE_NUMBER_VARIATION_PASSWORD &&
                    has(words, PASSWORD_WORDS) -> Kind.PASSWORD
                text && has(words, PASSWORD_WORDS) -> Kind.PASSWORD
                text && (variation == InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS ||
                    variation == InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS) -> Kind.USERNAME
                (text || type == InputType.TYPE_CLASS_NUMBER) && has(words, USERNAME_WORDS) -> Kind.USERNAME
                // Apps use it to turn off suggestions in user name fields too.
                text && variation == InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD -> Kind.PASSWORD
                text -> Kind.TEXT
                else -> Kind.OTHER
            }
        }
    }
}
