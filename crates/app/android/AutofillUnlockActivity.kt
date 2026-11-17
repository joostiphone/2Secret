// Opened by Android when the person picks "Fill with 2Secret" on a login
// screen (TwoSecretAutofillService). It asks for a fingerprint or face, whose
// check unlocks the store's key (AutofillStore), lists the logins for the
// page or app first ("Suggested", by registrable domain or app), the others
// on request, and hands Android the one the person picks. Nothing is chosen
// for them: a login only goes to the other app after a tap on it. Android
// opens this screen through 2Secret's own PendingIntent; other apps cannot
// (exported="false").
package dev.dioxus.main

import android.annotation.TargetApi
import android.app.Activity
import android.app.assist.AssistStructure
import android.content.Intent
import android.content.res.ColorStateList
import android.content.res.Configuration
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.RippleDrawable
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.Bundle
import android.os.CancellationSignal
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.service.autofill.Dataset
import android.text.Editable
import android.text.TextUtils
import android.text.TextWatcher
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.RemoteViews
import android.widget.ScrollView
import android.widget.TextView
import java.util.Arrays
import javax.crypto.Cipher

@TargetApi(Build.VERSION_CODES.P)
class AutofillUnlockActivity : Activity() {
    private var fields: AutofillFields? = null
    /** The page's host or the app's name, for the header and the prompt. */
    private var site = ""
    private var logins: List<AutofillStore.Login> = emptyList()
    private var unlocked = false
    private var showAll = false
    private var asked = false
    private var retried = false
    private var signal: CancellationSignal? = null
    private var night = false
    private lateinit var list: LinearLayout
    private lateinit var search: EditText

    // The app's colours (crates/app/src/style.css), light and dark.
    private fun color(light: Int, dark: Int): Int = (if (night) dark else light) or 0xFF000000.toInt()
    private val bg get() = color(0xF4F5F8, 0x11131A)
    private val panel get() = color(0xFFFFFF, 0x181B24)
    private val ink get() = color(0x1A1D26, 0xE7E9EF)
    private val muted get() = color(0x687083, 0x959CB0)
    private val border get() = color(0xE2E5EC, 0x2A2F3E)
    private val selected get() = color(0xE5EBFF, 0x27305A)

    override fun onCreate(savedInstanceState: Bundle?) {
        night = (resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES
        setTheme(if (night) android.R.style.Theme_DeviceDefault_NoActionBar else android.R.style.Theme_DeviceDefault_Light_NoActionBar)
        super.onCreate(savedInstanceState)
        // No screenshots of the logins, and none in the app switcher.
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_HIDDEN)
        setResult(RESULT_CANCELED)
        @Suppress("DEPRECATION")
        val structure: AssistStructure? = intent.getParcelableExtra(AutofillManager.EXTRA_ASSIST_STRUCTURE)
        if (structure == null) {
            finish()
            return
        }
        val found = AutofillFields.parse(structure)
        fields = found
        site = siteOf(found)
        layout()
        message(AutofillText.unlocking)
    }

    override fun onResume() {
        super.onResume()
        // The prompt needs the screen in front.
        if (!asked) {
            asked = true
            unlock()
        }
    }

    override fun onDestroy() {
        signal?.cancel()
        signal = null
        super.onDestroy()
    }

    @Suppress("DEPRECATION") // getApplicationInfo(String, Int): Android 13 has a newer form.
    private fun siteOf(found: AutofillFields): String {
        found.webDomain?.let { return it.removePrefix("www.") }
        if (found.packageName.isEmpty()) return ""
        return try {
            packageManager.getApplicationLabel(packageManager.getApplicationInfo(found.packageName, 0)).toString()
        } catch (e: Exception) {
            found.packageName
        }
    }

    // Unlocking

    private fun unlock() {
        val sealed = AutofillStore.read(this) ?: return message(AutofillText.notSetUp, AutofillText.close) { finish() }
        val cipher: Cipher? = try {
            AutofillStore.unlockCipher()
        } catch (e: KeyPermanentlyInvalidatedException) {
            // The enrolled fingerprints or faces changed: the key is void.
            AutofillStore.clear(this)
            return message(AutofillText.keyGone, AutofillText.close) { finish() }
        } catch (e: Exception) {
            return message(AutofillText.failed(e.toString()), AutofillText.close) { finish() }
        }
        if (cipher == null) return message(AutofillText.notSetUp, AutofillText.close) { finish() }
        message(AutofillText.unlocking)
        val cancel = CancellationSignal()
        signal = cancel
        val executor = mainExecutor
        val builder = BiometricPrompt.Builder(this)
            .setTitle("2Secret")
            .setSubtitle(AutofillText.reason(site))
            .setNegativeButton(AutofillText.cancel, executor) { _, _ -> finish() }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setConfirmationRequired(false)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        }
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                signal = null
                opened(sealed, result.cryptoObject?.cipher ?: cipher)
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) {
                signal = null
                failed(errorCode, errString?.toString())
            }
        }
        try {
            builder.build().authenticate(BiometricPrompt.CryptoObject(cipher), cancel, executor, callback)
        } catch (e: Exception) {
            message(AutofillText.failed(e.toString()), AutofillText.close) { finish() }
        }
    }

    private fun failed(code: Int, detail: String?) {
        if (isFinishing || isDestroyed) return
        when (code) {
            BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED,
            BiometricPrompt.BIOMETRIC_ERROR_TIMEOUT,
            13, // BIOMETRIC_ERROR_NEGATIVE_BUTTON
            -> finish()
            // Not in front yet, or the sensor was busy: once more by itself.
            BiometricPrompt.BIOMETRIC_ERROR_CANCELED,
            BiometricPrompt.BIOMETRIC_ERROR_HW_UNAVAILABLE,
            -> if (!retried) {
                retried = true
                list.postDelayed({ if (!isFinishing) unlock() }, 600)
            } else {
                message(AutofillText.notNow, AutofillText.tryAgain) { unlock() }
            }
            BiometricPrompt.BIOMETRIC_ERROR_LOCKOUT,
            BiometricPrompt.BIOMETRIC_ERROR_LOCKOUT_PERMANENT,
            -> message(AutofillText.lockout, AutofillText.close) { finish() }
            BiometricPrompt.BIOMETRIC_ERROR_NO_BIOMETRICS,
            BiometricPrompt.BIOMETRIC_ERROR_HW_NOT_PRESENT,
            14, // BIOMETRIC_ERROR_NO_DEVICE_CREDENTIAL
            15, // BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED
            -> message(AutofillText.unavailable, AutofillText.close) { finish() }
            else -> message(AutofillText.failed(detail ?: "$code"), AutofillText.tryAgain) { unlock() }
        }
    }

    private fun opened(sealed: AutofillStore.Sealed, cipher: Cipher) {
        if (isFinishing || isDestroyed) return
        val json = try {
            AutofillStore.open(sealed, cipher)
        } catch (e: Exception) {
            return message(AutofillText.failed(e.toString()), AutofillText.close) { finish() }
        }
        val contents = try {
            AutofillStore.parse(json)
        } catch (e: Exception) {
            null
        } finally {
            Arrays.fill(json, 0.toByte())
        }
        if (contents == null) return message(AutofillText.notSetUp, AutofillText.close) { finish() }
        // Like the app: after 14 days without the master password, no more.
        val age = System.currentTimeMillis() / 1000 - contents.passwordEnteredAt
        if (age < 0 || age >= AutofillStore.MAX_AGE_SECONDS) {
            return message(AutofillText.passwordNeeded, AutofillText.close) { finish() }
        }
        logins = contents.logins
        unlocked = true
        search.visibility = View.VISIBLE
        render()
    }

    // The list

    private fun render() {
        val found = fields ?: return
        list.removeAllViews()
        val query = search.text.toString().trim().lowercase()
        fun wanted(login: AutofillStore.Login) = query.isEmpty() ||
            login.title.lowercase().contains(query) || login.username.lowercase().contains(query) ||
            login.domains.any { it.contains(query) }
        val suggested = logins.filter { it.isFor(found) && wanted(it) }
        val others = logins.filter { !it.isFor(found) && wanted(it) }
        var noted = false
        if (suggested.isNotEmpty()) {
            heading(AutofillText.suggested)
            suggested.forEach { row(it) }
        } else if (query.isEmpty() && site.isNotEmpty()) {
            note(AutofillText.noneFor(site))
            noted = true
        }
        when {
            others.isEmpty() -> if (suggested.isEmpty() && !noted) note(AutofillText.nothing)
            showAll || query.isNotEmpty() || suggested.isEmpty() -> {
                heading(AutofillText.all)
                others.forEach { row(it) }
            }
            else -> button(AutofillText.showAll) {
                showAll = true
                render()
            }
        }
    }

    /** Give Android the login to fill, and close. */
    @Suppress("DEPRECATION") // Dataset.Builder(RemoteViews) and setValue: Android 13 has newer forms.
    private fun fill(login: AutofillStore.Login) {
        val found = fields ?: return
        val presentation = RemoteViews(packageName, android.R.layout.simple_list_item_1)
        presentation.setTextViewText(android.R.id.text1, login.title.ifEmpty { login.username })
        val dataset = Dataset.Builder(presentation)
        var filled = false
        val username = found.username
        if (username != null && login.username.isNotEmpty()) {
            dataset.setValue(username, AutofillValue.forText(login.username))
            filled = true
        }
        val password = found.password
        if (password != null && login.password.isNotEmpty()) {
            dataset.setValue(password, AutofillValue.forText(login.password))
            filled = true
        }
        if (!filled) return
        setResult(RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, dataset.build()))
        finish()
    }

    // Views

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    private fun label(text: String, size: Float, color: Int): TextView {
        val view = TextView(this)
        view.text = text
        view.textSize = size
        view.setTextColor(color)
        return view
    }

    @Suppress("DEPRECATION") // The bar colours: Android 15 draws behind them.
    private fun layout() {
        val root = LinearLayout(this)
        root.orientation = LinearLayout.VERTICAL
        root.setBackgroundColor(bg)
        root.setPadding(dp(20), dp(20), dp(20), dp(12))
        // The search field is 2Secret's own: nothing for AutoFill there.
        root.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS

        val title = label("2Secret", 20f, ink)
        title.setTypeface(title.typeface, Typeface.BOLD)
        root.addView(title)
        if (site.isNotEmpty()) {
            val host = label(site, 14f, muted)
            host.setSingleLine(true)
            host.ellipsize = TextUtils.TruncateAt.MIDDLE
            root.addView(host)
        }

        search = EditText(this)
        search.hint = AutofillText.search
        search.setSingleLine(true)
        search.setTextColor(ink)
        search.setHintTextColor(muted)
        search.visibility = View.GONE
        search.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}

            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}

            override fun afterTextChanged(s: Editable?) {
                if (unlocked) render()
            }
        })
        val searchParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
        searchParams.topMargin = dp(12)
        root.addView(search, searchParams)

        list = LinearLayout(this)
        list.orientation = LinearLayout.VERTICAL
        val scroll = ScrollView(this)
        scroll.addView(list, ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
        val scrollParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f)
        scrollParams.topMargin = dp(8)
        root.addView(scroll, scrollParams)

        val cancel = Button(this)
        cancel.text = AutofillText.cancel
        cancel.setOnClickListener { finish() }
        val cancelParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT)
        cancelParams.gravity = Gravity.END
        root.addView(cancel, cancelParams)

        setContentView(root)
        window.statusBarColor = bg
        window.navigationBarColor = bg
        if (!night) root.systemUiVisibility = View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR
    }

    /** A text in the middle, and a button under it. */
    private fun message(message: String, button: String? = null, action: (() -> Unit)? = null) {
        search.visibility = View.GONE
        list.removeAllViews()
        val view = label(message, 16f, ink)
        view.gravity = Gravity.CENTER
        view.setPadding(dp(8), dp(48), dp(8), dp(8))
        list.addView(view, ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
        if (button != null && action != null) {
            val view2 = Button(this)
            view2.text = button
            view2.setOnClickListener { action() }
            val params = LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT)
            params.gravity = Gravity.CENTER_HORIZONTAL
            params.topMargin = dp(16)
            list.addView(view2, params)
        }
    }

    private fun heading(title: String) {
        val view = label(title, 13f, muted)
        view.setTypeface(view.typeface, Typeface.BOLD)
        view.setPadding(dp(4), dp(12), dp(4), dp(6))
        list.addView(view)
    }

    private fun note(message: String) {
        val view = label(message, 14f, muted)
        view.setPadding(dp(4), dp(12), dp(4), dp(6))
        list.addView(view)
    }

    private fun button(title: String, action: () -> Unit) {
        val view = Button(this)
        view.text = title
        view.setOnClickListener { action() }
        val params = LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT)
        params.gravity = Gravity.CENTER_HORIZONTAL
        params.topMargin = dp(8)
        list.addView(view, params)
    }

    private fun row(login: AutofillStore.Login) {
        val row = LinearLayout(this)
        row.orientation = LinearLayout.VERTICAL
        row.setPadding(dp(16), dp(12), dp(16), dp(12))
        val shape = GradientDrawable()
        shape.setColor(panel)
        shape.setStroke(dp(1), border)
        shape.cornerRadius = dp(10).toFloat()
        row.background = RippleDrawable(ColorStateList.valueOf(selected), shape, null)
        row.isClickable = true
        row.isFocusable = true
        row.setOnClickListener { fill(login) }
        row.addView(label(login.title.ifEmpty { login.username }, 16f, ink))
        if (login.title.isNotEmpty() && login.username.isNotEmpty()) row.addView(label(login.username, 13f, muted))
        val params = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
        params.bottomMargin = dp(8)
        list.addView(row, params)
    }
}
