// The app's Android code, in one file because dx takes only the file that
// Dioxus.toml names (android_main_activity) and compiles it before
// scripts/android.sh can add others. Sections: the activity (folder picker,
// the hooks Rust calls through JNI), Biometric (unlock with fingerprint or
// face), AutofillStore, AutofillFields, AutofillText,
// TwoSecretAutofillService and AutofillUnlockActivity (AutoFill in other
// apps). The service and its screen are added to the manifest by
// scripts/android.sh.

package dev.dioxus.main

import android.annotation.SuppressLint
import android.annotation.TargetApi
import android.app.Activity
import android.app.KeyguardManager
import android.app.PendingIntent
import android.app.assist.AssistStructure
import android.content.Context
import android.content.Intent
import android.content.res.ColorStateList
import android.content.res.Configuration
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.RippleDrawable
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.hardware.fingerprint.FingerprintManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.CancellationSignal
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import android.text.Editable
import android.text.InputType
import android.text.TextUtils
import android.text.TextWatcher
import android.util.Log
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.RemoteViews
import android.widget.ScrollView
import android.widget.TextView
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.IOException
import java.security.InvalidAlgorithmParameterException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.MGF1ParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Arrays
import java.util.Locale
import java.util.concurrent.Executors
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec
import org.json.JSONArray
import org.json.JSONObject

typealias BuildConfig = io.github.joostiphone.twosecret.BuildConfig

// ------------------------------------------------------------------------
// MainActivity
// ------------------------------------------------------------------------

// The app's activity (Dioxus.toml: android_main_activity). Rust (crates/app)
// does everything else; this hands it what only Java can do:
// - the folder chosen in the system's folder picker (android_folders.rs);
// - the fingerprint or face prompt for biometric unlock (Biometric below,
//   biometric.rs);
// - AutoFill: whether 2Secret is the phone's AutoFill service, and the store
//   of logins it fills from (AutofillStore below, android_autofill.rs).
// Rust calls these methods and reads the companion's fields by name through
// JNI; proguard-2secret.pro keeps them in release builds.

class MainActivity : WryActivity() {
    companion object {
        const val PICK_FOLDER = 0x2533

        /** The document tree the person chose, or null. */
        @JvmField @Volatile var pickedFolder: String? = null

        /** Set once the folder picker has closed. */
        @JvmField @Volatile var pickDone: Boolean = false

        /** Set once the fingerprint or face prompt has closed (Biometric, below). */
        @JvmField @Volatile var bioDone: Boolean = false

        /** Biometric.OK, or why not. */
        @JvmField @Volatile var bioError: Int = 0

        /** The system's text for a failure, if any. */
        @JvmField @Volatile var bioMessage: String? = null

        /** What the key's cipher made; Rust wipes it once it has read it. */
        @JvmField @Volatile var bioOutput: ByteArray? = null
    }

    /** Open the system's folder picker (ACTION_OPEN_DOCUMENT_TREE). */
    fun pickFolder() {
        pickedFolder = null
        pickDone = false
        runOnUiThread {
            try {
                val intent = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE)
                intent.addFlags(
                    Intent.FLAG_GRANT_READ_URI_PERMISSION or
                        Intent.FLAG_GRANT_WRITE_URI_PERMISSION or
                        Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION or
                        Intent.FLAG_GRANT_PREFIX_URI_PERMISSION
                )
                @Suppress("DEPRECATION")
                startActivityForResult(intent, PICK_FOLDER)
            } catch (e: Exception) {
                pickDone = true
            }
        }
    }

    @Deprecated("The folder picker's answer; ActivityResultRegistry needs a launcher made in onCreate.")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        @Suppress("DEPRECATION")
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != PICK_FOLDER) return
        val uri = if (resultCode == Activity.RESULT_OK) data?.data else null
        if (uri != null) {
            // Keep access after a restart.
            try {
                contentResolver.takePersistableUriPermission(
                    uri,
                    Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                )
            } catch (e: SecurityException) {
            }
        }
        pickedFolder = uri?.toString()
        pickDone = true
    }

    // Biometric unlock (biometric.rs). Rust calls these from a background
    // thread; the prompt itself runs on the UI thread.

    /** Whether a strong fingerprint or face check can be asked. */
    fun biometricAvailable(): Boolean {
        return Biometric.available(this)
    }

    /** Show the prompt; the answer goes into bioDone and the fields next to it. */
    fun biometricStart(alias: String, create: Boolean, input: ByteArray, reason: String) {
        Biometric.start(this, alias, create, input, reason)
    }

    fun biometricCancel() {
        Biometric.cancel()
    }

    fun biometricDelete(alias: String) {
        Biometric.delete(alias)
    }

    // AutoFill (android_autofill.rs).

    /** Android 9 or newer (for the fingerprint or face check), with AutoFill. */
    fun autofillAvailable(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return false
        return try {
            getSystemService(AutofillManager::class.java)?.isAutofillSupported == true
        } catch (e: Exception) {
            false
        }
    }

    /** Whether 2Secret is the phone's AutoFill service. */
    fun autofillActive(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return false
        return try {
            getSystemService(AutofillManager::class.java)?.hasEnabledAutofillServices() == true
        } catch (e: Exception) {
            false
        }
    }

    /** Android's screen for choosing 2Secret as the AutoFill service. */
    fun autofillSettings(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return false
        return try {
            startActivity(Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE, Uri.parse("package:$packageName")))
            true
        } catch (e: Exception) {
            false
        }
    }

    /** A new store of logins (JSON), encrypted on a background thread. */
    fun autofillWrite(json: ByteArray) {
        AutofillStore.write(this, json)
    }

    fun autofillClear() {
        AutofillStore.clear(this)
    }
}

// ------------------------------------------------------------------------
// Biometric
// ------------------------------------------------------------------------

// Unlocking with a fingerprint or face (crates/app/src/biometric.rs).
//
// The device key Rust makes is encrypted (AES-256-GCM) with an Android
// Keystore key that works only after a strong (class 3) fingerprint or face
// check, for every single use, and that Android deletes for good when a
// fingerprint or face is added or all are removed. The check is the system's
// BiometricPrompt with that key's cipher (a CryptoObject): the cipher only
// works once the person passed it. Rust stores what comes out (IV and
// ciphertext) in the app's no-backup storage.

object Biometric {
    // The answers biometric.rs knows.
    const val OK = 0
    const val CANCELLED = 1
    const val NOT_NOW = 2
    const val OFF = 3
    const val LOCKOUT = 4
    const val KEY_GONE = 5
    const val FAILED = 6

    private const val KEYSTORE = "AndroidKeyStore"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val IV_SIZE = 12
    private const val TAG_BITS = 128

    /** The current prompt; answers of earlier ones are dropped. */
    private var generation = 0
    private var signal: CancellationSignal? = null
    /** The device key (create) or IV and ciphertext (open), wiped afterwards. */
    private var input: ByteArray? = null

    /** Whether a strong fingerprint or face is enrolled (Android 9 or newer). */
    @SuppressLint("MissingPermission") // Android 9 takes USE_BIOMETRIC for FingerprintManager too.
    @Suppress("DEPRECATION")
    fun available(context: Context): Boolean {
        return try {
            when {
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.R -> {
                    val manager = context.getSystemService(BiometricManager::class.java)
                    manager?.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
                        BiometricManager.BIOMETRIC_SUCCESS
                }
                Build.VERSION.SDK_INT == Build.VERSION_CODES.Q -> {
                    val manager = context.getSystemService(BiometricManager::class.java)
                    manager?.canAuthenticate() == BiometricManager.BIOMETRIC_SUCCESS
                }
                Build.VERSION.SDK_INT == Build.VERSION_CODES.P -> {
                    // Android 9's BiometricPrompt knows fingerprints only.
                    val fingerprints = context.getSystemService(FingerprintManager::class.java)
                    val keyguard = context.getSystemService(KeyguardManager::class.java)
                    fingerprints != null && fingerprints.isHardwareDetected &&
                        fingerprints.hasEnrolledFingerprints() && keyguard?.isDeviceSecure == true
                }
                else -> false
            }
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Show the prompt for the key [alias]. `create`: make a new key and
     * encrypt [input] (the device key), giving IV and ciphertext; else decrypt
     * [input] (IV and ciphertext), giving the device key. Called by Rust from
     * a background thread; the answer goes into MainActivity.bio*.
     */
    fun start(activity: Activity, alias: String, create: Boolean, input: ByteArray, reason: String) {
        val id = synchronized(this) {
            generation += 1
            this.input = input
            signal = null
            MainActivity.bioOutput = null
            MainActivity.bioMessage = null
            MainActivity.bioError = OK
            MainActivity.bioDone = false
            generation
        }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return finish(id, OFF)
        val cipher: Cipher? = try {
            prepare(alias, create, input)
        } catch (e: KeyPermanentlyInvalidatedException) {
            // The enrolled fingerprints or faces changed: the key is void.
            delete(alias)
            return finish(id, KEY_GONE)
        } catch (e: Exception) {
            // A key that needs a fingerprint or face cannot be made while none
            // is enrolled.
            val off = create && (e is InvalidAlgorithmParameterException || e is IllegalStateException)
            return finish(id, if (off) OFF else FAILED, e.toString())
        }
        if (cipher == null) return finish(id, KEY_GONE)
        activity.runOnUiThread { show(activity, id, create, cipher, reason) }
    }

    @TargetApi(Build.VERSION_CODES.P)
    private fun prepare(alias: String, create: Boolean, input: ByteArray): Cipher? {
        val keyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        if (create) {
            if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
            cipher.init(Cipher.ENCRYPT_MODE, newKey(alias))
        } else {
            val key = keyStore.getKey(alias, null) as? SecretKey ?: return null
            if (input.size <= IV_SIZE) return null
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, input, 0, IV_SIZE))
        }
        return cipher
    }

    /** AES-256-GCM, usable only right after a strong biometric check. */
    @TargetApi(Build.VERSION_CODES.P)
    private fun newKey(alias: String): SecretKey {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            // 0: a check for every use; strong biometrics, not the PIN.
            spec.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        generator.init(spec.build())
        return generator.generateKey()
    }

    @TargetApi(Build.VERSION_CODES.P)
    private fun show(activity: Activity, id: Int, create: Boolean, cipher: Cipher, reason: String) {
        try {
            val cancel = CancellationSignal()
            synchronized(this) {
                if (id != generation || MainActivity.bioDone) return
                signal = cancel
            }
            val executor = activity.mainExecutor
            val builder = BiometricPrompt.Builder(activity)
                .setTitle("2Secret")
                .setNegativeButton(activity.getString(android.R.string.cancel), executor) { _, _ ->
                    finish(id, CANCELLED)
                }
            if (reason.isNotEmpty()) builder.setSubtitle(reason)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setConfirmationRequired(false)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                builder.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            }
            val callback = object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    unlocked(id, create, result.cryptoObject?.cipher ?: cipher)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) {
                    finish(id, answer(errorCode), errString?.toString())
                }
            }
            builder.build().authenticate(BiometricPrompt.CryptoObject(cipher), cancel, executor, callback)
        } catch (e: Exception) {
            finish(id, FAILED, e.toString())
        }
    }

    /** The check passed: the cipher works now. */
    private fun unlocked(id: Int, create: Boolean, cipher: Cipher) {
        val data = synchronized(this) { if (id == generation) input else null } ?: return
        try {
            val output = if (create) {
                val sealed = cipher.doFinal(data)
                cipher.iv + sealed
            } else {
                cipher.doFinal(data, IV_SIZE, data.size - IV_SIZE)
            }
            finish(id, OK, null, output)
        } catch (e: AEADBadTagException) {
            // Not what this key encrypted.
            finish(id, KEY_GONE)
        } catch (e: Exception) {
            finish(id, FAILED, e.toString())
        }
    }

    /** What a BiometricPrompt error means for Rust. */
    private fun answer(code: Int): Int = when (code) {
        BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED,
        BiometricPrompt.BIOMETRIC_ERROR_TIMEOUT,
        13, // BIOMETRIC_ERROR_NEGATIVE_BUTTON
        -> CANCELLED
        // The app was not in front, another prompt was showing, or the
        // sensor was busy: asking again a moment later works.
        BiometricPrompt.BIOMETRIC_ERROR_CANCELED,
        BiometricPrompt.BIOMETRIC_ERROR_HW_UNAVAILABLE,
        -> NOT_NOW
        BiometricPrompt.BIOMETRIC_ERROR_LOCKOUT,
        BiometricPrompt.BIOMETRIC_ERROR_LOCKOUT_PERMANENT,
        -> LOCKOUT
        BiometricPrompt.BIOMETRIC_ERROR_NO_BIOMETRICS,
        BiometricPrompt.BIOMETRIC_ERROR_HW_NOT_PRESENT,
        14, // BIOMETRIC_ERROR_NO_DEVICE_CREDENTIAL
        15, // BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED
        -> OFF
        else -> FAILED
    }

    /** The first answer of the current prompt counts; the input is wiped. */
    private fun finish(id: Int, code: Int, message: String? = null, output: ByteArray? = null) {
        synchronized(this) {
            if (id != generation || MainActivity.bioDone) {
                output?.let { Arrays.fill(it, 0.toByte()) }
                return
            }
            input?.let { Arrays.fill(it, 0.toByte()) }
            input = null
            signal = null
            MainActivity.bioOutput = output
            MainActivity.bioMessage = message
            MainActivity.bioError = code
            MainActivity.bioDone = true
        }
    }

    /** Rust stopped waiting: close the prompt. */
    fun cancel() {
        val open = synchronized(this) {
            val open = signal
            signal = null
            generation += 1
            input?.let { Arrays.fill(it, 0.toByte()) }
            input = null
            open
        }
        try {
            open?.cancel()
        } catch (e: Exception) {
        }
    }

    fun delete(alias: String) {
        try {
            val keyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }
            if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
        } catch (e: Exception) {
        }
    }
}

// ------------------------------------------------------------------------
// AutofillStore
// ------------------------------------------------------------------------

// The logins AutoFill may fill (crates/app/src/android_autofill.rs), sealed
// so nothing of them is readable before a fingerprint or face check.
//
// The app (MainActivity, for Rust) writes the store while the vault is
// unlocked; AutofillUnlockActivity reads it. Every write encrypts the JSON
// with AES-256-GCM under a new random key, and that key with the public key
// of an RSA key pair in Android Keystore (OAEP, SHA-256). Encrypting needs no
// check, so the app writes without asking. The private key only decrypts
// right after a strong (class 3) fingerprint or face check, for every use
// (BiometricPrompt with its cipher), and Android voids it when a fingerprint
// or face is added or all are removed. The file is in the app's no-backup
// storage. Layout:
//   "2SAF" | version (1) | length of the wrapped key (2 bytes) | wrapped key
//   | IV (12 bytes) | ciphertext and tag

object AutofillStore {
    private const val TAG = "2Secret"
    private const val ALIAS = "2secret-autofill"
    private const val KEYSTORE = "AndroidKeyStore"
    private const val RSA = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
    private const val AES = "AES/GCM/NoPadding"
    private const val VERSION = 1
    private const val IV_SIZE = 12
    private const val TAG_BITS = 128
    private val MAGIC = "2SAF".toByteArray(Charsets.US_ASCII)
    private val AAD = "2secret/v1/android-autofill".toByteArray(Charsets.US_ASCII)

    /** OAEP with SHA-256; MGF1 with SHA-1, the one Android Keystore takes on every version. */
    private val OAEP = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)

    /** Writes and removals, one after the other, off the UI thread. */
    private val worker = Executors.newSingleThreadExecutor()
    private val random = SecureRandom()

    /** The time without the master password after which AutoFill stops, as in the app. */
    const val MAX_AGE_SECONDS = 14L * 86_400

    private fun file(context: Context) = File(context.noBackupFilesDir, "autofill/store.bin")

    fun exists(context: Context): Boolean = file(context).isFile

    /** Encrypt and store [json]; it is wiped afterwards. */
    fun write(context: Context, json: ByteArray) {
        val app = context.applicationContext
        worker.execute {
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) writeNow(app, json)
            } catch (e: Exception) {
                // Better no store than one with logins that changed since.
                Log.w(TAG, "AutoFill store not written: $e")
                file(app).delete()
            } finally {
                Arrays.fill(json, 0.toByte())
            }
        }
    }

    /** Remove the store and its key. */
    fun clear(context: Context) {
        val app = context.applicationContext
        worker.execute {
            file(app).delete()
            try {
                val keyStore = keyStore()
                if (keyStore.containsAlias(ALIAS)) keyStore.deleteEntry(ALIAS)
            } catch (e: Exception) {
                Log.w(TAG, "AutoFill key not removed: $e")
            }
        }
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }

    @TargetApi(Build.VERSION_CODES.P)
    private fun writeNow(context: Context, json: ByteArray) {
        val publicKey = publicKey()
        val key = ByteArray(32).also { random.nextBytes(it) }
        try {
            val iv = ByteArray(IV_SIZE).also { random.nextBytes(it) }
            val aes = Cipher.getInstance(AES)
            aes.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, iv))
            aes.updateAAD(AAD)
            val body = aes.doFinal(json)
            val rsa = Cipher.getInstance(RSA)
            rsa.init(Cipher.ENCRYPT_MODE, publicKey, OAEP)
            val wrapped = rsa.doFinal(key)
            val bytes = ByteArrayOutputStream()
            DataOutputStream(bytes).use {
                it.write(MAGIC)
                it.writeByte(VERSION)
                it.writeShort(wrapped.size)
                it.write(wrapped)
                it.write(iv)
                it.write(body)
            }
            val target = file(context)
            val dir = target.parentFile ?: throw IOException("no folder for the store")
            if (!dir.isDirectory && !dir.mkdirs()) throw IOException("cannot make $dir")
            val tmp = File(dir, "store.tmp")
            tmp.writeBytes(bytes.toByteArray())
            if (!tmp.renameTo(target)) {
                tmp.delete()
                throw IOException("cannot replace the store")
            }
        } finally {
            Arrays.fill(key, 0.toByte())
        }
    }

    /** The key pair's public key, made the first time. */
    @TargetApi(Build.VERSION_CODES.P)
    private fun publicKey(): PublicKey {
        val keyStore = keyStore()
        if (!keyStore.containsAlias(ALIAS)) generate()
        val stored = keyStore.getCertificate(ALIAS)?.publicKey ?: throw IOException("no AutoFill key")
        // A plain copy, so encrypting runs in software and needs no check.
        return KeyFactory.getInstance(stored.algorithm).generatePublic(X509EncodedKeySpec(stored.encoded))
    }

    @TargetApi(Build.VERSION_CODES.P)
    private fun generate() {
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(2048)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            // 0: a check for every use; strong biometrics, not the PIN.
            spec.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        }
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, KEYSTORE)
        generator.initialize(spec.build())
        generator.generateKeyPair()
    }

    /** The store as it is on disk, still encrypted. */
    class Sealed(val wrapped: ByteArray, val iv: ByteArray, val body: ByteArray)

    fun read(context: Context): Sealed? {
        return try {
            DataInputStream(file(context).inputStream().buffered()).use { input ->
                val magic = ByteArray(MAGIC.size)
                input.readFully(magic)
                if (!magic.contentEquals(MAGIC) || input.readUnsignedByte() != VERSION) return null
                val wrapped = ByteArray(input.readUnsignedShort())
                input.readFully(wrapped)
                val iv = ByteArray(IV_SIZE)
                input.readFully(iv)
                Sealed(wrapped, iv, input.readBytes())
            }
        } catch (e: Exception) {
            null
        }
    }

    /**
     * The private key's cipher, for the BiometricPrompt; null without a key.
     * Throws KeyPermanentlyInvalidatedException when the enrolled
     * fingerprints or faces changed.
     */
    @TargetApi(Build.VERSION_CODES.P)
    fun unlockCipher(): Cipher? {
        val key = keyStore().getKey(ALIAS, null) as? PrivateKey ?: return null
        return Cipher.getInstance(RSA).apply { init(Cipher.DECRYPT_MODE, key, OAEP) }
    }

    /** Decrypt with the cipher the check unlocked. Wipe the result after use. */
    fun open(sealed: Sealed, unlocked: Cipher): ByteArray {
        val key = unlocked.doFinal(sealed.wrapped)
        try {
            val aes = Cipher.getInstance(AES)
            aes.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, sealed.iv))
            aes.updateAAD(AAD)
            return aes.doFinal(sealed.body)
        } finally {
            Arrays.fill(key, 0.toByte())
        }
    }

    /** A login of the store (twosecret_core::autofill::AndroidLogin). */
    class Login(
        val title: String,
        val username: String,
        val password: String,
        val domains: List<String>,
        val exactHosts: List<String>,
        val packages: List<String>,
    ) {
        /**
         * Whether the login is for the page or app: a page's host is one of
         * its registrable domains or below one ("login.example.com" for
         * "example.com"), or one of its exact hosts; an app's package is one
         * of its apps. On a web page the browser's package never counts.
         */
        fun isFor(fields: AutofillFields): Boolean {
            val host = fields.webDomain
            if (!host.isNullOrEmpty()) {
                return host in exactHosts || domains.any { host == it || host.endsWith(".$it") }
            }
            return fields.packageName.isNotEmpty() && fields.packageName in packages
        }
    }

    class Contents(val passwordEnteredAt: Long, val logins: List<Login>)

    fun parse(json: ByteArray): Contents {
        val root = JSONObject(String(json, Charsets.UTF_8))
        val items = root.getJSONArray("logins")
        val logins = (0 until items.length()).map { i ->
            val item = items.getJSONObject(i)
            Login(
                item.optString("title"),
                item.optString("username"),
                item.optString("password"),
                strings(item.optJSONArray("domains")),
                strings(item.optJSONArray("exact_hosts")),
                strings(item.optJSONArray("packages")),
            )
        }
        return Contents(root.getLong("password_entered_at"), logins)
    }

    private fun strings(array: JSONArray?): List<String> =
        if (array == null) emptyList() else (0 until array.length()).map { array.getString(it) }
}

// ------------------------------------------------------------------------
// AutofillFields
// ------------------------------------------------------------------------

// The login fields of a screen in another app or of a web page, as Android's
// AutoFill describes them (an AssistStructure), and whose they are.

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

// ------------------------------------------------------------------------
// AutofillText
// ------------------------------------------------------------------------

// What AutoFill says, in English and Dutch after the phone's language (the
// app's own texts are in crates/app/src/i18n.rs).

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

// ------------------------------------------------------------------------
// TwoSecretAutofillService
// ------------------------------------------------------------------------

// 2Secret as Android's AutoFill service: on a login screen of another app or
// a web page it offers one choice, "Fill with 2Secret". That choice holds no
// login yet: it opens AutofillUnlockActivity, which asks for a fingerprint or
// face, decrypts the store and lets the person pick the login to fill. So
// nothing of the vault reaches Android or the other app before that check.
// 2Secret saves nothing new from here (no SaveInfo).

@TargetApi(Build.VERSION_CODES.O)
class TwoSecretAutofillService : AutofillService() {
    override fun onFillRequest(request: FillRequest, cancellationSignal: CancellationSignal, callback: FillCallback) {
        val response = try {
            response(request)
        } catch (e: Exception) {
            Log.w("2Secret", "AutoFill: $e")
            null
        }
        callback.onSuccess(response)
    }

    @Suppress("DEPRECATION") // Dataset.Builder(RemoteViews) and setValue: Android 13 has newer forms.
    private fun response(request: FillRequest): FillResponse? {
        // The check needs Android 9's BiometricPrompt.
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return null
        val structure = request.fillContexts.lastOrNull()?.structure ?: return null
        val fields = AutofillFields.parse(structure)
        // Not in 2Secret itself, and only once the app has written a store.
        if (fields.isEmpty() || fields.packageName == packageName || !AutofillStore.exists(this)) return null

        // The system adds the screen's structure to this intent when it opens it.
        val intent = Intent(this, AutofillUnlockActivity::class.java)
        var flags = PendingIntent.FLAG_UPDATE_CURRENT
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) flags = flags or PendingIntent.FLAG_MUTABLE
        val sender = PendingIntent.getActivity(this, 0, intent, flags).intentSender

        val presentation = RemoteViews(packageName, android.R.layout.simple_list_item_1)
        presentation.setTextViewText(android.R.id.text1, AutofillText.fillWith)
        val dataset = Dataset.Builder(presentation)
        for (id in fields.ids) dataset.setValue(id, null)
        dataset.setAuthentication(sender)
        return FillResponse.Builder().addDataset(dataset.build()).build()
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        callback.onSuccess()
    }
}

// ------------------------------------------------------------------------
// AutofillUnlockActivity
// ------------------------------------------------------------------------

// Opened by Android when the person picks "Fill with 2Secret" on a login
// screen (TwoSecretAutofillService). It asks for a fingerprint or face, whose
// check unlocks the store's key (AutofillStore), lists the logins for the
// page or app first ("Suggested", by registrable domain or app), the others
// on request, and hands Android the one the person picks. Nothing is chosen
// for them: a login only goes to the other app after a tap on it. Android
// opens this screen through 2Secret's own PendingIntent; other apps cannot
// (exported="false").

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
