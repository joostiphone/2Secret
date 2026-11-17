// Unlocking with a fingerprint or face (crates/app/src/biometric.rs).
//
// The device key Rust makes is encrypted (AES-256-GCM) with an Android
// Keystore key that works only after a strong (class 3) fingerprint or face
// check, for every single use, and that Android deletes for good when a
// fingerprint or face is added or all are removed. The check is the system's
// BiometricPrompt with that key's cipher (a CryptoObject): the cipher only
// works once the person passed it. Rust stores what comes out (IV and
// ciphertext) in the app's no-backup storage.
package dev.dioxus.main

import android.annotation.SuppressLint
import android.annotation.TargetApi
import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.hardware.fingerprint.FingerprintManager
import android.os.Build
import android.os.CancellationSignal
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import java.security.InvalidAlgorithmParameterException
import java.security.KeyStore
import java.util.Arrays
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

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
