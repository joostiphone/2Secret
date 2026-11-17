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
package dev.dioxus.main

import android.annotation.TargetApi
import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.IOException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.MGF1ParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Arrays
import java.util.concurrent.Executors
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec

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
