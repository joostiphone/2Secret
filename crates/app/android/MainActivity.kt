// The app's activity (Dioxus.toml: android_main_activity). Rust (crates/app)
// does everything else; this hands it what only Java can do:
// - the folder chosen in the system's folder picker (android_folders.rs);
// - the fingerprint or face prompt for biometric unlock (Biometric.kt,
//   biometric.rs);
// - AutoFill: whether 2Secret is the phone's AutoFill service, and the store
//   of logins it fills from (AutofillStore.kt, android_autofill.rs).
// Rust calls these methods and reads the companion's fields by name through
// JNI; proguard-2secret.pro keeps them in release builds. scripts/android.sh
// copies the other files of this folder into the Android project.
package dev.dioxus.main

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.view.autofill.AutofillManager

typealias BuildConfig = io.github.joostiphone.twosecret.BuildConfig

class MainActivity : WryActivity() {
    companion object {
        const val PICK_FOLDER = 0x2533

        /** The document tree the person chose, or null. */
        @JvmField @Volatile var pickedFolder: String? = null

        /** Set once the folder picker has closed. */
        @JvmField @Volatile var pickDone: Boolean = false

        /** Set once the fingerprint or face prompt has closed (Biometric.kt). */
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
