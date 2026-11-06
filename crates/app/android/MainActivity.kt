// The app's activity (Dioxus.toml: android_main_activity). Rust (crates/app)
// does everything else; this only hands it the folder chosen in the
// system's folder picker (crates/app/src/android_folders.rs).
package dev.dioxus.main

import android.app.Activity
import android.content.Intent

typealias BuildConfig = io.github.joostiphone.twosecret.BuildConfig

class MainActivity : WryActivity() {
    companion object {
        const val PICK_FOLDER = 0x2533

        /** The document tree the person chose, or null. */
        @JvmField @Volatile var pickedFolder: String? = null

        /** Set once the folder picker has closed. */
        @JvmField @Volatile var pickDone: Boolean = false
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
}
