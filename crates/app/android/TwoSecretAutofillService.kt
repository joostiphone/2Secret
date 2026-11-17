// 2Secret as Android's AutoFill service: on a login screen of another app or
// a web page it offers one choice, "Fill with 2Secret". That choice holds no
// login yet: it opens AutofillUnlockActivity, which asks for a fingerprint or
// face, decrypts the store and lets the person pick the login to fill. So
// nothing of the vault reaches Android or the other app before that check.
// 2Secret saves nothing new from here (no SaveInfo).
package dev.dioxus.main

import android.annotation.TargetApi
import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import android.util.Log
import android.widget.RemoteViews

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
