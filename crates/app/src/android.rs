//! Android: the few things that need the Java side (through JNI).

use std::path::PathBuf;

use jni::objects::{JObject, JString, JValue};
use jni::{JNIEnv, JavaVM};

/// Run `f` with the JNI environment and the app's activity, inside a local
/// reference frame (the UI thread never returns to Java, so local
/// references would otherwise pile up).
fn with_env<T>(f: impl FnOnce(&mut JNIEnv, &JObject) -> jni::errors::Result<T>) -> Result<T, String> {
    let ctx = ndk_context::android_context();
    // SAFETY: tao stores the VM and a global reference to the activity in
    // ndk_context before the app starts; both live as long as the app.
    let vm = unsafe { JavaVM::from_raw(ctx.vm().cast()) }.map_err(|e| e.to_string())?;
    let mut env = vm.attach_current_thread().map_err(|e| e.to_string())?;
    let activity = unsafe { JObject::from_raw(ctx.context().cast()) };
    let result = env.with_local_frame(16, |env| f(env, &activity));
    if env.exception_check().unwrap_or(false) {
        let _ = env.exception_describe();
        let _ = env.exception_clear();
    }
    result.map_err(|e| e.to_string())
}

fn string(env: &mut JNIEnv, obj: JObject) -> jni::errors::Result<String> {
    Ok(env.get_string(&JString::from(obj))?.into())
}

/// The app's private directory that is left out of Android's cloud backups,
/// so a backup never holds the Secret Key next to the encrypted vault.
pub fn data_dir() -> Option<PathBuf> {
    with_env(|env, activity| {
        let dir = env.call_method(activity, "getNoBackupFilesDir", "()Ljava/io/File;", &[])?.l()?;
        let path = env.call_method(&dir, "getAbsolutePath", "()Ljava/lang/String;", &[])?.l()?;
        Ok(PathBuf::from(string(env, path)?).join("2Secret"))
    })
    .ok()
}

/// The system language ("nl", "en", ...).
pub fn language() -> Option<String> {
    with_env(|env, _| {
        let locale = env.call_static_method("java/util/Locale", "getDefault", "()Ljava/util/Locale;", &[])?.l()?;
        let lang = env.call_method(&locale, "getLanguage", "()Ljava/lang/String;", &[])?.l()?;
        string(env, lang)
    })
    .ok()
    .filter(|l| !l.is_empty())
}

/// The phone's model name, e.g. "Pixel 8".
pub fn device_model() -> Option<String> {
    with_env(|env, _| {
        let model = env.get_static_field("android/os/Build", "MODEL", "Ljava/lang/String;")?.l()?;
        string(env, model)
    })
    .ok()
    .filter(|m| !m.trim().is_empty())
}

/// Open a web address in the user's browser.
pub fn open_url(url: &str) {
    let result = with_env(|env, activity| {
        let url = env.new_string(url)?;
        let uri = env
            .call_static_method(
                "android/net/Uri",
                "parse",
                "(Ljava/lang/String;)Landroid/net/Uri;",
                &[JValue::Object(&url)],
            )?
            .l()?;
        let action = env.new_string("android.intent.action.VIEW")?;
        let intent = env.new_object(
            "android/content/Intent",
            "(Ljava/lang/String;Landroid/net/Uri;)V",
            &[JValue::Object(&action), JValue::Object(&uri)],
        )?;
        const FLAG_ACTIVITY_NEW_TASK: i32 = 0x1000_0000;
        env.call_method(&intent, "addFlags", "(I)Landroid/content/Intent;", &[JValue::Int(FLAG_ACTIVITY_NEW_TASK)])?;
        env.call_method(activity, "startActivity", "(Landroid/content/Intent;)V", &[JValue::Object(&intent)])?;
        Ok(())
    });
    if let Err(e) = result {
        eprintln!("2Secret: cannot open {url}: {e}");
    }
}

/// Save a file in Downloads/2Secret (Android 10+), or in the app's folder on
/// shared storage on older versions. Returns where it went.
pub fn save_file(name: &str, mime: &str, content: &[u8]) -> Result<String, String> {
    let sdk = with_env(|env, _| env.get_static_field("android/os/Build$VERSION", "SDK_INT", "I")?.i())?;
    if sdk >= 29 {
        with_env(|env, activity| {
            let values = env.new_object("android/content/ContentValues", "()V", &[])?;
            for (key, value) in [("_display_name", name), ("mime_type", mime), ("relative_path", "Download/2Secret")] {
                let (key, value) = (env.new_string(key)?, env.new_string(value)?);
                env.call_method(
                    &values,
                    "put",
                    "(Ljava/lang/String;Ljava/lang/String;)V",
                    &[JValue::Object(&key), JValue::Object(&value)],
                )?;
            }
            let resolver =
                env.call_method(activity, "getContentResolver", "()Landroid/content/ContentResolver;", &[])?.l()?;
            let collection = env
                .get_static_field("android/provider/MediaStore$Downloads", "EXTERNAL_CONTENT_URI", "Landroid/net/Uri;")?
                .l()?;
            let uri = env
                .call_method(
                    &resolver,
                    "insert",
                    "(Landroid/net/Uri;Landroid/content/ContentValues;)Landroid/net/Uri;",
                    &[JValue::Object(&collection), JValue::Object(&values)],
                )?
                .l()?;
            if uri.is_null() {
                return Err(jni::errors::Error::NullPtr("MediaStore insert"));
            }
            let out = env
                .call_method(
                    &resolver,
                    "openOutputStream",
                    "(Landroid/net/Uri;)Ljava/io/OutputStream;",
                    &[JValue::Object(&uri)],
                )?
                .l()?;
            let bytes = env.byte_array_from_slice(content)?;
            env.call_method(&out, "write", "([B)V", &[JValue::Object(&bytes)])?;
            env.call_method(&out, "close", "()V", &[])?;
            Ok(())
        })?;
        Ok(format!("Downloads/2Secret/{name}"))
    } else {
        let dir = with_env(|env, activity| {
            let none = JObject::null();
            let dir = env
                .call_method(
                    activity,
                    "getExternalFilesDir",
                    "(Ljava/lang/String;)Ljava/io/File;",
                    &[JValue::Object(&none)],
                )?
                .l()?;
            let path = env.call_method(&dir, "getAbsolutePath", "()Ljava/lang/String;", &[])?.l()?;
            string(env, path)
        })?;
        let path = PathBuf::from(dir).join(name);
        std::fs::write(&path, content).map_err(|e| e.to_string())?;
        Ok(path.display().to_string())
    }
}
