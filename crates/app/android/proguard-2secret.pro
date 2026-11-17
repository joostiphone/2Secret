# 2Secret (scripts/android.sh copies this next to the app's build.gradle.kts,
# whose release build reads every *.pro there). Rust (crates/app/src) calls
# MainActivity's methods and reads its static fields by name through JNI:
# R8 must neither remove nor rename them. The AutoFill service and its screen
# are kept through the manifest.
-keep class dev.dioxus.main.MainActivity { *; }
