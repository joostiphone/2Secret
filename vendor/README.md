# Vendored crates

## tao 0.34.8 with the UIScene life cycle

An iOS app built with the iOS 27 SDK (Xcode 27) must use the UIScene life
cycle, or it does not start ([TN3187](https://developer.apple.com/documentation/technotes/tn3187-migrating-to-the-uikit-scene-based-life-cycle)).
Only an app built with the iOS 27.1 SDK gets the whole screen of iPhone Duo.
The app's window comes from [tao](https://github.com/tauri-apps/tao) 0.34
through Dioxus 0.7, and tao only supports scenes from 0.37 on, which Dioxus
0.8 uses.

`vendor/tao` is tao 0.34.8 from crates.io with the UIScene support of tao
0.37.1 backported, and the root `Cargo.toml` uses it through
`[patch.crates-io]`. Only the iOS code changed:

- `src/platform_impl/ios/scene.rs` (new): the scene delegate
  `TaoSceneDelegate`. It connects the app's window to the scene, and passes
  `otpauth://` and other links, also the one that started the app, on as
  `Event::Opened`.
- `src/platform_impl/ios/app_state.rs`: on the scene life cycle the app is
  set up when its first scene connects, not in
  `application:didFinishLaunchingWithOptions:`. Windows without a scene wait
  for the next scene that connects.
- `src/platform_impl/ios/view.rs`: a new window joins the connected scene;
  the application delegate answers
  `application:configurationForConnectingSceneSession:options:` with the
  scene delegate; a view laid out while detached from its window is skipped
  instead of crashing.
- `src/platform_impl/ios/mod.rs`: the new module.
- `Cargo.toml`: `[lints.rust]` allows the warnings of the upstream code,
  which a path dependency shows.

Unlike tao 0.37 it keeps tao 0.34's events, which Dioxus 0.7 expects: the
active scene gives `Event::Resumed` and `Event::Suspended`, as the
application delegate did. The app has one scene
(`UIApplicationSupportsMultipleScenes` is false in `ios/project.yml`).

To see the changes, download the crate and compare:

```sh
curl -sSL https://crates.io/api/v1/crates/tao/0.34.8/download | tar xz
diff -ru tao-0.34.8/src vendor/tao/src
```

Remove `vendor/tao` and the `[patch.crates-io]` section when 2Secret moves to
Dioxus 0.8.
