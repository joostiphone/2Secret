// Copyright 2021-2025 Tauri Programme within The Commons Conservancy
// SPDX-License-Identifier: Apache-2.0

//! The UIScene life cycle, backported from tao 0.37 for 2Secret (see
//! `vendor/README.md`). An app built with the iOS 27 SDK must use it or it does
//! not start, and only then does iPhone Duo give it its whole screen.
//!
//! Unlike tao 0.37 this keeps the events of tao 0.34: the active scene gives
//! `Event::Resumed` and `Event::Suspended`, like the application delegate did,
//! and the app has one scene (`UIApplicationSupportsMultipleScenes` false).

use std::ffi::{c_char, CStr};

use objc2::runtime::{
  AnyClass as Class, AnyObject as Object, AnyProtocol, ClassBuilder as ClassDecl, Sel,
};

use crate::{
  event::Event,
  platform_impl::platform::{
    app_state,
    event_loop::EventWrapper,
    ffi::{id, nil, NSUInteger},
  },
};

// whether the app adopted the scene life cycle by declaring a
// `UIApplicationSceneManifest` in its Info.plist
// https://developer.apple.com/documentation/bundleresources/information-property-list/uiapplicationscenemanifest
pub unsafe fn scene_lifecycle_enabled() -> bool {
  let bundle: id = msg_send![class!(NSBundle), mainBundle];
  let key: id = msg_send![
    class!(NSString),
    stringWithUTF8String: c"UIApplicationSceneManifest".as_ptr()
  ];
  let manifest: id = msg_send![bundle, objectForInfoDictionaryKey: key];
  !manifest.is_null()
}

// the objects of an NSSet or NSArray (`allObjects` gives an array)
pub unsafe fn objects(collection: id) -> Vec<id> {
  if collection.is_null() {
    return Vec::new();
  }
  let is_set: bool = msg_send![collection, isKindOfClass: class!(NSSet)];
  let array: id = if is_set {
    msg_send![collection, allObjects]
  } else {
    collection
  };
  let count: NSUInteger = msg_send![array, count];
  (0..count)
    .map(|i| -> id { msg_send![array, objectAtIndex: i] })
    .collect()
}

unsafe fn url_from_nsurl(url: id) -> Option<url::Url> {
  if url.is_null() {
    return None;
  }
  let absolute: id = msg_send![url, absoluteString];
  if absolute.is_null() {
    return None;
  }
  let bytes: *const c_char = msg_send![absolute, UTF8String];
  if bytes.is_null() {
    return None;
  }
  let string = CStr::from_ptr(bytes).to_string_lossy();
  string
    .parse()
    .map_err(|e| log::error!("failed to parse URL {string} from a scene: {e}"))
    .ok()
}

// the URLs of a set of `UIOpenURLContext`s, as an `Opened` event
unsafe fn open_url_contexts(contexts: id) {
  let urls: Vec<url::Url> = objects(contexts)
    .into_iter()
    .filter_map(|context| url_from_nsurl(msg_send![context, URL]))
    .collect();
  if !urls.is_empty() {
    app_state::handle_nonuser_event(EventWrapper::StaticEvent(Event::Opened { urls }));
  }
}

extern "C" fn will_connect(_: &Object, _: Sel, scene: id, _session: id, options: id) {
  unsafe {
    app_state::connect_scene(scene);
    // a link that started the app comes with the scene, not with
    // `application:openURL:options:`
    if !options.is_null() {
      open_url_contexts(msg_send![options, URLContexts]);
    }
  }
}

// iOS may disconnect a scene that is in the background to free resources;
// its windows join the scene that connects next
extern "C" fn did_disconnect(_: &Object, _: Sel, scene: id) {
  unsafe {
    if app_state::is_terminated() {
      return;
    }
    app_state::disconnect_scene(scene);
  }
}

extern "C" fn did_become_active(_: &Object, _: Sel, _: id) {
  unsafe { app_state::handle_nonuser_event(EventWrapper::StaticEvent(Event::Resumed)) }
}

extern "C" fn will_resign_active(_: &Object, _: Sel, _: id) {
  unsafe { app_state::handle_nonuser_event(EventWrapper::StaticEvent(Event::Suspended)) }
}

extern "C" fn open_urls(_: &Object, _: Sel, _: id, contexts: id) {
  unsafe { open_url_contexts(contexts) }
}

// universal links
extern "C" fn continue_user_activity(_: &Object, _: Sel, _: id, user_activity: id) {
  unsafe {
    if let Some(url) = url_from_nsurl(msg_send![user_activity, webpageURL]) {
      app_state::handle_nonuser_event(EventWrapper::StaticEvent(Event::Opened {
        urls: vec![url],
      }));
    }
  }
}

// the class the scene configuration names as its delegate; registered on the
// first call, which `create_delegate_class` makes at start, because the system
// looks it up by name when it restores a scene session
pub fn scene_delegate_class() -> &'static Class {
  static CLASS: std::sync::OnceLock<&'static Class> = std::sync::OnceLock::new();
  CLASS.get_or_init(|| unsafe {
    let mut decl = ClassDecl::new(c"TaoSceneDelegate", class!(UIResponder))
      .expect("Failed to declare class `TaoSceneDelegate`");
    if let Some(protocol) = AnyProtocol::get(c"UIWindowSceneDelegate") {
      decl.add_protocol(protocol);
    }
    decl.add_method(
      sel!(scene:willConnectToSession:options:),
      will_connect as extern "C" fn(_, _, _, _, _),
    );
    decl.add_method(
      sel!(sceneDidDisconnect:),
      did_disconnect as extern "C" fn(_, _, _),
    );
    decl.add_method(
      sel!(sceneDidBecomeActive:),
      did_become_active as extern "C" fn(_, _, _),
    );
    decl.add_method(
      sel!(sceneWillResignActive:),
      will_resign_active as extern "C" fn(_, _, _),
    );
    decl.add_method(
      sel!(scene:openURLContexts:),
      open_urls as extern "C" fn(_, _, _, _),
    );
    decl.add_method(
      sel!(scene:continueUserActivity:),
      continue_user_activity as extern "C" fn(_, _, _, _),
    );
    decl.register()
  })
}

// `application:configurationForConnectingSceneSession:options:`, answered even
// when the Info.plist declares no scene manifest: UIKit only asks when the app
// runs on the scene life cycle, and this installs the scene delegate there
pub extern "C" fn configuration_for_connecting_scene_session(
  _: &Object,
  _: Sel,
  _application: id,
  session: id,
  _options: id,
) -> id {
  unsafe {
    // keep the role of the connecting session; a nil name picks the
    // configuration for that role from the Info.plist, or the default one
    let role: id = msg_send![session, role];
    let config: id = msg_send![
      class!(UISceneConfiguration),
      configurationWithName: nil,
      sessionRole: role
    ];
    let () = msg_send![config, setDelegateClass: scene_delegate_class()];
    config
  }
}
