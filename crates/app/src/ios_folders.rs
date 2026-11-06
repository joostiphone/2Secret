//! iPhone and iPad: folders chosen in the Files app's folder picker.
//!
//! iOS gives the app the folder the person chose (in iCloud Drive, On My
//! iPhone, or a storage app that allows it). 2Secret keeps a bookmark of
//! it, to open it again after a restart, and reaches its files through
//! `NSFileCoordinator`: a coordinated read downloads a file that is still in
//! the cloud before it is read, and coordinated writes tell the storage app
//! what changed.

use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::ptr::NonNull;
use std::sync::{Arc, Mutex};

use base64::Engine;
use block2::StackBlock;
use objc2::rc::{Allocated, Retained};
use objc2::runtime::{AnyClass, AnyObject, Bool, NSObject};
use objc2::{define_class, msg_send, AnyThread, DefinedClass, MainThreadMarker, MainThreadOnly};
use objc2_foundation::{
    NSArray, NSData, NSError, NSFileCoordinator, NSFileCoordinatorReadingOptions, NSFileCoordinatorWritingOptions,
    NSFileManager, NSString, NSURLBookmarkCreationOptions, NSURLBookmarkResolutionOptions, NSURL,
};
use twosecret_client::folder::{Coordinator, FolderFs, LocalFs};
use twosecret_core::profile::FolderService;

use crate::picked::Chosen;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// iCloud Drive's own folder, in the paths iOS gives.
const ICLOUD: &str = "/Mobile Documents/com~apple~CloudDocs";

// ---------------------------------------------------------------------------
// The folder picker
// ---------------------------------------------------------------------------

struct PickerIvars {
    reply: RefCell<Option<futures_channel::oneshot::Sender<Option<Chosen>>>>,
}

define_class!(
    // SAFETY: NSObject has no subclassing requirements, and FolderPicker
    // does not implement Drop.
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "TwoSecretFolderPicker"]
    #[ivars = PickerIvars]
    struct FolderPicker;

    impl FolderPicker {
        #[unsafe(method(documentPicker:didPickDocumentsAtURLs:))]
        fn did_pick(&self, _picker: &AnyObject, urls: &NSArray<NSURL>) {
            let chosen = urls.firstObject().and_then(|url| chosen(&url));
            self.finish(chosen);
        }

        #[unsafe(method(documentPickerWasCancelled:))]
        fn cancelled(&self, _picker: &AnyObject) {
            self.finish(None);
        }
    }
);

impl FolderPicker {
    fn finish(&self, chosen: Option<Chosen>) {
        if let Some(reply) = self.ivars().reply.borrow_mut().take() {
            let _ = reply.send(chosen);
        }
    }
}

thread_local! {
    /// The picker's delegate while it is shown (UIKit keeps only a weak
    /// reference to it).
    static ACTIVE: RefCell<Option<Retained<FolderPicker>>> = const { RefCell::new(None) };
}

/// A folder picker for folders (`UIDocumentPickerViewController`).
fn new_picker() -> Option<Retained<AnyObject>> {
    let class = AnyClass::get(c"UIDocumentPickerViewController")?;
    unsafe {
        let alloc: Allocated<AnyObject> = msg_send![class, alloc];
        // iOS 14 and later: content types; before: type identifiers.
        if let Some(types) = AnyClass::get(c"UTType") {
            let folder: Option<Retained<AnyObject>> =
                msg_send![types, typeWithIdentifier: &*NSString::from_str("public.folder")];
            let list = NSArray::from_retained_slice(&[folder?]);
            msg_send![alloc, initForOpeningContentTypes: &*list]
        } else {
            let list = NSArray::from_retained_slice(&[NSString::from_str("public.folder")]);
            // UIDocumentPickerModeOpen
            msg_send![alloc, initWithDocumentTypes: &*list, inMode: 1usize]
        }
    }
}

/// The view controller on top, to present the picker from.
fn top_controller() -> Option<*mut AnyObject> {
    use dioxus::mobile::tao::platform::ios::WindowExtIOS;
    let mut top = dioxus::mobile::window().window.ui_view_controller() as *mut AnyObject;
    if top.is_null() {
        return None;
    }
    loop {
        let presented: *mut AnyObject = unsafe { msg_send![top, presentedViewController] };
        if presented.is_null() {
            return Some(top);
        }
        top = presented;
    }
}

/// Let the person choose a folder in the Files app's folder picker.
pub async fn pick() -> Option<Chosen> {
    let Some(mtm) = MainThreadMarker::new() else {
        eprintln!("2Secret: the folder picker needs the main thread");
        return None;
    };
    let (tx, rx) = futures_channel::oneshot::channel();
    let delegate: Retained<FolderPicker> = {
        let this = FolderPicker::alloc(mtm).set_ivars(PickerIvars { reply: RefCell::new(Some(tx)) });
        unsafe { msg_send![super(this), init] }
    };
    let picker = new_picker()?;
    let top = top_controller()?;
    unsafe {
        let _: () = msg_send![&*picker, setDelegate: &*delegate];
        let _: () = msg_send![&*picker, setAllowsMultipleSelection: false];
        let none: Option<&block2::DynBlock<dyn Fn()>> = None;
        let _: () = msg_send![top, presentViewController: &*picker, animated: true, completion: none];
    }
    ACTIVE.with(|a| *a.borrow_mut() = Some(delegate));
    let result = rx.await.ok().flatten();
    ACTIVE.with(|a| a.borrow_mut().take());
    result
}

/// The folder the picker gave: access to it for as long as the app runs,
/// and a bookmark to open it again later.
fn chosen(url: &NSURL) -> Option<Chosen> {
    // Balanced never: the folder stays open while the app runs. Access is
    // started once for the folder, not per file (the system runs out of
    // sandbox extensions otherwise).
    unsafe { url.startAccessingSecurityScopedResource() };
    let bookmark = match url.bookmarkDataWithOptions_includingResourceValuesForKeys_relativeToURL_error(
        NSURLBookmarkCreationOptions::MinimalBookmark,
        None,
        None,
    ) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("2Secret: no bookmark for the chosen folder: {}", e.localizedDescription());
            return None;
        }
    };
    let path = url.path()?.to_string();
    let token = B64.encode(bookmark.to_vec());
    if let Ok(mut open) = OPEN.lock() {
        open.get_or_insert_with(HashMap::new).insert(token.clone(), PathBuf::from(&path));
    }
    let in_icloud = path.find(ICLOUD).map(|i| path[i + ICLOUD.len()..].trim_matches('/').to_string());
    let name = match &in_icloud {
        Some(rest) if rest.is_empty() => "iCloud Drive".to_string(),
        _ => Path::new(&path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| path.clone()),
    };
    Some(Chosen {
        token,
        key: path,
        name,
        service: in_icloud.is_some().then_some(FolderService::ICloudDrive),
        service_path: in_icloud,
    })
}

// ---------------------------------------------------------------------------
// Opening a chosen folder again
// ---------------------------------------------------------------------------

/// The chosen folders opened since the app started, by bookmark.
static OPEN: Mutex<Option<HashMap<String, PathBuf>>> = Mutex::new(None);

fn ns_error(e: &NSError) -> io::Error {
    // NSFileNoSuchFileError, NSFileReadNoSuchFileError
    let kind = if matches!(e.code(), 4 | 260) { io::ErrorKind::NotFound } else { io::ErrorKind::Other };
    io::Error::new(kind, e.localizedDescription().to_string())
}

/// Open a chosen folder from its bookmark. Returns its files, and a new
/// bookmark when iOS says the old one is getting stale.
pub fn open(token: &str) -> io::Result<(Arc<dyn FolderFs>, Option<String>)> {
    let known = OPEN.lock().ok().and_then(|o| o.as_ref().and_then(|m| m.get(token).cloned()));
    if let Some(path) = known {
        return Ok((files(path), None));
    }
    let bytes = B64.decode(token).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    let data = NSData::with_bytes(&bytes);
    let mut stale = Bool::NO;
    let url = unsafe {
        NSURL::URLByResolvingBookmarkData_options_relativeToURL_bookmarkDataIsStale_error(
            &data,
            NSURLBookmarkResolutionOptions::empty(),
            None,
            &mut stale,
        )
    }
    .map_err(|e| ns_error(&e))?;
    unsafe { url.startAccessingSecurityScopedResource() };
    let path = PathBuf::from(url.path().ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?.to_string());
    let renewed = if stale.as_bool() {
        url.bookmarkDataWithOptions_includingResourceValuesForKeys_relativeToURL_error(
            NSURLBookmarkCreationOptions::MinimalBookmark,
            None,
            None,
        )
        .ok()
        .map(|d| B64.encode(d.to_vec()))
    } else {
        None
    };
    // The URL stays alive with the access it holds, for as long as the app
    // runs.
    std::mem::forget(url);
    if let Ok(mut open) = OPEN.lock() {
        let open = open.get_or_insert_with(HashMap::new);
        open.insert(token.to_string(), path.clone());
        if let Some(new) = &renewed {
            open.insert(new.clone(), path.clone());
        }
    }
    Ok((files(path), renewed))
}

fn files(path: PathBuf) -> Arc<dyn FolderFs> {
    Arc::new(LocalFs::coordinated(path, Arc::new(Coordinated)))
}

// ---------------------------------------------------------------------------
// File coordination
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Access {
    Read,
    Write,
    Remove,
}

/// File access through `NSFileCoordinator`.
struct Coordinated;

fn url_of(path: &Path) -> Retained<NSURL> {
    NSURL::fileURLWithPath(&NSString::from_str(&path.to_string_lossy()))
}

fn coordinate(path: &Path, access: Access, f: &mut dyn FnMut(&Path) -> io::Result<()>) -> io::Result<()> {
    let url = url_of(path);
    let coordinator = NSFileCoordinator::initWithFilePresenter(NSFileCoordinator::alloc(), None);
    let result: RefCell<Option<io::Result<()>>> = RefCell::new(None);
    let f = RefCell::new(f);
    let (result_ref, f_ref) = (&result, &f);
    let block = StackBlock::new(move |new_url: NonNull<NSURL>| {
        // The coordinator may hand a different URL (the item moved).
        let given = unsafe { new_url.as_ref() }.path().map(|p| PathBuf::from(p.to_string()));
        let at = given.unwrap_or_else(|| path.to_path_buf());
        let outcome = (f_ref.borrow_mut())(&at);
        *result_ref.borrow_mut() = Some(outcome);
    });
    let mut error: Option<Retained<NSError>> = None;
    match access {
        Access::Read => coordinator.coordinateReadingItemAtURL_options_error_byAccessor(
            &url,
            NSFileCoordinatorReadingOptions::empty(),
            Some(&mut error),
            &block,
        ),
        Access::Write => coordinator.coordinateWritingItemAtURL_options_error_byAccessor(
            &url,
            NSFileCoordinatorWritingOptions::ForReplacing,
            Some(&mut error),
            &block,
        ),
        Access::Remove => coordinator.coordinateWritingItemAtURL_options_error_byAccessor(
            &url,
            NSFileCoordinatorWritingOptions::ForDeleting,
            Some(&mut error),
            &block,
        ),
    }
    if let Some(e) = error {
        return Err(ns_error(&e));
    }
    result.into_inner().unwrap_or_else(|| Err(io::Error::other("the file was not handed over")))
}

impl Coordinator for Coordinated {
    fn read(&self, path: &Path, f: &mut dyn FnMut(&Path) -> io::Result<()>) -> io::Result<()> {
        coordinate(path, Access::Read, f)
    }

    fn write(&self, path: &Path, f: &mut dyn FnMut(&Path) -> io::Result<()>) -> io::Result<()> {
        coordinate(path, Access::Write, f)
    }

    fn remove(&self, path: &Path, f: &mut dyn FnMut(&Path) -> io::Result<()>) -> io::Result<()> {
        coordinate(path, Access::Remove, f)
    }

    /// Files iCloud Drive has not downloaded yet.
    fn download(&self, paths: &[PathBuf]) {
        let manager = NSFileManager::defaultManager();
        for path in paths {
            let _ = manager.startDownloadingUbiquitousItemAtURL_error(&url_of(path));
        }
    }
}
