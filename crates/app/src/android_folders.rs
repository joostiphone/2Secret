//! Android: folders chosen in the system's folder picker (the Storage Access
//! Framework).
//!
//! The picker gives a document tree (`content://…/tree/…`) that the app may
//! keep using after a restart (MainActivity takes the permission). Its files
//! are reached through `DocumentsContract` and the content resolver: one
//! query lists a folder, files are read and written as streams. Android
//! cannot replace a file by renaming another onto it, so files are written
//! in place ("wt"); the folder format copes with a half-written file.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};

use jni::objects::{JObject, JValue};
use jni::JNIEnv;
use twosecret_client::folder::{FolderFs, FsEntry};
use twosecret_core::profile::FolderService;

use crate::android::{string, with_env};
use crate::picked::Chosen;

/// A folder's type in a document tree.
const DIR_MIME: &str = "vnd.android.document/directory";
/// The type of the files written: the phone's own storage keeps a file's
/// name as given only for this one (it adds an extension otherwise).
const FILE_MIME: &str = "application/octet-stream";
/// The phone's own storage (and SD cards).
const LOCAL: &str = "com.android.externalstorage.documents";
const CONTRACT: &str = "android/provider/DocumentsContract";

fn jni_error(e: String) -> io::Error {
    if e.contains("FileNotFound") {
        io::Error::new(io::ErrorKind::NotFound, e)
    } else {
        io::Error::other(e)
    }
}

// ---------------------------------------------------------------------------
// The folder picker
// ---------------------------------------------------------------------------

/// Let the person choose a folder (`ACTION_OPEN_DOCUMENT_TREE`).
pub async fn pick() -> Option<Chosen> {
    if let Err(e) = with_env(|env, activity| env.call_method(activity, "pickFolder", "()V", &[]).map(|_| ())) {
        eprintln!("2Secret: cannot open the folder picker: {e}");
        return None;
    }
    // MainActivity.onActivityResult says when the picker closed.
    let started = std::time::Instant::now();
    loop {
        crate::platform::sleep_ms(300).await;
        let answer = with_env(|env, activity| {
            let class = env.get_object_class(activity)?;
            if !env.get_static_field(&class, "pickDone", "Z")?.z()? {
                return Ok(None);
            }
            let uri = env.get_static_field(&class, "pickedFolder", "Ljava/lang/String;")?.l()?;
            Ok(Some(if uri.is_null() { None } else { Some(string(env, uri)?) }))
        })
        .ok()?;
        if let Some(tree) = answer {
            return chosen(&tree?);
        }
        if started.elapsed().as_secs() > 30 * 60 {
            return None;
        }
    }
}

fn chosen(tree: &str) -> Option<Chosen> {
    let fs = Tree::open(tree).ok()?;
    let authority = tree.strip_prefix("content://").and_then(|r| r.split('/').next()).unwrap_or_default();
    Some(Chosen {
        token: tree.to_string(),
        key: tree.to_string(),
        name: fs.root_name(),
        service: (authority == LOCAL).then_some(FolderService::Other),
        service_path: None,
    })
}

/// Open a chosen folder again.
pub fn open(token: &str) -> io::Result<(Arc<dyn FolderFs>, Option<String>)> {
    Ok((Arc::new(Tree::open(token)?), None))
}

// ---------------------------------------------------------------------------
// Document trees
// ---------------------------------------------------------------------------

/// A folder in a document tree: `rel` is its way down from the chosen folder.
struct Tree {
    tree: String,
    rel: String,
}

/// The chosen folders found readable since the app started.
static OPENED: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Document ids found so far, by tree and way down (`tree\nrel`).
static IDS: Mutex<Option<HashMap<String, String>>> = Mutex::new(None);
/// The chosen folders' names, by tree.
static NAMES: Mutex<Option<HashMap<String, String>>> = Mutex::new(None);

fn key(tree: &str, rel: &str) -> String {
    format!("{tree}\n{rel}")
}

fn cached(tree: &str, rel: &str) -> Option<String> {
    IDS.lock().ok()?.as_ref()?.get(&key(tree, rel)).cloned()
}

fn remember(tree: &str, rel: &str, id: &str) {
    if let Ok(mut ids) = IDS.lock() {
        ids.get_or_insert_with(HashMap::new).insert(key(tree, rel), id.to_string());
    }
}

/// Forget `rel` and everything in it.
fn forget(tree: &str, rel: &str) {
    if let Ok(mut ids) = IDS.lock() {
        if let Some(ids) = ids.as_mut() {
            let (exact, below) = (key(tree, rel), format!("{}/", key(tree, rel)));
            ids.retain(|k, _| k != &exact && !k.starts_with(&below));
        }
    }
}

fn join(a: &str, b: &str) -> String {
    match (a.is_empty(), b.is_empty()) {
        (true, _) => b.to_string(),
        (_, true) => a.to_string(),
        _ => format!("{a}/{b}"),
    }
}

fn split(rel: &str) -> (&str, &str) {
    rel.rsplit_once('/').unwrap_or(("", rel))
}

fn resolver<'a>(env: &mut JNIEnv<'a>, activity: &JObject) -> jni::errors::Result<JObject<'a>> {
    env.call_method(activity, "getContentResolver", "()Landroid/content/ContentResolver;", &[])?.l()
}

fn uri<'a>(env: &mut JNIEnv<'a>, text: &str) -> jni::errors::Result<JObject<'a>> {
    let text = env.new_string(text)?;
    env.call_static_method(
        "android/net/Uri",
        "parse",
        "(Ljava/lang/String;)Landroid/net/Uri;",
        &[JValue::Object(&text)],
    )?
    .l()
}

fn doc_uri<'a>(env: &mut JNIEnv<'a>, tree: &str, id: &str) -> jni::errors::Result<JObject<'a>> {
    let tree = uri(env, tree)?;
    let id = env.new_string(id)?;
    env.call_static_method(
        CONTRACT,
        "buildDocumentUriUsingTree",
        "(Landroid/net/Uri;Ljava/lang/String;)Landroid/net/Uri;",
        &[JValue::Object(&tree), JValue::Object(&id)],
    )?
    .l()
}

/// One row of a folder: id, name, type, time of change, size.
type Row = (String, String, String, i64, u64);

fn cursor_string(env: &mut JNIEnv, cursor: &JObject, column: i32) -> jni::errors::Result<String> {
    let value = env.call_method(cursor, "getString", "(I)Ljava/lang/String;", &[JValue::Int(column)])?.l()?;
    if value.is_null() {
        Ok(String::new())
    } else {
        string(env, value)
    }
}

fn cursor_long(env: &mut JNIEnv, cursor: &JObject, column: i32) -> jni::errors::Result<i64> {
    if env.call_method(cursor, "isNull", "(I)Z", &[JValue::Int(column)])?.z()? {
        return Ok(0);
    }
    env.call_method(cursor, "getLong", "(I)J", &[JValue::Int(column)])?.j()
}

/// The entries of the folder with document id `parent`.
fn children(tree: &str, parent: &str) -> io::Result<Vec<Row>> {
    with_env(|env, activity| {
        let resolver = resolver(env, activity)?;
        let tree_uri = uri(env, tree)?;
        let parent = env.new_string(parent)?;
        let list = env
            .call_static_method(
                CONTRACT,
                "buildChildDocumentsUriUsingTree",
                "(Landroid/net/Uri;Ljava/lang/String;)Landroid/net/Uri;",
                &[JValue::Object(&tree_uri), JValue::Object(&parent)],
            )?
            .l()?;
        let columns = ["document_id", "_display_name", "mime_type", "last_modified", "_size"];
        let projection = env.new_object_array(columns.len() as i32, "java/lang/String", JObject::null())?;
        for (i, c) in columns.iter().enumerate() {
            let c = env.new_string(c)?;
            env.set_object_array_element(&projection, i as i32, c)?;
        }
        let none = JObject::null();
        let cursor = env
            .call_method(
                &resolver,
                "query",
                "(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;",
                &[
                    JValue::Object(&list),
                    JValue::Object(&projection),
                    JValue::Object(&none),
                    JValue::Object(&none),
                    JValue::Object(&none),
                ],
            )?
            .l()?;
        if cursor.is_null() {
            return Err(jni::errors::Error::NullPtr("query"));
        }
        let mut rows = Vec::new();
        let result = (|| {
            while env.call_method(&cursor, "moveToNext", "()Z", &[])?.z()? {
                let row = env.with_local_frame(8, |env| -> jni::errors::Result<Row> {
                    Ok((
                        cursor_string(env, &cursor, 0)?,
                        cursor_string(env, &cursor, 1)?,
                        cursor_string(env, &cursor, 2)?,
                        cursor_long(env, &cursor, 3)?,
                        cursor_long(env, &cursor, 4)?.max(0) as u64,
                    ))
                })?;
                rows.push(row);
            }
            Ok(())
        })();
        let _ = env.call_method(&cursor, "close", "()V", &[]);
        result.map(|()| rows)
    })
    .map_err(jni_error)
}

fn create_document(tree: &str, parent: &str, mime: &str, name: &str) -> io::Result<String> {
    with_env(|env, activity| {
        let resolver = resolver(env, activity)?;
        let parent = doc_uri(env, tree, parent)?;
        let (mime, name) = (env.new_string(mime)?, env.new_string(name)?);
        let made = env
            .call_static_method(
                CONTRACT,
                "createDocument",
                "(Landroid/content/ContentResolver;Landroid/net/Uri;Ljava/lang/String;Ljava/lang/String;)Landroid/net/Uri;",
                &[JValue::Object(&resolver), JValue::Object(&parent), JValue::Object(&mime), JValue::Object(&name)],
            )?
            .l()?;
        if made.is_null() {
            return Err(jni::errors::Error::NullPtr("createDocument"));
        }
        let id = env
            .call_static_method(CONTRACT, "getDocumentId", "(Landroid/net/Uri;)Ljava/lang/String;", &[JValue::Object(&made)])?
            .l()?;
        string(env, id)
    })
    .map_err(jni_error)
}

fn delete_document(tree: &str, id: &str) -> io::Result<()> {
    with_env(|env, activity| {
        let resolver = resolver(env, activity)?;
        let doc = doc_uri(env, tree, id)?;
        env.call_static_method(
            CONTRACT,
            "deleteDocument",
            "(Landroid/content/ContentResolver;Landroid/net/Uri;)Z",
            &[JValue::Object(&resolver), JValue::Object(&doc)],
        )?;
        Ok(())
    })
    .map_err(jni_error)
}

fn read_document(tree: &str, id: &str) -> io::Result<Vec<u8>> {
    with_env(|env, activity| {
        let resolver = resolver(env, activity)?;
        let doc = doc_uri(env, tree, id)?;
        let stream = env
            .call_method(
                &resolver,
                "openInputStream",
                "(Landroid/net/Uri;)Ljava/io/InputStream;",
                &[JValue::Object(&doc)],
            )?
            .l()?;
        if stream.is_null() {
            return Err(jni::errors::Error::NullPtr("openInputStream"));
        }
        let buf = env.new_byte_array(64 * 1024)?;
        let mut out = Vec::new();
        let result = (|| {
            loop {
                let n = env.call_method(&stream, "read", "([B)I", &[JValue::Object(&buf)])?.i()?;
                if n < 0 {
                    return Ok(());
                }
                let mut chunk = vec![0i8; n as usize];
                env.get_byte_array_region(&buf, 0, &mut chunk)?;
                out.extend(chunk.iter().map(|b| *b as u8));
                // Vault files are small; anything this big is not one.
                if out.len() > 32 * 1024 * 1024 {
                    return Err(jni::errors::Error::NullPtr("file too large"));
                }
            }
        })();
        let _ = env.call_method(&stream, "close", "()V", &[]);
        result.map(|()| out)
    })
    .map_err(jni_error)
}

fn write_document(tree: &str, id: &str, contents: &[u8]) -> io::Result<()> {
    with_env(|env, activity| {
        let resolver = resolver(env, activity)?;
        let doc = doc_uri(env, tree, id)?;
        // "wt": "w" does not always truncate.
        let mode = env.new_string("wt")?;
        let stream = env
            .call_method(
                &resolver,
                "openOutputStream",
                "(Landroid/net/Uri;Ljava/lang/String;)Ljava/io/OutputStream;",
                &[JValue::Object(&doc), JValue::Object(&mode)],
            )?
            .l()?;
        if stream.is_null() {
            return Err(jni::errors::Error::NullPtr("openOutputStream"));
        }
        let bytes = env.byte_array_from_slice(contents)?;
        let written = env.call_method(&stream, "write", "([B)V", &[JValue::Object(&bytes)]).map(|_| ());
        let closed = env.call_method(&stream, "close", "()V", &[]).map(|_| ());
        written.and(closed)
    })
    .map_err(jni_error)
}

impl Tree {
    fn open(tree: &str) -> io::Result<Tree> {
        let fs = Tree { tree: tree.to_string(), rel: String::new() };
        if OPENED.lock().is_ok_and(|o| o.iter().any(|t| t == tree)) {
            return Ok(fs);
        }
        // Still allowed (the permission may have been taken back).
        children(tree, &fs.root_id()?)?;
        if let Ok(mut opened) = OPENED.lock() {
            opened.push(tree.to_string());
        }
        Ok(fs)
    }

    fn root_id(&self) -> io::Result<String> {
        if let Some(id) = cached(&self.tree, "") {
            return Ok(id);
        }
        let id = with_env(|env, _| {
            let tree = uri(env, &self.tree)?;
            let id = env
                .call_static_method(
                    CONTRACT,
                    "getTreeDocumentId",
                    "(Landroid/net/Uri;)Ljava/lang/String;",
                    &[JValue::Object(&tree)],
                )?
                .l()?;
            string(env, id)
        })
        .map_err(jni_error)?;
        remember(&self.tree, "", &id);
        Ok(id)
    }

    fn root_name(&self) -> String {
        if let Some(name) = NAMES.lock().ok().and_then(|n| n.as_ref().and_then(|n| n.get(&self.tree).cloned())) {
            return name;
        }
        let name = with_env(|env, activity| {
            let resolver = resolver(env, activity)?;
            let tree = uri(env, &self.tree)?;
            let id = env
                .call_static_method(CONTRACT, "getTreeDocumentId", "(Landroid/net/Uri;)Ljava/lang/String;", &[JValue::Object(&tree)])?
                .l()?;
            let id = string(env, id)?;
            let doc = doc_uri(env, &self.tree, &id)?;
            let projection = env.new_object_array(1, "java/lang/String", JObject::null())?;
            let column = env.new_string("_display_name")?;
            env.set_object_array_element(&projection, 0, column)?;
            let none = JObject::null();
            let cursor = env
                .call_method(
                    &resolver,
                    "query",
                    "(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;",
                    &[
                        JValue::Object(&doc),
                        JValue::Object(&projection),
                        JValue::Object(&none),
                        JValue::Object(&none),
                        JValue::Object(&none),
                    ],
                )?
                .l()?;
            if cursor.is_null() {
                return Ok(String::new());
            }
            let name =
                if env.call_method(&cursor, "moveToFirst", "()Z", &[])?.z()? { cursor_string(env, &cursor, 0)? } else { String::new() };
            let _ = env.call_method(&cursor, "close", "()V", &[]);
            Ok(name)
        })
        .unwrap_or_default();
        // A document id like "primary:Sync/Vault" ends in the folder's name.
        let name = if name.is_empty() {
            self.tree.rsplit("%2F").next().unwrap_or_default().rsplit("%3A").next().unwrap_or_default().to_string()
        } else {
            name
        };
        if let Ok(mut names) = NAMES.lock() {
            names.get_or_insert_with(HashMap::new).insert(self.tree.clone(), name.clone());
        }
        name
    }

    /// The entries of the folder `abs` (its way down from the chosen
    /// folder), with their document ids; `None` when it is not there.
    fn rows(&self, abs: &str) -> io::Result<Option<Vec<Row>>> {
        let Some(id) = self.id_of(abs)? else { return Ok(None) };
        match children(&self.tree, &id) {
            Ok(rows) => {
                for row in &rows {
                    remember(&self.tree, &join(abs, &row.1), &row.0);
                }
                Ok(Some(rows))
            }
            // An id from before (the folder went or moved): look again once.
            Err(_) if !abs.is_empty() && cached(&self.tree, abs).is_some() => {
                forget(&self.tree, abs);
                let Some(id) = self.id_of(abs)? else { return Ok(None) };
                let rows = children(&self.tree, &id)?;
                for row in &rows {
                    remember(&self.tree, &join(abs, &row.1), &row.0);
                }
                Ok(Some(rows))
            }
            Err(e) => Err(e),
        }
    }

    /// The document id of `abs`, looked up from the chosen folder down.
    fn id_of(&self, abs: &str) -> io::Result<Option<String>> {
        if abs.is_empty() {
            return self.root_id().map(Some);
        }
        if let Some(id) = cached(&self.tree, abs) {
            return Ok(Some(id));
        }
        let (parent, name) = split(abs);
        let Some(rows) = self.rows(parent)? else { return Ok(None) };
        Ok(rows.into_iter().find(|r| r.1 == name).map(|r| r.0))
    }

    /// The document id of the folder `abs`, made (one folder at a time) if
    /// it is not there.
    fn ensure_dir(&self, abs: &str) -> io::Result<String> {
        if let Some(id) = self.id_of(abs)? {
            return Ok(id);
        }
        let (parent, name) = split(abs);
        let parent_id = self.ensure_dir(parent)?;
        let id = create_document(&self.tree, &parent_id, DIR_MIME, name)?;
        remember(&self.tree, abs, &id);
        Ok(id)
    }

    fn abs(&self, rel: &str) -> io::Result<String> {
        if rel.split('/').any(|p| p == "." || p == "..") || rel.starts_with('/') || rel.contains("//") {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("unexpected file name {rel}")));
        }
        Ok(join(&self.rel, rel))
    }
}

impl FolderFs for Tree {
    fn describe(&self) -> String {
        if self.rel.is_empty() {
            self.tree.clone()
        } else {
            format!("{}#{}", self.tree, self.rel)
        }
    }

    fn name(&self) -> String {
        if self.rel.is_empty() {
            self.root_name()
        } else {
            split(&self.rel).1.to_string()
        }
    }

    fn list(&self, dir: &str) -> io::Result<Option<Vec<FsEntry>>> {
        let rows = self.rows(&self.abs(dir)?)?;
        Ok(rows.map(|rows| {
            rows.into_iter()
                .map(|(_, name, mime, modified, size)| FsEntry { name, dir: mime == DIR_MIME, stamp: (modified, size) })
                .collect()
        }))
    }

    fn read(&self, path: &str) -> io::Result<Option<Vec<u8>>> {
        let abs = self.abs(path)?;
        let Some(id) = self.id_of(&abs)? else { return Ok(None) };
        match read_document(&self.tree, &id) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                forget(&self.tree, &abs);
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    fn write(&self, path: &str, contents: &[u8]) -> io::Result<()> {
        let abs = self.abs(path)?;
        let (parent, name) = split(&abs);
        if name.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "no file name"));
        }
        let id = match self.id_of(&abs)? {
            Some(id) => id,
            None => {
                let parent_id = self.ensure_dir(parent)?;
                let id = create_document(&self.tree, &parent_id, FILE_MIME, name)?;
                remember(&self.tree, &abs, &id);
                id
            }
        };
        match write_document(&self.tree, &id, contents) {
            // Gone meanwhile: make it again.
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                forget(&self.tree, &abs);
                let parent_id = self.ensure_dir(parent)?;
                let id = create_document(&self.tree, &parent_id, FILE_MIME, name)?;
                remember(&self.tree, &abs, &id);
                write_document(&self.tree, &id, contents)
            }
            other => other,
        }
    }

    fn remove(&self, path: &str) -> io::Result<()> {
        let abs = self.abs(path)?;
        if abs.is_empty() {
            return Ok(());
        }
        let Some(id) = self.id_of(&abs)? else { return Ok(()) };
        let result = delete_document(&self.tree, &id);
        forget(&self.tree, &abs);
        match result {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            other => other,
        }
    }

    fn create(&self) -> io::Result<()> {
        self.ensure_dir(&self.rel).map(|_| ())
    }

    fn remove_all(&self) -> io::Result<()> {
        // Never the chosen folder itself (remove refuses it too); a folder
        // goes with what is in it.
        if self.rel.is_empty() {
            return Ok(());
        }
        self.remove("")
    }

    fn child(&self, path: &str) -> Arc<dyn FolderFs> {
        Arc::new(Tree { tree: self.tree.clone(), rel: join(&self.rel, path.trim_matches('/')) })
    }
}
