# Vaults in storage folders

Every vault has a **location**:

| Location | What it means |
|---|---|
| With the account | On the account's sync server, on all its devices (or, for an account without a server, on this device; such vaults go to a server the account connects to later). The only location where a vault can be shared or be part of emergency access. |
| This device only | Never leaves the device, also in an account with a sync server. |
| A storage folder | In a folder that a storage app keeps in sync between devices: iCloud Drive, Dropbox, Google Drive, OneDrive, Syncthing, a network share. Only the account's own devices can open it. |
| A WebDAV server | In a folder on a WebDAV server: Nextcloud, ownCloud, a Synology or QNAP NAS, Koofr, Fastmail and others. The same format as a storage folder, reached over HTTPS. |

Vaults in storage folders work in the desktop apps (macOS, Windows, Linux,
BSD), the command line and, through the system's folder picker, on iPhone,
iPad and Android (see *On iPhone, iPad and Android* below). Vaults on a
WebDAV server work in all of them. The web vault and the browser extension
show where such a vault is, but cannot open it (browsers may only reach a
WebDAV server that allows it, which few do).

## Where each service works

The apps and the command line show this table (from
`FolderService::availability()` in `crates/core/src/folder.rs`) when a
service is chosen:

| Service | macOS | Windows | Linux | BSD | iPhone/iPad | Android | Web/extension |
|---|---|---|---|---|---|---|---|
| iCloud Drive | ✓ | ✓ (iCloud for Windows) | ✗ | ✗ | ✓ | ✗ | ✗ |
| Dropbox | ✓ | ✓ | ✓ | ✗ | later | later | ✗ |
| Google Drive | ✓ | ✓ | ✗ (no official app) | ✗ | later | later | ✗ |
| OneDrive | ✓ | ✓ | ✗ (no official app) | ✗ | later | later | ✗ |
| Other folder (Syncthing, a NAS) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ |

✗ means the service has no app there, so the vault can never show up there.
*Later* means its app does not let other apps choose a folder there; a
direct connection to the service is planned.

A vault on a WebDAV server works everywhere except in the web vault and the
browser extension.

## On iPhone, iPad and Android

An app on a phone reaches only the folders the person gives it in the
system's folder picker. 2Secret keeps what it needs to open such a folder
again in `picked-folders.json` in its own data folder (it never leaves the
device), and a vault there records the chosen folder and the way down to
its own folder (`VaultLocation::Folder.grant`).

- **iPhone and iPad**: the Files app's folder picker. iCloud Drive and *On
  My iPhone* work, and so does a folder that Möbius Sync (Syncthing) keeps
  in sync there; most storage apps (Google Drive, OneDrive, often Dropbox)
  do not let other apps choose a folder. 2Secret keeps a bookmark of the
  folder and reaches its files through `NSFileCoordinator`, which downloads
  a file that is still in iCloud before it is read and tells the storage
  app what changed.
- **Android**: the system's folder picker (`ACTION_OPEN_DOCUMENT_TREE`).
  Folders on the phone work, for instance one that Syncthing-Fork or
  FolderSync keeps in sync; Google Drive and Dropbox offer no folders there.
  Android cannot replace a file by renaming another onto it, so files are
  written in place; another device may see a half-written file, which it
  skips and reads again later.

A phone cannot find a storage app's folder by itself. A vault that another
device moved to a folder shows *Choose the folder*; once the person chose
it (the service's own folder, the `2Secret` folder in it or the vault's
folder), the phone remembers it for that service and finds vaults moved
there later by itself. A vault made on a phone gets its folder in
`<chosen folder>/2Secret/`; desktops find it by its path in the service's
folder, or else in `<service folder>/2Secret/<vault folder>`.

## WebDAV

A vault on a WebDAV server is kept in `<address>/2Secret/<name>-<id8>/`,
exactly as in a storage folder. The address may be that of a WebDAV folder
or just the server's: for Nextcloud and ownCloud, 2Secret finds the user's
files at `remote.php/dav/files/<user>/` by itself. Plain `http://` is only
accepted for this device (`localhost`). Use an app password where the server
offers one (Nextcloud: *Settings → Security → Devices & sessions*).

The user name, and the password encrypted with the vault key (associated
data `2secret/v1/webdav-password/<vault id>`), are stored with the vault, so
every device of the account can open it: when a vault moves from the sync
server to a WebDAV server, the placeholder on the sync server (and a
`moved.json`) carries them, and the account's other devices, phones
included, follow the vault without being asked.

Files are written with `PUT` (servers keep a half-written upload out of
sight), listed with `PROPFIND`, and fetched again only when their ETag
changed.

## The folder

A new vault in a folder gets its own folder: `<chosen folder>/2Secret/<name>-<id8>/`
(the name is only for people; the vault is identified by `vault.json`).

```
vault.json                 written once
meta~<tag>.json            one per device: the vault's name, description, icon
items/<item>~<tag>.json    one per item per device that changed it
moved.json                 only after the vault moved away (or was deleted)
```

`<tag>` is a random ten-character name of the device (`Profile.device_tag`,
lowercase base32). Item ids and tags are the only names in the folder.

### vault.json

```json
{
  "format": "2secret-vault-folder",
  "version": 1,
  "vault_id": "…",
  "account_id": "…",
  "created_at": 1767225600,
  "wrapped_key": { "type": "symmetric", … }
}
```

`wrapped_key` is the vault key wrapped with the account key (associated data
`2secret/v1/vault-key/<vault id>`), exactly as on the server. A device takes
the key only if it is wrapped with **its own account key**: a key sealed to
the account's public key (which anyone could make) is refused, and so is a
folder of another account.

### meta~&lt;tag&gt;.json

`{ "vault_id": …, "meta": EncString }`: the vault's name, description and
icon with the time they were changed, encrypted with the vault key
(associated data `2secret/v1/vault-meta-version/<vault id>`). The newest
version wins.

### items/&lt;item&gt;~&lt;tag&gt;.json

`{ "id": …, "vault_id": …, "data": EncString | absent, "tomb": EncString | absent }`

- `data` is the item, encrypted exactly as for the server (associated data
  `2secret/v1/item/<vault id>/<item id>`).
- `tomb` marks a deletion: `{ "deleted_at": … }` encrypted with the vault
  key (associated data `2secret/v1/item-tombstone/<vault id>/<item id>`).
  The storage service cannot fake a deletion.

### moved.json

`{ "vault_id": …, "moved": EncString }`: where the vault went (back to the
server, to one device, to another folder) or that it was deleted, encrypted
with the vault key (associated data `2secret/v1/vault-moved/<vault id>`).
Devices that find it follow the vault and stop writing to the folder.

## One writer per file

A device writes only its own files and never changes another device's, so a
storage app never sees two devices change the same file and has no reason to
make "conflicted copies". If it makes one anyway (`x~tag 2.json`,
`x~tag (1).json`, `x~tag (conflicted copy).json`, `x~tag-PC.json`,
`x~tag.sync-conflict-….json`), it is read like the others; a device removes
the copies of its own files once their contents are merged.

Files are written atomically: a temporary file (`.~tmp-…`) in the same
folder, then a rename.

## Merging

On every sync a device reads all versions of every item (from all devices,
copies included) and its own copy, and merges them with the rule the server
sync uses:

- the version with the newest `updated_at` wins;
- the current and earlier passwords of the other versions are kept in the
  winner's password history (at most 50), so no password is ever lost;
- a deletion wins unless an edit is newer than it ("an edit after a deletion
  brings the item back").

Every device computes the same result from the same files, so a device
writes its own version only when the merged result is not in the folder yet:
its own change, or something only it still has.

A file that is missing, half downloaded or cannot be opened is skipped and
read again later; it is **never** taken as a deletion. Only a tombstone
deletes.

## Clearing up

- Copies of a device's own files go once merged.
- When every version of an item is a tombstone, each device removes its own
  tombstone after 90 days. A device that was away longer than that can bring
  a deleted item back.

## Moving a vault

A vault keeps its id and key wherever it goes, so moving it needs no
re-encryption and every device of the account can follow it. A move copies
the vault, checks the copy, switches, and only then clears the old place; an
interrupted move leaves the vault intact where it was.

- **Server → folder**: after a full sync, all files are written and read
  back. The server keeps an empty **placeholder** with the same id, whose
  encrypted metadata says where the vault went (`VaultMeta.moved`: the
  service and the vault's path inside the service's folder). Other desktops
  of the account look for that path in their own service folder and take the
  vault from there; phones and the web vault show where it is. Items still
  added to the placeholder (by a device that was offline, or by an older
  version of 2Secret) are taken into the folder and removed from the
  placeholder by any device that has the folder.
- **Server → this device**: the vault is removed from the server; the
  account's other devices lose it.
- **Folder → server**: a last folder sync, then everything is uploaded (to
  the placeholder, which becomes the vault again). `moved.json` tells the
  other devices, which upload what only they still had; the item files are
  removed from the folder.
- **Server → WebDAV server**: as server → folder; the placeholder also
  carries the WebDAV password (encrypted with the vault key), so other
  devices, phones included, take the vault from the WebDAV server
  themselves.
- **Folder → this device / another folder / a WebDAV server**, **this
  device → server / a folder**: the same steps, without the server where it
  is not involved.

Shared vaults stay on the server (stop sharing first). Emergency access
covers only vaults on the server.

## Deleting a vault

Deleting a vault in a folder removes its files and writes a `moved.json`
saying it was deleted, so the other devices remove it too; the server
placeholder goes as well.

## What a storage folder sees

See *What a storage folder sees* in [SECURITY.md](SECURITY.md).
