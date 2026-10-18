//! # twosecret-core
//!
//! The platform independent heart of 2Secret: cryptography, the vault and item
//! model, the unlocked [`Session`], the password generator, TOTP, Watchtower,
//! importers/exporters and the client side of the sync protocol.
//!
//! This crate performs no I/O apart from the optional [`storage::FileStorage`]
//! backend, which makes it usable on every target 2Secret ships to: macOS,
//! Windows, Linux, the BSDs, iOS and the web (`wasm32-unknown-unknown`).

pub mod api;
pub mod autofill;
pub mod biometric;
pub mod brand;
pub mod crypto;
pub mod emergency_kit;
pub mod error;
pub mod export;
pub mod favicon;
pub mod generator;
pub mod import;
pub mod item;
pub mod passkey;
pub mod profile;
pub mod secret_ref;
pub mod session;
pub mod share;
pub mod ssh;
#[cfg(feature = "ssh-agent")]
pub mod ssh_agent;
pub mod storage;
pub mod strength;
pub mod sync;
pub mod totp;
pub mod update;
pub mod util;
pub mod watchtower;
mod wordlist;

pub use error::{Error, Result};
pub use item::{Category, Field, FieldKind, Item, ItemSummary};
pub use profile::Profile;
pub use session::Session;

/// Version of the 2Secret core library.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
