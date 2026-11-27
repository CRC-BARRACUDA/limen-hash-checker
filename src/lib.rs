//! hash-checker — the hashes of a file or a piece of text, and whether one of
//! them is the hash you were given.
//!
//! It calculates and compares, and that is all it does. A hash is worked out
//! on this machine and stays on it: nothing is looked up anywhere, because what
//! a hash *means* — known-good, known-bad — is another module's question.
//!
//! Twenty-two digests, in one pass over the data — checksums (Adler-32, CRC-32,
//! CRC-64, XXH64, XXH3), the ones only for comparing with what others still
//! publish (MD5, SHA-1), and the ones to rely on (SHA-2, SHA-3, BLAKE2, BLAKE3;
//! RIPEMD-160 and Whirlpool for the tools that print them).
//!
//! A folder is hashed too: every file in it, and one hash for the whole —
//! see [`folder`].
//!
//! ```text
//!   hashing   the digests, and reading a hash somebody was given
//!   folder    a folder: its files' hashes, and one hash for all of it
//!   handler   the module: its state, and which method goes where
//!   view      the screen
//!   api       the same answers as data, for other modules
//!   clipboard putting a hash where it can be pasted
//! ```
//!
//! Methods
//! -------
//!   ui          -> the screen: what to hash, its one field, and optionally a hash
//!   kind        -> file, folder or text was chosen: show its field
//!   calculate   -> hash what the form holds, and compare if a hash was given
//!   clear       -> start over
//!   copy        -> one of the hashes, onto the clipboard
//!   copy_list   -> a folder's checksum list, onto the clipboard
//!   algorithms  -> which digests there are
//!   hash_file   -> a file's hashes, as data
//!   hash_dir    -> a folder: each file's hash and the folder's own, as data
//!   hash_text   -> a text's hashes, as data
//!   hash_base64 -> the hashes of bytes the caller holds, as data
//!   verify      -> whether a given hash is the hash of a file, text or bytes

use std::sync::OnceLock;

mod api;
mod clipboard;
mod folder;
mod handler;
mod hashing;
mod view;

#[cfg(test)]
mod tests;

pub(crate) use folder::*;
pub(crate) use handler::*;
pub(crate) use hashing::*;

pub(crate) use limen_sdk_rust::ui::{
    button, file, label, menu_item, notice, row, select, separator, step, table, text, window,
};
pub(crate) use limen_sdk_rust::{json, rpc, Catalog, Handler, Host, RpcError, Value};

use limen_sdk_rust::export_module;

pub(crate) fn catalog() -> &'static Catalog {
    static C: OnceLock<Catalog> = OnceLock::new();
    C.get_or_init(|| {
        Catalog::new(&[
            ("en", include_str!("../locales/en.toml")),
            ("uk", include_str!("../locales/uk.toml")),
        ])
    })
}

export_module!(HashChecker);
