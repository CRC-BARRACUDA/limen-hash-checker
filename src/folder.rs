//! A folder: every file in it hashed, and one hash for the folder as a whole.
//!
//! The folder's hash is the hash of its **checksum list** — the lines
//! `sha256sum` would print for its files, in a fixed order:
//!
//! ```text
//!   <hash of the file><two spaces><path inside the folder, with />\n
//! ```
//!
//! one line per file, sorted by path, byte for byte. So it changes when any
//! file changes, appears, disappears or moves, and two copies of a folder are
//! the same exactly when their hashes are — whatever the folder is called and
//! wherever it lies. It is made of nothing that cannot be reproduced by hand,
//! which is the point: a number nobody else can recompute proves nothing.
//!
//! What is *not* in it: empty folders, and anything that is not a file's
//! contents — names of owners, permissions, dates.

use std::path::Path;

use crate::*;

/// One file of a folder.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Entry {
    /// Where it is inside the folder, with `/` between the parts on every
    /// system — so a folder hashes the same on Windows as on Linux.
    pub path: String,
    pub size: u64,
    pub hash: String,
}

/// A folder, hashed.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Folder {
    pub algorithm: Algorithm,
    /// Every file, sorted by path.
    pub files: Vec<Entry>,
    /// What could not be read, and why — a file or a folder inside.
    pub failed: Vec<(String, String)>,
    /// Links that were not followed. Following them is how a walk leaves the
    /// folder it was asked about, or never ends.
    pub links: usize,
    /// What is neither file nor folder — a pipe, a socket, a device — and is
    /// not read: reading a pipe waits for whoever is to write to it.
    pub special: usize,
}

impl Folder {
    pub(crate) fn total_size(&self) -> u64 {
        self.files.iter().map(|f| f.size).sum()
    }

    /// The checksum list: what `sha256sum` would print, and can check.
    pub(crate) fn listing(&self) -> String {
        self.files.iter().map(|f| format!("{}  {}\n", f.hash, f.path)).collect()
    }

    /// The folder's own hash — or nothing when a file could not be read: a
    /// hash of part of a folder would compare equal to nothing and be taken
    /// for the hash of all of it.
    pub(crate) fn hash(&self) -> Option<String> {
        if !self.failed.is_empty() {
            return None;
        }
        digest_bytes(self.listing().as_bytes(), &[self.algorithm]).of(self.algorithm).map(str::to_string)
    }
}

/// Hash every file under `root` with `algorithm`.
///
/// Fails only when `root` itself is not a folder that can be read. A file
/// inside that cannot be is noted and the rest goes on: one locked file should
/// not cost the hashes of the other ten thousand.
pub(crate) fn digest_folder(root: &str, algorithm: Algorithm) -> Result<Folder, String> {
    let base = Path::new(root);
    let said = |e: std::io::Error| format!("{root}: {e}");
    if !std::fs::metadata(base).map_err(said)?.is_dir() {
        return Err(format!("{root}: is not a folder"));
    }
    // The first read is the one that may fail outright.
    std::fs::read_dir(base).map_err(said)?;

    let mut out = Folder { algorithm, files: Vec::new(), failed: Vec::new(), links: 0, special: 0 };
    // Folders still to read, as their path inside the root ("" is the root).
    let mut pending = vec![String::new()];
    while let Some(inside) = pending.pop() {
        let dir = if inside.is_empty() { base.to_path_buf() } else { base.join(&inside) };
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) => {
                out.failed.push((inside, e.to_string()));
                continue;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    out.failed.push((inside.clone(), e.to_string()));
                    continue;
                }
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = if inside.is_empty() { name } else { format!("{inside}/{name}") };
            // The entry's own type, not what it points at: a link is a link.
            let kind = match entry.file_type() {
                Ok(kind) => kind,
                Err(e) => {
                    out.failed.push((path, e.to_string()));
                    continue;
                }
            };
            if kind.is_symlink() {
                out.links += 1;
            } else if kind.is_dir() {
                pending.push(path);
            } else if kind.is_file() {
                match std::fs::File::open(entry.path()).and_then(|f| digest_reader(f, &[algorithm])) {
                    Ok(d) => out.files.push(Entry {
                        hash: d.of(algorithm).unwrap_or_default().to_string(),
                        size: d.size,
                        path,
                    }),
                    Err(e) => out.failed.push((path, e.to_string())),
                }
            } else {
                out.special += 1;
            }
        }
    }
    // By path, byte for byte: the order the folder's hash depends on must not
    // depend on the order a filesystem happens to list things in.
    out.files.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    out.failed.sort();
    Ok(out)
}
