//! A folder: every file in it, and one hash for the whole.

use super::*;
use crate::api;

/// A folder of its own for one test, removed when the test is done with it.
struct Tree(std::path::PathBuf);

impl Tree {
    fn new(test: &str, files: &[(&str, &[u8])]) -> Tree {
        let root = std::env::temp_dir().join(format!("limen-hash-dir-{}-{test}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for (path, bytes) in files {
            let at = root.join(path);
            std::fs::create_dir_all(at.parent().unwrap()).unwrap();
            std::fs::write(at, bytes).unwrap();
        }
        std::fs::create_dir_all(&root).unwrap();
        Tree(root)
    }

    fn path(&self) -> String {
        self.0.to_string_lossy().into_owned()
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const FILES: [(&str, &[u8]); 3] = [("b.txt", b"abc"), ("a.txt", b"abc"), ("sub/deep/c.bin", b"")];

#[test]
fn every_file_is_hashed_and_listed_in_order() {
    let tree = Tree::new("list", &FILES);
    let folder = digest_folder(&tree.path(), Algorithm::Sha256).unwrap();

    let paths: Vec<&str> = folder.files.iter().map(|f| f.path.as_str()).collect();
    assert_eq!(paths, ["a.txt", "b.txt", "sub/deep/c.bin"], "sorted, and with / on every system");
    assert_eq!(folder.files[0].hash, abc(Algorithm::Sha256));
    assert_eq!(folder.files[0].size, 3);
    assert_eq!(folder.files[2].hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_eq!(folder.total_size(), 6);
    assert!(folder.failed.is_empty() && folder.links == 0 && folder.special == 0);
}

/// The folder's hash is the hash of its checksum list, and the list is what
/// `sha256sum` prints — so anybody can recompute it without this module.
#[test]
fn the_folder_hash_is_the_hash_of_its_checksum_list() {
    let tree = Tree::new("hash", &FILES);
    let folder = digest_folder(&tree.path(), Algorithm::Sha256).unwrap();
    let sha = abc(Algorithm::Sha256);
    let listing = format!(
        "{sha}  a.txt\n{sha}  b.txt\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  sub/deep/c.bin\n"
    );
    assert_eq!(folder.listing(), listing);
    assert_eq!(
        folder.hash().as_deref(),
        digest_bytes(listing.as_bytes(), &[Algorithm::Sha256]).of(Algorithm::Sha256)
    );
}

/// Two copies of a folder have the same hash wherever they lie and whatever
/// they are called; a change to any file, its name or its place does not.
#[test]
fn the_same_contents_hash_the_same_and_any_change_does_not() {
    let hash_of = |test: &str, files: &[(&str, &[u8])]| {
        let tree = Tree::new(test, files);
        digest_folder(&tree.path(), Algorithm::Sha256).unwrap().hash().unwrap()
    };
    let original = hash_of("same-1", &FILES);
    assert_eq!(hash_of("same-2", &FILES), original, "another folder, the same files");
    // Written in another order: the order on disk is not part of the answer.
    assert_eq!(hash_of("same-3", &[FILES[2], FILES[0], FILES[1]]), original);

    for (what, files) in [
        ("a byte changed", vec![("b.txt", &b"abd"[..]), FILES[1], FILES[2]]),
        ("a file renamed", vec![("B.txt", &b"abc"[..]), FILES[1], FILES[2]]),
        ("a file moved", vec![("sub/b.txt", &b"abc"[..]), FILES[1], FILES[2]]),
        ("a file removed", vec![FILES[0], FILES[1]]),
        ("a file added", vec![FILES[0], FILES[1], FILES[2], ("new", &b""[..])]),
    ] {
        assert_ne!(hash_of("changed", &files), original, "{what}");
    }
}

#[test]
fn the_algorithm_chosen_is_the_one_used() {
    let tree = Tree::new("algo", &FILES);
    for algorithm in [Algorithm::Md5, Algorithm::Blake3, Algorithm::Crc32, Algorithm::Xxh3] {
        let folder = digest_folder(&tree.path(), algorithm).unwrap();
        assert_eq!(folder.files[0].hash, abc(algorithm), "{algorithm:?}");
        assert_eq!(folder.hash().unwrap().len(), algorithm.hex_len(), "{algorithm:?}");
    }
}

#[test]
fn an_empty_folder_has_no_files_and_still_a_hash() {
    let tree = Tree::new("empty", &[]);
    let folder = digest_folder(&tree.path(), Algorithm::Sha256).unwrap();
    assert!(folder.files.is_empty());
    // The hash of an empty list: the hash of nothing.
    assert_eq!(folder.hash().as_deref(), Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
}

#[test]
fn what_is_not_a_folder_says_so() {
    let file = Scratch::with("not-a-dir", b"abc");
    let e = digest_folder(&file.path(), Algorithm::Sha256).unwrap_err();
    assert!(e.contains("not a folder"), "{e}");
    assert!(digest_folder("/no/such/limen-hash-folder", Algorithm::Sha256).is_err());
}

/// A link is not followed: following them is how a walk leaves the folder it
/// was asked about, or never comes back. It is counted, so it can be said.
#[cfg(unix)]
#[test]
fn links_are_counted_and_not_followed() {
    let tree = Tree::new("links", &FILES);
    std::os::unix::fs::symlink(tree.0.join("a.txt"), tree.0.join("link-to-file")).unwrap();
    // A link back to the folder itself: followed, this would never end.
    std::os::unix::fs::symlink(&tree.0, tree.0.join("sub/loop")).unwrap();

    let folder = digest_folder(&tree.path(), Algorithm::Sha256).unwrap();
    assert_eq!(folder.links, 2);
    assert_eq!(folder.files.len(), 3, "{:?}", folder.files);
    // And they are not in the hash: the folder hashes as it did without them.
    let plain = Tree::new("links-plain", &FILES);
    assert_eq!(folder.hash(), digest_folder(&plain.path(), Algorithm::Sha256).unwrap().hash());
}

/// A file that cannot be read is said, the rest is still hashed — and the
/// folder gets no hash of its own, because a hash of part of it is not its.
#[cfg(unix)]
#[test]
fn an_unreadable_file_costs_the_folder_its_hash_and_nothing_else() {
    use std::os::unix::fs::PermissionsExt;
    let tree = Tree::new("locked", &FILES);
    let locked = tree.0.join("b.txt");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    // Root reads what nobody may; there is nothing to test then.
    if std::fs::File::open(&locked).is_ok() {
        return;
    }
    let folder = digest_folder(&tree.path(), Algorithm::Sha256).unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o644)).unwrap();

    assert_eq!(folder.files.len(), 2);
    assert_eq!(folder.failed.len(), 1);
    assert_eq!(folder.failed[0].0, "b.txt");
    assert_eq!(folder.hash(), None);
}

// ---- the screen ------------------------------------------------------------ //

fn tables(view: &Value) -> Vec<&Value> {
    view["widgets"].as_array().unwrap().iter().filter(|w| w["kind"] == "table").collect()
}

fn step_of(view: &Value) -> Option<(String, String)> {
    view["widgets"].as_array().unwrap().iter().find(|w| w["kind"] == "step").map(|s| {
        (s["state"].as_str().unwrap().to_string(), s["label"].as_str().unwrap().to_string())
    })
}

#[test]
fn a_folder_on_the_screen_is_its_hash_and_its_files() {
    let tree = Tree::new("view", &FILES);
    let mut m = HashChecker::default();
    for lang in ["en", "uk"] {
        let v = m.calculate(&json!({ "path": tree.path() }), lang);
        assert!(m.shown.is_none() && m.folder.is_some());
        let t = tables(&v);
        assert_eq!(t.len(), 2, "{lang}: the folder's own hash, then its files");
        assert_eq!(t[0]["row_ids"], json!(["folder"]));
        assert_eq!(t[0]["rows"][0][0], "SHA-256");
        assert_eq!(t[1]["row_ids"], json!(["f0", "f1", "f2"]));
        assert_eq!(t[1]["rows"][0], json!(["a.txt", catalog().tr(lang, "result.bytes").replace("{n}", "3"), abc(Algorithm::Sha256)]));
        let s = v.to_string();
        assert!(s.contains("\"method\":\"copy_list\""), "{lang}: {s}");
        assert!(!s.contains("{n}") && !s.contains("{what}") && !s.contains("{size}"), "{lang}: {s}");
    }
}

/// The dropdown sends back the label it showed, and that is the algorithm the
/// folder is hashed with — and stays chosen for the next one.
#[test]
fn the_folder_is_hashed_with_the_algorithm_picked() {
    let tree = Tree::new("view-algo", &FILES);
    let mut m = HashChecker::default();
    let v = m.calculate(&json!({ "path": tree.path(), "algorithm": "BLAKE3" }), "en");
    assert_eq!(tables(&v)[1]["rows"][0][2], abc(Algorithm::Blake3));
    assert_eq!(m.algorithm, Some(Algorithm::Blake3));
    let select = v["widgets"].as_array().unwrap().iter().find(|w| w["id"] == "algorithm").unwrap();
    assert_eq!(select["default"], "BLAKE3");
    assert_eq!(select["options"].as_array().unwrap().len(), Algorithm::ALL.len());
    // Every option is a name the module reads back.
    for option in select["options"].as_array().unwrap() {
        assert!(Algorithm::parse(option.as_str().unwrap()).is_some(), "{option}");
    }
}

#[test]
fn a_given_hash_is_looked_for_in_the_folder() {
    let tree = Tree::new("verdict", &FILES);
    let mut m = HashChecker::default();
    let whole = digest_folder(&tree.path(), Algorithm::Sha256).unwrap().hash().unwrap();
    let verdict = |m: &mut HashChecker, expected: &str| {
        let v = m.calculate(&json!({ "path": tree.path(), "expected": expected }), "en");
        (m.folder.as_ref().unwrap().verdict.clone().unwrap(), step_of(&v).unwrap())
    };

    let (is, (state, _)) = verdict(&mut m, &whole);
    assert_eq!((is, state.as_str()), (FolderVerdict::IsTheFolder, "done"));

    // "Is that file in here" — and which ones it is.
    let (is, (state, label)) = verdict(&mut m, &abc(Algorithm::Sha256).to_uppercase());
    assert_eq!(is, FolderVerdict::IsFiles(vec!["a.txt".into(), "b.txt".into()]));
    assert_eq!(state, "done");
    assert!(label.contains('2'), "{label}");

    let (is, (state, _)) = verdict(&mut m, &"0".repeat(64));
    assert_eq!((is, state.as_str()), (FolderVerdict::Nothing, "error"));

    // An MD5 against a folder hashed with SHA-256 is not a mismatch: it was
    // never compared, and saying "does not match" would be a false alarm.
    let (is, (state, label)) = verdict(&mut m, abc(Algorithm::Md5));
    assert_eq!(is, FolderVerdict::OtherKind(vec![Algorithm::Md5]));
    assert_eq!(state, "warning");
    assert!(label.contains("MD5") && label.contains("SHA-256"), "{label}");

    let (is, _) = verdict(&mut m, "not a hash");
    assert_eq!(is, FolderVerdict::NotAHash);
}

/// A long folder is listed in part and said to be: every file is still hashed
/// and still in the checksum list.
#[test]
fn a_long_folder_is_listed_in_part_and_says_so() {
    let names: Vec<String> = (0..view::MAX_ROWS + 20).map(|i| format!("f{i:04}")).collect();
    let files: Vec<(&str, &[u8])> = names.iter().map(|n| (n.as_str(), &b""[..])).collect();
    let tree = Tree::new("long", &files);
    let mut m = HashChecker::default();
    let v = m.calculate(&json!({ "path": tree.path(), "algorithm": "CRC-32" }), "en");
    assert_eq!(tables(&v)[1]["rows"].as_array().unwrap().len(), view::MAX_ROWS);
    assert_eq!(m.folder.as_ref().unwrap().folder.files.len(), view::MAX_ROWS + 20);
    assert_eq!(m.folder.as_ref().unwrap().folder.listing().lines().count(), view::MAX_ROWS + 20);
    assert!(v.to_string().contains(&format!("the first {} of {}", view::MAX_ROWS, view::MAX_ROWS + 20)));
}

/// After a folder, a file's result must not sit beside the folder's, nor the
/// other way round.
#[test]
fn a_file_after_a_folder_replaces_it() {
    let tree = Tree::new("replace", &FILES);
    let mut m = HashChecker::default();
    m.calculate(&json!({ "path": tree.path() }), "en");
    m.calculate(&json!({ "kind": "Text", "text": "abc" }), "en");
    assert!(m.folder.is_none() && m.shown.is_some());
    m.calculate(&json!({ "kind": "Folder", "path": tree.path() }), "en");
    assert!(m.folder.is_some() && m.shown.is_none());
    // A row that belongs to neither is said to be gone.
    assert_eq!(m.copy(&json!({ "id": "f99" }), "en")["notice"]["level"], "error");
    assert_eq!(m.copy(&json!({ "id": "sha256" }), "en")["notice"]["level"], "error");
}

/// A folder dropped where a file was asked for is hashed as the folder it is,
/// and the form follows — and the other way round. Answering "that is a
/// folder" to somebody who can see that helps nobody.
#[test]
fn a_path_is_hashed_as_what_it_is_and_the_form_follows() {
    let tree = Tree::new("as-it-is", &FILES);
    let mut m = HashChecker::default();
    assert_eq!(m.kind, Kind::File);
    let v = m.calculate(&json!({ "path": tree.path() }), "en");
    assert_eq!(m.kind, Kind::Folder);
    assert!(m.folder.is_some());
    assert!(v["widgets"].as_array().unwrap().iter().any(|w| w["id"] == "algorithm"));

    let file = Scratch::with("as-it-is-file", b"abc");
    m.calculate(&json!({ "kind": "Folder", "path": file.path() }), "en");
    assert_eq!(m.kind, Kind::File);
    assert!(m.shown.is_some() && m.folder.is_none());

    // What is neither is still an error, under the kind that was chosen.
    let v = m.calculate(&json!({ "kind": "Folder", "path": "/no/such/limen-hash-folder" }), "en");
    assert_eq!(v["notice"]["level"], "error");
    assert_eq!(m.kind, Kind::Folder);
}

// ---- for other modules ------------------------------------------------------ //

#[test]
fn hash_dir_answers_with_the_files_and_the_folder() {
    let tree = Tree::new("api", &FILES);
    let answer = api::hash_dir(&json!({ "path": tree.path() })).unwrap();
    assert_eq!(answer["algorithm"], "sha256");
    assert_eq!(answer["count"], 3);
    assert_eq!(answer["size"], 6);
    assert_eq!(answer["files"][0], json!({ "path": "a.txt", "size": 3, "hash": abc(Algorithm::Sha256) }));
    assert_eq!(answer["failed"], json!([]));
    assert_eq!(
        answer["hash"].as_str().map(str::to_string),
        digest_folder(&tree.path(), Algorithm::Sha256).unwrap().hash()
    );

    let md5 = api::hash_dir(&json!({ "path": tree.path(), "algorithm": "MD5" })).unwrap();
    assert_eq!(md5["files"][0]["hash"], abc(Algorithm::Md5));

    assert_eq!(api::hash_dir(&json!({})).unwrap_err().code, rpc::INVALID_PARAMS);
    assert_eq!(api::hash_dir(&json!({ "path": tree.path(), "algorithm": "tiger" })).unwrap_err().code, rpc::INVALID_PARAMS);
    assert_eq!(api::hash_dir(&json!({ "path": "/no/such/limen-hash-folder" })).unwrap_err().code, rpc::MODULE_ERROR);
}

/// For a look at a real folder, and to check it with another tool:
/// `HASH_DIR=/path cargo test show_a_folder -- --ignored --nocapture | sha256sum -c`
/// (run from inside that folder).
#[test]
#[ignore = "prints the checksum list of the folder named in HASH_DIR"]
fn show_a_folder() {
    let path = std::env::var("HASH_DIR").expect("HASH_DIR names the folder");
    let folder = digest_folder(&path, Algorithm::Sha256).unwrap();
    print!("{}", folder.listing());
    eprintln!("folder {:?} failed {} links {}", folder.hash(), folder.failed.len(), folder.links);
}
