//! The screen: what it offers, and what it says once something is hashed.

use super::*;

fn hashes_on(view: &Value) -> Vec<(String, String)> {
    view["widgets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|w| w["kind"] == "table")
        .map(|t| {
            t["rows"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| (r[0].as_str().unwrap().to_string(), r[1].as_str().unwrap().to_string()))
                .collect()
        })
        .unwrap_or_default()
}

/// Before anything is hashed there is a way to choose what to hash, and
/// nothing pretending to be a result.
#[test]
fn the_screen_starts_with_a_form_and_no_result() {
    for lang in ["en", "uk"] {
        let v = HashChecker::default().view(lang);
        let s = v.to_string();
        assert!(s.contains("\"kind\":\"file\""), "{lang}: {s}");
        assert!(s.contains("\"method\":\"calculate\""), "{lang}: {s}");
        assert!(hashes_on(&v).is_empty(), "{lang}: {s}");
    }
}

#[test]
fn a_file_is_hashed_and_named() {
    let file = Scratch::with("view-file", b"abc");
    let mut m = HashChecker::default();
    let v = m.calculate(&json!({ "path": file.path() }), "en");

    let shown = hashes_on(&v);
    // Every algorithm, in the listed order, each with its hash of "abc".
    let expected: Vec<(String, String)> =
        ABC.iter().map(|(a, hash)| (a.label().to_string(), hash.to_string())).collect();
    assert_eq!(shown, expected);
    let s = v.to_string();
    assert!(s.contains("3 bytes"), "{s}");
    // The file's name, not the whole path, heads the result.
    let name = file.0.file_name().unwrap().to_string_lossy().into_owned();
    assert!(v["widgets"].as_array().unwrap().iter().any(|w| w["text"] == name.as_str()), "{s}");
    // No hash was given, so nothing is said about one.
    assert!(!s.contains("Matches") && !s.contains("Does not match"), "{s}");
}

/// The kind chosen is what is hashed: text when it says text, whatever is
/// still sitting in the path from before.
#[test]
fn the_kind_chosen_decides_what_is_hashed() {
    let file = Scratch::with("view-kind", b"something else entirely");
    let mut m = HashChecker::default();
    let v = m.calculate(&json!({ "kind": "Text", "path": file.path(), "text": "abc" }), "en");
    assert!(hashes_on(&v).contains(&("SHA-256".to_string(), abc(Algorithm::Sha256).to_string())));
    assert!(v.to_string().contains("The text"));

    // And the file when it says file, whatever text was typed earlier.
    let abc_file = Scratch::with("view-kind-file", b"abc");
    let v = m.calculate(&json!({ "kind": "File", "path": abc_file.path(), "text": "not this" }), "en");
    assert!(hashes_on(&v).contains(&("SHA-256".to_string(), abc(Algorithm::Sha256).to_string())));
    assert!(!v.to_string().contains("The text"));
}

/// One dropdown, and the one field that goes with its answer — not three
/// fields that leave it to be guessed which is meant.
#[test]
fn the_form_shows_the_one_field_of_the_kind_chosen() {
    let ids = |v: &Value| -> Vec<String> {
        v["widgets"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|w| w.get("id").and_then(Value::as_str).map(str::to_string))
            .collect()
    };
    for lang in ["en", "uk"] {
        let t = |k: &str| catalog().tr(lang, k);
        // It opens asking for a file.
        let mut m = HashChecker::default();
        let v = m.view(lang);
        assert_eq!(ids(&v), ["kind", "path", "expected"], "{lang}");
        let kind = &v["widgets"][2];
        assert_eq!(kind["options"], json!([t("kind.file"), t("kind.folder"), t("kind.text")]));
        assert_eq!(kind["default"], t("kind.file").as_str());
        assert_eq!(kind["on_change"]["method"], "kind", "the form follows the dropdown at once");
        assert!(v["widgets"][3].get("accepts").is_none(), "a file, not a folder: {}", v["widgets"][3]);

        // The dropdown answers with the label it showed, in the language shown.
        let v = m.choose_kind(&json!({ "kind": t("kind.folder") }), lang);
        assert_eq!(m.kind, Kind::Folder, "{lang}");
        assert_eq!(ids(&v), ["kind", "path", "algorithm", "expected"], "{lang}");
        assert_eq!(v["widgets"][3]["accepts"], "dir");

        let v = m.choose_kind(&json!({ "kind": t("kind.text") }), lang);
        assert_eq!(m.kind, Kind::Text, "{lang}");
        assert_eq!(ids(&v), ["kind", "text", "expected"], "{lang}");
    }
}

/// Changing the kind drops the result — it was the other kind's — and keeps
/// what was typed, so changing one's mind and back costs nothing.
#[test]
fn changing_the_kind_keeps_what_was_typed_and_drops_the_result() {
    let mut m = HashChecker::default();
    m.calculate(&json!({ "kind": "Text", "text": "abc", "expected": "ABCDEF" }), "en");
    assert!(m.shown.is_some());

    // The dropdown reports itself and nothing else.
    let v = m.choose_kind(&json!({ "kind": "File" }), "en");
    assert!(m.shown.is_none() && hashes_on(&v).is_empty());
    assert_eq!((m.text.as_str(), m.expected.as_str()), ("abc", "ABCDEF"));

    let v = m.choose_kind(&json!({ "kind": "Text" }), "en");
    let text = v["widgets"].as_array().unwrap().iter().find(|w| w["id"] == "text").unwrap();
    assert_eq!(text["default"], "abc");
    // Something that is not a kind changes nothing.
    m.choose_kind(&json!({ "kind": "Disk image" }), "en");
    assert_eq!(m.kind, Kind::Text);
}

/// A kind is known by its name in either language, and by its plain key.
#[test]
fn a_kind_is_read_in_either_language() {
    for (answer, kind) in [
        ("File", Kind::File), ("Файл", Kind::File), ("file", Kind::File),
        ("Folder", Kind::Folder), ("Тека", Kind::Folder), ("FOLDER", Kind::Folder),
        ("Text", Kind::Text), ("Текст", Kind::Text),
    ] {
        assert_eq!(Kind::parse(answer), Some(kind), "{answer}");
    }
    assert_eq!(Kind::parse(""), None);
    assert_eq!(Kind::parse("Disk"), None);
}

/// The form keeps what was typed: a redraw that emptied it would make
/// comparing a second hash mean choosing the file again.
#[test]
fn the_form_keeps_what_was_entered() {
    let mut m = HashChecker::default();
    let v = m.calculate(&json!({ "kind": "Text", "text": "abc", "expected": "  ABCDEF  " }), "en");
    let defaults: Vec<&str> = v["widgets"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|w| w.get("default").and_then(Value::as_str))
        .collect();
    assert!(defaults.contains(&"abc") && defaults.contains(&"ABCDEF"), "{defaults:?}");
}

#[test]
fn a_given_hash_is_said_to_match_or_not() {
    let mut m = HashChecker::default();
    for lang in ["en", "uk"] {
        let yes = m.calculate(&json!({ "kind": "Text", "text": "abc", "expected": abc(Algorithm::Sha256).to_uppercase() }), lang);
        assert_eq!(m.shown.as_ref().unwrap().verdict, Some(Verdict::Matches(Algorithm::Sha256)));
        let step = yes["widgets"].as_array().unwrap().iter().find(|w| w["kind"] == "step").unwrap().clone();
        assert_eq!(step["state"], "done", "{lang}");
        assert!(step["label"].as_str().unwrap().contains("SHA-256"), "{lang}: {step}");
        assert!(!step["label"].as_str().unwrap().contains("{what}"), "{lang}: {step}");

        // Found under its own name whichever algorithm it is, not only the
        // first of its length.
        m.calculate(&json!({ "kind": "Text", "text": "abc", "expected": abc(Algorithm::Blake3) }), lang);
        assert_eq!(m.shown.as_ref().unwrap().verdict, Some(Verdict::Matches(Algorithm::Blake3)));

        let no = m.calculate(&json!({ "kind": "Text", "text": "abc", "expected": "0".repeat(32) }), lang);
        assert_eq!(m.shown.as_ref().unwrap().verdict, Some(Verdict::Differs(vec![Algorithm::Md5])));
        let step = no["widgets"].as_array().unwrap().iter().find(|w| w["kind"] == "step").unwrap().clone();
        assert_eq!(step["state"], "error", "{lang}");
        assert!(step["label"].as_str().unwrap().contains("MD5"), "{lang}: {step}");

        // A length several algorithms share is said to be any of them:
        // "it is not the SHA-256" would be a claim about which one was meant.
        let no = m.calculate(&json!({ "kind": "Text", "text": "abc", "expected": "0".repeat(64) }), lang);
        let step = no["widgets"].as_array().unwrap().iter().find(|w| w["kind"] == "step").unwrap().clone();
        assert!(
            step["label"].as_str().unwrap().contains("SHA-256, SHA-512/256, SHA3-256, BLAKE2s, BLAKE3, Kupyna-256, GOST 34.311-95"),
            "{lang}: {step}"
        );

        // Something that is no hash is not "does not match": it is a third answer.
        m.calculate(&json!({ "kind": "Text", "text": "abc", "expected": "the vendor said it was fine" }), lang);
        assert_eq!(m.shown.as_ref().unwrap().verdict, Some(Verdict::NotAHash));
    }
}

/// Nothing to hash, and a file that is not there, are said — and leave the
/// form on the screen to try again with.
#[test]
fn a_failure_is_said_and_leaves_the_form() {
    let mut m = HashChecker::default();
    let v = m.calculate(&json!({}), "en");
    assert_eq!(v["notice"]["level"], "warning");
    assert!(v.to_string().contains("\"kind\":\"file\""));
    assert!(m.shown.is_none());

    let v = m.calculate(&json!({ "path": "/no/such/limen-hash-file" }), "en");
    assert_eq!(v["notice"]["level"], "error");
    assert!(v["notice"]["text"].as_str().unwrap().contains("/no/such/limen-hash-file"));
    assert!(hashes_on(&v).is_empty(), "an old result must not stay under a new failure");
}

/// A stale result must not survive a failed attempt: it would sit under the
/// name of a file it is not the hash of.
#[test]
fn a_failed_attempt_clears_the_previous_result() {
    let mut m = HashChecker::default();
    m.calculate(&json!({ "kind": "Text", "text": "abc" }), "en");
    assert!(m.shown.is_some());
    m.calculate(&json!({ "kind": "File", "path": "/no/such/limen-hash-file" }), "en");
    assert!(m.shown.is_none());
}

#[test]
fn each_hash_can_be_copied_by_its_row() {
    let mut m = HashChecker::default();
    let v = m.calculate(&json!({ "kind": "Text", "text": "abc" }), "en");
    let table = v["widgets"].as_array().unwrap().iter().find(|w| w["kind"] == "table").unwrap();
    assert_eq!(table["row_ids"], json!(Algorithm::ALL.map(Algorithm::key)));
    assert_eq!(table["menu"][0]["label"], "Copy");
    assert_eq!(table["menu"][0]["action"], json!({ "capability": "hash.calc", "method": "copy" }));

    // A row that is not there any more is said to be gone, not copied as
    // something else. (A real copy is not made here: it would overwrite the
    // clipboard of whoever runs the tests.)
    let gone = HashChecker::default().copy(&json!({ "id": "sha256" }), "en");
    assert_eq!(gone["notice"]["level"], "error");
    let unknown = m.copy(&json!({ "id": "tiger" }), "en");
    assert_eq!(unknown["notice"]["level"], "error");
}

#[test]
fn clear_starts_over() {
    let mut m = HashChecker::default();
    m.calculate(&json!({ "kind": "Text", "text": "abc", "expected": "x" }), "en");
    let v = m.clear("en");
    assert!(m.shown.is_none() && m.text.is_empty() && m.expected.is_empty());
    assert!(hashes_on(&v).is_empty());
}

#[test]
fn a_size_is_said_roughly_and_exactly() {
    assert_eq!(view::size_text(0, "en"), "0 bytes");
    assert_eq!(view::size_text(1023, "en"), "1023 bytes");
    assert_eq!(view::size_text(1024, "en"), "1.0 KB (1024 bytes)");
    assert_eq!(view::size_text(5 * 1024 * 1024 * 1024, "en"), "5.0 GB (5368709120 bytes)");
}

#[test]
fn a_file_name_is_the_last_part_of_either_kind_of_path() {
    assert_eq!(file_name("/home/anna/setup.exe"), "setup.exe");
    assert_eq!(file_name(r"C:\Users\Anna\setup.exe"), "setup.exe");
    assert_eq!(file_name("setup.exe"), "setup.exe");
    assert_eq!(file_name("/var/log/"), "log");
}
