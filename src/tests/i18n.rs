//! Both languages say everything the code asks for.

use super::*;

/// Every `section.key` a catalog defines.
fn keys(toml: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut section = String::new();
    for line in toml.lines() {
        let line = line.trim();
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = name.to_string();
        } else if let Some((key, _)) = line.split_once(" = ") {
            if !line.starts_with('#') {
                out.push(format!("{section}.{key}"));
            }
        }
    }
    out
}

/// A key missing from one language renders as the key itself on that
/// language's screen — so the two lists have to be the same list.
#[test]
fn both_languages_have_the_same_strings() {
    let en = keys(include_str!("../../locales/en.toml"));
    // `[module]` is the host's: its English lives in limen.toml.
    let uk: Vec<String> =
        keys(include_str!("../../locales/uk.toml")).into_iter().filter(|k| !k.starts_with("module.")).collect();
    assert_eq!(en, uk);
    assert!(en.len() > 20, "the catalogue was read: {en:?}");
}

/// Every string the code names exists in both languages, and nothing is
/// defined that nothing names — a typo in a key shows up as the key, on
/// screen, in front of a user.
#[test]
fn every_string_the_code_asks_for_exists() {
    let defined = keys(include_str!("../../locales/en.toml"));
    let sections: Vec<&str> = defined.iter().filter_map(|k| k.split('.').next()).collect();

    // Every `"section.key"` literal in the sources, for a section the
    // catalogue has — however the code goes on to look it up.
    let mut asked = Vec::new();
    for source in [include_str!("../handler.rs"), include_str!("../view.rs")] {
        for literal in source.split('"').skip(1).step_by(2) {
            let Some((section, key)) = literal.split_once('.') else { continue };
            let word = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit());
            if word(section) && word(key) && sections.contains(&section) {
                asked.push(literal.to_string());
            }
        }
    }
    assert!(asked.len() > 30, "{asked:?}");
    for key in &asked {
        for lang in ["en", "uk"] {
            assert_ne!(&catalog().tr(lang, key), key, "{lang} has no {key}");
        }
    }
    for key in &defined {
        assert!(asked.contains(key), "{key} is in the catalogue and never used");
    }
}

#[test]
fn placeholders_survive_translation() {
    for key in keys(include_str!("../../locales/en.toml")) {
        let en = catalog().tr("en", &key);
        let uk = catalog().tr("uk", &key);
        for mark in ["{n}", "{what}", "{size}", "{shown}", "{given}"] {
            assert_eq!(en.matches(mark).count(), uk.matches(mark).count(), "{key}: {mark}");
        }
    }
}
