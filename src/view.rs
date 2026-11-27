//! The one screen: what to hash, and — once it has been — what came out.

use crate::*;

/// How many of a folder's files are listed. All of them are hashed and all are
/// in the checksum list; a table of a hundred thousand rows is one nobody
/// reads and the screen cannot draw.
pub(crate) const MAX_ROWS: usize = 500;

/// A size as a person would say it: `4.2 MB`, `812 bytes`.
pub(crate) fn short_size(bytes: u64, lang: &str) -> String {
    const UNITS: [&str; 4] = ["KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = None;
    for u in UNITS {
        if value < 1024.0 {
            break;
        }
        value /= 1024.0;
        unit = Some(u);
    }
    match unit {
        Some(u) => format!("{value:.1} {u}"),
        None => catalog().tr(lang, "result.bytes").replace("{n}", &bytes.to_string()),
    }
}

/// What a folder came to: its own hash, then its files.
fn folder_view(widgets: &mut Vec<limen_sdk_rust::ui::Widget>, shown: &ShownFolder, lang: &str) {
    let t = |k: &str| catalog().tr(lang, k);
    let folder = &shown.folder;
    let n = |s: String, count: usize| s.replace("{n}", &count.to_string());

    widgets.push(separator());
    widgets.push(label(&shown.name).strong());
    widgets.push(
        label(
            n(t("folder.summary"), folder.files.len())
                .replace("{size}", &size_text(folder.total_size(), lang))
                .replace("{what}", folder.algorithm.label()),
        )
        .weak(),
    );
    // What was passed over, said: a folder that "matches" with forty links
    // unfollowed is a different statement from one without them.
    if folder.links > 0 {
        widgets.push(label(format!("! {}", n(t("folder.links"), folder.links))).weak());
    }
    if folder.special > 0 {
        widgets.push(label(format!("! {}", n(t("folder.special"), folder.special))).weak());
    }

    match &shown.verdict {
        Some(FolderVerdict::IsTheFolder) => widgets.push(step(t("folder.is_folder"), "done")),
        Some(FolderVerdict::IsFiles(files)) => {
            widgets.push(step(n(t("folder.is_files"), files.len()), "done"));
            // The first few by name; the rest are in the table below.
            for path in files.iter().take(5) {
                widgets.push(label(format!("      {path}")).weak());
            }
        }
        Some(FolderVerdict::Nothing) => {
            widgets.push(step(t("folder.nothing").replace("{what}", folder.algorithm.label()), "error"));
        }
        Some(FolderVerdict::OtherKind(could_be)) => {
            let names: Vec<&str> = could_be.iter().map(|a| a.label()).collect();
            widgets.push(step(
                t("folder.other_kind")
                    .replace("{given}", &names.join(", "))
                    .replace("{what}", folder.algorithm.label()),
                "warning",
            ));
        }
        Some(FolderVerdict::NotAHash) => widgets.push(step(t("result.not_a_hash"), "warning")),
        None => {}
    }

    let copy = || vec![menu_item(t("result.copy"), CAP, "copy")];
    match folder.hash() {
        Some(hash) => {
            widgets.push(label(t("folder.hash").replace("{what}", folder.algorithm.label())).strong());
            widgets.push(
                table(vec![t("result.algorithm"), t("result.hash")], vec![vec![folder.algorithm.label().to_string(), hash]])
                    .row_ids(vec!["folder".to_string()])
                    .row_menu(copy())
                    .on_activate(CAP, "copy"),
            );
        }
        // No hash for a folder that was not read whole — and it is said why,
        // rather than the line simply not being there.
        None => widgets.push(step(n(t("folder.incomplete"), folder.failed.len()), "warning")),
    }

    if !folder.files.is_empty() {
        widgets.push(row(vec![button(t("folder.copy_list"), CAP, "copy_list")]));
        let listed = folder.files.len().min(MAX_ROWS);
        widgets.push(
            label(if listed < folder.files.len() {
                t("folder.files_first").replace("{shown}", &listed.to_string()).replace("{n}", &folder.files.len().to_string())
            } else {
                n(t("folder.files"), listed)
            })
            .strong(),
        );
        let rows: Vec<Vec<String>> = folder.files[..listed]
            .iter()
            .map(|f| vec![f.path.clone(), short_size(f.size, lang), f.hash.clone()])
            .collect();
        widgets.push(
            table(vec![t("folder.col_file"), t("folder.col_size"), t("result.hash")], rows)
                .row_ids((0..listed).map(|i| format!("f{i}")).collect())
                .row_menu(copy())
                .on_activate(CAP, "copy"),
        );
        widgets.push(label(t("result.copy_hint")).weak());
    }

    if !folder.failed.is_empty() {
        widgets.push(separator());
        widgets.push(label(n(t("folder.failed"), folder.failed.len())).strong());
        widgets.push(table(
            vec![t("folder.col_file"), t("folder.col_why")],
            folder.failed.iter().map(|(path, why)| vec![if path.is_empty() { ".".into() } else { path.clone() }, why.clone()]).collect(),
        ));
    }
}

/// A size as a person would say it, with the exact count beside it: a hash is
/// compared digit for digit, and the size it goes with should be no vaguer.
pub(crate) fn size_text(bytes: u64, lang: &str) -> String {
    let exact = catalog().tr(lang, "result.bytes").replace("{n}", &bytes.to_string());
    let short = short_size(bytes, lang);
    if short == exact { exact } else { format!("{short} ({exact})") }
}

impl HashChecker {
    /// Which hashes a file or a text gets: all of them, or one. All is first
    /// and is what the form opens on — one is for a file large enough that
    /// twenty-six digests of it are a wait for twenty-five nobody asked for.
    fn algorithm_choice(&self, lang: &str) -> limen_sdk_rust::ui::Widget {
        let t = |k: &str| catalog().tr(lang, k);
        let mut options = vec![t("ui.all")];
        options.extend(Algorithm::ALL.iter().map(|a| a.label().to_string()));
        select("only", options).label(t("ui.algorithm")).default(match self.only {
            Some(one) => one.label().to_string(),
            None => t("ui.all"),
        })
    }

    pub(crate) fn view(&self, lang: &str) -> Value {
        let t = |k: &str| catalog().tr(lang, k);
        let mut widgets = vec![
            label(t("ui.title")).heading(),
            label(t("ui.subtitle")).weak(),
            // What to hash, then the one field that goes with the answer:
            // three fields at once ask which of them is meant.
            select("kind", Kind::ALL.iter().map(|k| t(k.key())).collect())
                .label(t("ui.kind"))
                .default(t(self.kind.key()))
                .on_change(CAP, "kind"),
        ];
        match self.kind {
            Kind::File => {
                widgets.push(file("path").label(t("ui.file")).browse(t("ui.browse")).default(self.path.clone()));
                widgets.push(self.algorithm_choice(lang));
            }
            Kind::Folder => {
                widgets.push(
                    file("path")
                        .directory()
                        .label(t("ui.folder"))
                        .browse(t("ui.browse"))
                        .default(self.path.clone()),
                );
                // Only a folder is asked which: a file gets every hash at once.
                widgets.push(
                    select("algorithm", Algorithm::ALL.iter().map(|a| a.label().to_string()).collect())
                        .label(t("ui.algorithm"))
                        .default(self.algorithm.unwrap_or(Algorithm::USUAL).label()),
                );
            }
            Kind::Text => {
                widgets.push(
                    text("text").label(t("ui.text")).placeholder(t("ui.text_hint")).default(self.text.clone()),
                );
                widgets.push(self.algorithm_choice(lang));
            }
        }
        widgets.push(
            text("expected")
                .label(t("ui.expected"))
                .placeholder(t("ui.expected_hint"))
                .default(self.expected.clone()),
        );
        widgets.push(row(vec![
            button(t("ui.calculate"), CAP, "calculate").primary(),
            button(t("ui.clear"), CAP, "clear"),
        ]));

        if let Some(shown) = &self.folder {
            folder_view(&mut widgets, shown, lang);
            return window(t("ui.title"), widgets);
        }

        let Some(shown) = &self.shown else {
            return window(t("ui.title"), widgets);
        };

        widgets.push(separator());
        widgets.push(
            label(if shown.name.is_empty() { t("result.of_text") } else { shown.name.clone() }).strong(),
        );
        widgets.push(label(size_text(shown.digests.size, lang)).weak());

        // The answer to "is this the file I was promised", before the hashes:
        // it is the question the given hash was typed in to ask.
        match &shown.verdict {
            Some(Verdict::Matches(a)) => {
                widgets.push(step(t("result.matches").replace("{what}", a.label()), "done"));
            }
            Some(Verdict::Differs(could_be)) => {
                // Named by what it could have been: "it is not the SHA-256" is
                // only true to say when SHA-256 is the only thing that long.
                let names: Vec<&str> = could_be.iter().map(|a| a.label()).collect();
                widgets.push(step(t("result.differs").replace("{what}", &names.join(", ")), "error"));
            }
            Some(Verdict::NotAHash) => widgets.push(step(t("result.not_a_hash"), "warning")),
            None => {}
        }

        let rows: Vec<Vec<String>> =
            shown.digests.hashes.iter().map(|(a, hash)| vec![a.label().to_string(), hash.clone()]).collect();
        let ids: Vec<String> = shown.digests.hashes.iter().map(|(a, _)| a.key().to_string()).collect();
        widgets.push(
            table(vec![t("result.algorithm"), t("result.hash")], rows)
                .row_ids(ids)
                .row_menu(vec![menu_item(t("result.copy"), CAP, "copy")])
                .on_activate(CAP, "copy"),
        );
        widgets.push(label(t("result.copy_hint")).weak());
        window(t("ui.title"), widgets)
    }
}
