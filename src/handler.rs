//! The module itself: what it remembers between calls, and which method goes
//! where.

use crate::*;

pub(crate) const CAP: &str = "hash.calc";

/// What was hashed last, for the screen to show and for Copy to copy from.
#[derive(Clone, Debug)]
pub(crate) struct Shown {
    /// The file's name, or nothing when it was text.
    pub name: String,
    pub digests: Digests,
    /// How the hash that was given compared — `None` when none was given.
    pub verdict: Option<Verdict>,
}

/// A hash that was given, held against what was calculated.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Verdict {
    /// It is the hash of this, by this algorithm.
    Matches(Algorithm),
    /// It is a hash, of one of these kinds by its length, and not this one's.
    Differs(Vec<Algorithm>),
    /// It is not a hash at all: wrong length, or not hex.
    NotAHash,
}

/// A folder that was hashed last, and what the given hash turned out to be.
#[derive(Clone, Debug)]
pub(crate) struct ShownFolder {
    pub name: String,
    pub folder: Folder,
    pub verdict: Option<FolderVerdict>,
}

/// A hash that was given, held against a folder.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum FolderVerdict {
    /// It is the hash of the folder as a whole.
    IsTheFolder,
    /// It is the hash of these files in it — the answer to "is that file in
    /// here", which is as often the question as "is this folder intact".
    IsFiles(Vec<String>),
    /// It is a hash of the kind the folder was hashed with, and nothing's here.
    Nothing,
    /// It is a hash of another kind than the folder was hashed with — by its
    /// length it could be one of these. Not a mismatch: the wrong question.
    OtherKind(Vec<Algorithm>),
    /// It is not a hash at all.
    NotAHash,
}

/// What is to be hashed — the choice the form opens with, and the one field
/// it then shows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Kind {
    #[default]
    File,
    Folder,
    Text,
}

impl Kind {
    pub(crate) const ALL: [Kind; 3] = [Kind::File, Kind::Folder, Kind::Text];

    /// The catalogue key of its name.
    pub(crate) fn key(self) -> &'static str {
        match self {
            Kind::File => "kind.file",
            Kind::Folder => "kind.folder",
            Kind::Text => "kind.text",
        }
    }

    /// The kind a dropdown's answer names. An option is its own value, so a
    /// person reading Ukrainian sends Ukrainian back — and another module may
    /// say `file` in neither.
    pub(crate) fn parse(answer: &str) -> Option<Kind> {
        let answer = answer.trim();
        Kind::ALL.into_iter().find(|k| {
            k.key().trim_start_matches("kind.").eq_ignore_ascii_case(answer)
                || ["en", "uk"].iter().any(|lang| catalog().tr(lang, k.key()) == answer)
        })
    }
}

#[derive(Default)]
pub(crate) struct HashChecker {
    /// Which of the three the form is asking for.
    pub(crate) kind: Kind,
    /// What is in the form, so a redraw does not empty it.
    pub(crate) path: String,
    pub(crate) text: String,
    pub(crate) expected: String,
    /// The algorithm a folder is hashed with; `None` is the usual one.
    pub(crate) algorithm: Option<Algorithm>,
    /// A file or a text, hashed — or a folder. Never both.
    pub(crate) shown: Option<Shown>,
    pub(crate) folder: Option<ShownFolder>,
}

impl HashChecker {
    /// Take in whatever of the form a call carried. A field that did not come
    /// with it is left as it was: a dropdown that changed reports itself, not
    /// necessarily the fields beside it.
    fn read_form(&mut self, params: &Value) {
        let field = |k: &str| params.get(k).and_then(Value::as_str);
        if let Some(kind) = field("kind").and_then(Kind::parse) {
            self.kind = kind;
        }
        if let Some(path) = field("path") {
            self.path = path.trim().to_string();
        }
        if let Some(text) = field("text") {
            self.text = text.to_string();
        }
        if let Some(expected) = field("expected") {
            self.expected = expected.trim().to_string();
        }
        // The dropdown sends back the label it showed.
        if let Some(algorithm) = field("algorithm").and_then(Algorithm::parse) {
            self.algorithm = Some(algorithm);
        }
    }

    /// The kind was changed: show the field that goes with it. What was
    /// calculated belonged to the other kind and goes; what was typed stays,
    /// so changing one's mind and back costs nothing.
    pub(crate) fn choose_kind(&mut self, params: &Value, lang: &str) -> Value {
        self.read_form(params);
        self.shown = None;
        self.folder = None;
        self.view(lang)
    }

    /// Hash what the form holds, by the kind it is set to.
    pub(crate) fn calculate(&mut self, params: &Value, lang: &str) -> Value {
        let t = |k: &str| catalog().tr(lang, k);
        self.read_form(params);
        self.shown = None;
        self.folder = None;

        if self.kind != Kind::Text {
            if self.path.is_empty() {
                return notice(self.view(lang), "warning", t("ui.nothing"));
            }
            // A folder dropped where a file was asked for, or the other way
            // round, is hashed as what it is — and the form follows, rather
            // than answering "that is a folder" to somebody who can see that.
            let is_dir = std::path::Path::new(&self.path).is_dir();
            if is_dir || (self.kind == Kind::Folder && std::path::Path::new(&self.path).is_file()) {
                self.kind = if is_dir { Kind::Folder } else { Kind::File };
            }
            if self.kind == Kind::Folder {
                return self.calculate_folder(lang);
            }
        }

        let (name, digests) = if self.kind == Kind::File {
            match digest_file(&self.path, &Algorithm::ALL) {
                Ok(d) => (file_name(&self.path), d),
                Err(e) => return notice(self.view(lang), "error", e),
            }
        } else if !self.text.is_empty() {
            (String::new(), digest_bytes(self.text.as_bytes(), &Algorithm::ALL))
        } else {
            return notice(self.view(lang), "warning", t("ui.nothing"));
        };

        let verdict = (!self.expected.is_empty()).then(|| match expected_hash(&self.expected) {
            Some((could_be, hash)) => match which_matches(&digests, &could_be, &hash) {
                Some(algorithm) => Verdict::Matches(algorithm),
                None => Verdict::Differs(could_be),
            },
            None => Verdict::NotAHash,
        });
        self.shown = Some(Shown { name, digests, verdict });
        self.view(lang)
    }

    /// Hash the folder the form names: every file in it, with the one
    /// algorithm chosen — twenty-six digests of every file of a folder is
    /// twenty times the wait for hashes nobody will read.
    fn calculate_folder(&mut self, lang: &str) -> Value {
        let algorithm = self.algorithm.unwrap_or(Algorithm::USUAL);
        let folder = match digest_folder(&self.path, algorithm) {
            Ok(folder) => folder,
            Err(e) => return notice(self.view(lang), "error", e),
        };
        let verdict = (!self.expected.is_empty()).then(|| match expected_hash(&self.expected) {
            None => FolderVerdict::NotAHash,
            Some((could_be, _)) if !could_be.contains(&algorithm) => FolderVerdict::OtherKind(could_be),
            Some((_, hash)) if folder.hash().as_deref() == Some(hash.as_str()) => FolderVerdict::IsTheFolder,
            Some((_, hash)) => {
                let files: Vec<String> =
                    folder.files.iter().filter(|f| f.hash == hash).map(|f| f.path.clone()).collect();
                if files.is_empty() { FolderVerdict::Nothing } else { FolderVerdict::IsFiles(files) }
            }
        });
        self.folder = Some(ShownFolder { name: file_name(&self.path), folder, verdict });
        self.view(lang)
    }

    /// A folder's checksum list — the lines `sha256sum -c` reads — onto the
    /// clipboard.
    pub(crate) fn copy_list(&self, lang: &str) -> Value {
        let t = |k: &str| catalog().tr(lang, k);
        match &self.folder {
            Some(shown) if clipboard::copy_to_clipboard(&shown.folder.listing()) => notice(
                self.view(lang),
                "ok",
                t("notice.list_copied").replace("{n}", &shown.folder.files.len().to_string()),
            ),
            Some(_) => notice(self.view(lang), "error", t("notice.no_clipboard")),
            None => notice(self.view(lang), "error", t("notice.gone")),
        }
    }

    /// Start over: an empty form and nothing shown.
    pub(crate) fn clear(&mut self, lang: &str) -> Value {
        *self = HashChecker::default();
        self.view(lang)
    }

    /// Put one hash on the clipboard. `params`: `{ id }` — the row that was
    /// clicked: an algorithm's name for a file or a text; for a folder,
    /// `folder` for its own hash or `f<n>` for the n-th file's.
    pub(crate) fn copy(&self, params: &Value, lang: &str) -> Value {
        let t = |k: &str| catalog().tr(lang, k);
        let id = params.get("id").and_then(Value::as_str).unwrap_or("");
        // What to copy, and what to call it in the notice.
        let found: Option<(String, String)> = if let Some(shown) = &self.folder {
            if id == "folder" {
                shown.folder.hash().map(|h| (shown.folder.algorithm.label().to_string(), h))
            } else {
                id.strip_prefix('f')
                    .and_then(|n| n.parse::<usize>().ok())
                    .and_then(|n| shown.folder.files.get(n))
                    .map(|f| (shown.folder.algorithm.label().to_string(), f.hash.clone()))
            }
        } else {
            Algorithm::parse(id)
                .and_then(|a| Some((a.label().to_string(), self.shown.as_ref()?.digests.of(a)?.to_string())))
        };
        match found {
            Some((what, hash)) if clipboard::copy_to_clipboard(&hash) => {
                notice(self.view(lang), "ok", t("notice.copied").replace("{what}", &what))
            }
            Some(_) => notice(self.view(lang), "error", t("notice.no_clipboard")),
            None => notice(self.view(lang), "error", t("notice.gone")),
        }
    }
}

/// The last component of a path, whichever way its separators lean — a path
/// typed on Windows is still a Windows path when the module runs elsewhere in
/// a test.
pub(crate) fn file_name(path: &str) -> String {
    path.rsplit(['/', '\\']).find(|part| !part.is_empty()).unwrap_or(path).to_string()
}

impl Handler for HashChecker {
    fn capabilities(&self) -> Vec<String> {
        vec![CAP.into()]
    }

    fn invoke(&mut self, _cap: &str, method: &str, params: Value, host: &Host) -> Result<Value, RpcError> {
        match method {
            // The screen.
            "ui" => Ok(self.view(&host.locale())),
            "calculate" => Ok(self.calculate(&params, &host.locale())),
            "kind" => Ok(self.choose_kind(&params, &host.locale())),
            "clear" => Ok(self.clear(&host.locale())),
            "copy" => Ok(self.copy(&params, &host.locale())),
            "copy_list" => Ok(self.copy_list(&host.locale())),
            // For other modules: data, no screen. See `api`.
            "algorithms" => Ok(api::algorithms()),
            "hash_file" => api::hash_file(&params),
            "hash_dir" => api::hash_dir(&params),
            "hash_text" => api::hash_text(&params),
            "hash_base64" => api::hash_base64(&params),
            "verify" => api::verify(&params),
            other => Err(RpcError::new(rpc::METHOD_NOT_FOUND, format!("hash-checker has no method {other}"))),
        }
    }
}
