//! What other modules ask for: hashes as data, with no screen involved.
//!
//! ```text
//!   algorithms                              -> which digests there are
//!   hash_file   {path, algorithms?}         -> a file on this machine
//!   hash_dir    {path, algorithm?}          -> a folder: its files, and itself
//!   hash_text   {text, algorithms?}         -> text, as its UTF-8 bytes
//!   hash_base64 {data, algorithms?}         -> bytes the caller already holds
//!   verify      {expected, path|text|data}  -> whether a hash is the right one
//! ```
//!
//! Every answer has the same shape — `{"size": bytes, "hashes": {"sha256": …}}`
//! — so a caller that learned one has learned them all. `algorithms` narrows
//! what is calculated (`["sha256"]`); left out, all of them are.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use crate::*;

fn invalid(message: impl Into<String>) -> RpcError {
    RpcError::new(rpc::INVALID_PARAMS, message)
}

/// The digests a caller asked for: all of them if it named none, and an error —
/// not a silent "all of them" — if it named one that does not exist.
fn wanted(params: &Value) -> Result<Vec<Algorithm>, RpcError> {
    let Some(asked) = params.get("algorithms") else {
        return Ok(Algorithm::ALL.to_vec());
    };
    let names = asked.as_array().ok_or_else(|| invalid("`algorithms` is a list of names, like [\"sha256\"]"))?;
    let mut out = Vec::new();
    for name in names {
        let name = name.as_str().unwrap_or("");
        out.push(Algorithm::parse(name).ok_or_else(|| {
            invalid(format!("no algorithm \"{name}\": there are {}", names_of_all()))
        })?);
    }
    if out.is_empty() {
        return Ok(Algorithm::ALL.to_vec());
    }
    Ok(out)
}

fn str_of<'a>(params: &'a Value, key: &str) -> Option<&'a str> {
    params.get(key).and_then(Value::as_str)
}

/// Every algorithm's name, for an error that has to list them.
fn names_of_all() -> String {
    Algorithm::ALL.iter().map(|a| a.key()).collect::<Vec<_>>().join(", ")
}

/// A set of digests as the answer every method gives.
pub(crate) fn answer(d: &Digests) -> Value {
    let mut hashes = json!({});
    for (algorithm, hash) in &d.hashes {
        hashes[algorithm.key()] = json!(hash);
    }
    json!({ "size": d.size, "hashes": hashes })
}

pub(crate) fn algorithms() -> Value {
    json!({
        "algorithms": Algorithm::ALL.iter().map(|a| json!({
            "name": a.key(),
            "label": a.label(),
            "hex_digits": a.hex_len(),
        })).collect::<Vec<_>>(),
    })
}

pub(crate) fn hash_file(params: &Value) -> Result<Value, RpcError> {
    let path = str_of(params, "path").filter(|p| !p.is_empty()).ok_or_else(|| invalid("`path` is the file to hash"))?;
    let digests = digest_file(path, &wanted(params)?).map_err(|e| RpcError::new(rpc::MODULE_ERROR, e))?;
    let mut out = answer(&digests);
    out["path"] = json!(path);
    Ok(out)
}

/// A folder: each file's hash, and the folder's own.
///
/// One algorithm — `algorithm`, SHA-256 if none is named — because it is run
/// over every file. `hash` is the folder's own (see `folder` for how it is
/// made), and is `null` when anything could not be read: `failed` says what.
pub(crate) fn hash_dir(params: &Value) -> Result<Value, RpcError> {
    let path = str_of(params, "path").filter(|p| !p.is_empty()).ok_or_else(|| invalid("`path` is the folder to hash"))?;
    let algorithm = match str_of(params, "algorithm") {
        None => Algorithm::USUAL,
        Some(name) => Algorithm::parse(name)
            .ok_or_else(|| invalid(format!("no algorithm \"{name}\": there are {}", names_of_all())))?,
    };
    let folder = digest_folder(path, algorithm).map_err(|e| RpcError::new(rpc::MODULE_ERROR, e))?;
    Ok(json!({
        "path": path,
        "algorithm": algorithm.key(),
        "hash": folder.hash(),
        "count": folder.files.len(),
        "size": folder.total_size(),
        "files": folder.files.iter().map(|f| json!({ "path": f.path, "size": f.size, "hash": f.hash })).collect::<Vec<_>>(),
        "failed": folder.failed.iter().map(|(path, why)| json!({ "path": path, "error": why })).collect::<Vec<_>>(),
        "links_skipped": folder.links,
        "special_skipped": folder.special,
    }))
}

pub(crate) fn hash_text(params: &Value) -> Result<Value, RpcError> {
    let text = str_of(params, "text").ok_or_else(|| invalid("`text` is the text to hash"))?;
    Ok(answer(&digest_bytes(text.as_bytes(), &wanted(params)?)))
}

pub(crate) fn hash_base64(params: &Value) -> Result<Value, RpcError> {
    Ok(answer(&digest_bytes(&decoded(params)?, &wanted(params)?)))
}

fn decoded(params: &Value) -> Result<Vec<u8>, RpcError> {
    let data = str_of(params, "data").ok_or_else(|| invalid("`data` is the bytes to hash, in base64"))?;
    STANDARD.decode(data.trim()).map_err(|e| invalid(format!("`data` is not base64: {e}")))
}

/// Whether `expected` is the hash of what was given: a `path`, some `text`, or
/// base64 `data` — the first of those that is there.
///
/// The algorithm is read off the hash itself — its name if it has one in front
/// (`sha256:…`), its length otherwise — so the caller need not know which one
/// it was handed. Several algorithms share a length; the hash is held against
/// each, and `algorithm` says which it turned out to be.
///
/// `match` is the answer. `actual` carries what it was compared with, by
/// algorithm, so a "no" can be shown rather than only reported.
pub(crate) fn verify(params: &Value) -> Result<Value, RpcError> {
    let given = str_of(params, "expected").unwrap_or("");
    let (could_be, expected) = expected_hash(given).ok_or_else(|| {
        invalid(
            "`expected` is not a hash this module knows: in hex, they are 8, 16, 32, 40, 56, 64, 96 or 128 digits",
        )
    })?;
    let digests = if let Some(path) = str_of(params, "path").filter(|p| !p.is_empty()) {
        digest_file(path, &could_be).map_err(|e| RpcError::new(rpc::MODULE_ERROR, e))?
    } else if let Some(text) = str_of(params, "text") {
        digest_bytes(text.as_bytes(), &could_be)
    } else if params.get("data").is_some() {
        digest_bytes(&decoded(params)?, &could_be)
    } else {
        return Err(invalid("give what to check: a `path`, some `text`, or base64 `data`"));
    };
    let matched = which_matches(&digests, &could_be, &expected);
    Ok(json!({
        "match": matched.is_some(),
        "algorithm": matched.map(Algorithm::key),
        "expected": expected,
        "actual": answer(&digests)["hashes"],
        "size": digests.size,
    }))
}
