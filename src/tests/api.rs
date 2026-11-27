//! What other modules get: the same hashes, as data.

use super::*;
use crate::api;

fn sha256_of_abc() -> &'static str {
    abc(Algorithm::Sha256)
}

/// One shape for every answer: the size, and the hashes by name.
#[test]
fn every_method_answers_in_the_same_shape() {
    let file = Scratch::with("api-file", b"abc");
    let from_file = api::hash_file(&json!({ "path": file.path() })).unwrap();
    let from_text = api::hash_text(&json!({ "text": "abc" })).unwrap();
    let from_data = api::hash_base64(&json!({ "data": "YWJj" })).unwrap();

    for answer in [&from_file, &from_text, &from_data] {
        assert_eq!(answer["size"], 3, "{answer}");
        for (algorithm, hash) in ABC {
            assert_eq!(answer["hashes"][algorithm.key()], hash, "{answer}");
        }
        assert_eq!(answer["hashes"].as_object().unwrap().len(), Algorithm::ALL.len());
    }
    // A file's answer says which file it was.
    assert_eq!(from_file["path"], file.path());
}

/// A caller that wants one digest of a large file should not wait for four.
#[test]
fn a_caller_gets_only_the_algorithms_it_named() {
    let answer = api::hash_text(&json!({ "text": "abc", "algorithms": ["SHA-256"] })).unwrap();
    assert_eq!(answer["hashes"], json!({ "sha256": sha256_of_abc() }));

    let two = api::hash_text(&json!({ "text": "abc", "algorithms": ["sha512", "md5"] })).unwrap();
    assert_eq!(two["hashes"].as_object().unwrap().len(), 2);
    assert_eq!(two["hashes"]["md5"], abc(Algorithm::Md5));

    let newer = api::hash_text(&json!({ "text": "abc", "algorithms": ["SHA3-256", "blake3", "CRC-32"] })).unwrap();
    assert_eq!(newer["hashes"], json!({
        "crc32": abc(Algorithm::Crc32),
        "sha3_256": abc(Algorithm::Sha3_256),
        "blake3": abc(Algorithm::Blake3),
    }));
}

/// A name that is not an algorithm is an error, not a quiet "all of them":
/// the caller asked for something and should learn it does not exist.
#[test]
fn an_unknown_algorithm_is_refused_by_name() {
    let e = api::hash_text(&json!({ "text": "abc", "algorithms": ["tiger"] })).unwrap_err();
    assert_eq!(e.code, rpc::INVALID_PARAMS);
    assert!(e.message.contains("tiger") && e.message.contains("sha3_256"), "{}", e.message);

    let e = api::hash_text(&json!({ "text": "abc", "algorithms": "sha256" })).unwrap_err();
    assert_eq!(e.code, rpc::INVALID_PARAMS);
}

/// The empty text has hashes of its own, and asking for them is not asking
/// for nothing.
#[test]
fn empty_text_is_still_text() {
    let answer = api::hash_text(&json!({ "text": "" })).unwrap();
    assert_eq!(answer["size"], 0);
    assert_eq!(answer["hashes"]["md5"], "d41d8cd98f00b204e9800998ecf8427e");
}

#[test]
fn what_is_missing_or_malformed_is_said() {
    for (params, word) in [
        (json!({}), "path"),
        (json!({ "path": "" }), "path"),
    ] {
        let e = api::hash_file(&params).unwrap_err();
        assert_eq!(e.code, rpc::INVALID_PARAMS, "{params}");
        assert!(e.message.contains(word), "{}", e.message);
    }
    assert_eq!(api::hash_text(&json!({})).unwrap_err().code, rpc::INVALID_PARAMS);
    assert_eq!(api::hash_base64(&json!({})).unwrap_err().code, rpc::INVALID_PARAMS);
    let e = api::hash_base64(&json!({ "data": "not base64 !!" })).unwrap_err();
    assert_eq!(e.code, rpc::INVALID_PARAMS);

    // A file that is not there is the module failing at what was asked, not
    // the caller asking wrongly — and the message names the file.
    let e = api::hash_file(&json!({ "path": "/no/such/limen-hash-file" })).unwrap_err();
    assert_eq!(e.code, rpc::MODULE_ERROR);
    assert!(e.message.contains("/no/such/limen-hash-file"), "{}", e.message);
}

/// `verify` reads the algorithm off the hash, and says what it compared with.
#[test]
fn verify_says_yes_no_and_against_what() {
    let file = Scratch::with("api-verify", b"abc");
    for params in [
        json!({ "expected": sha256_of_abc(), "path": file.path() }),
        json!({ "expected": sha256_of_abc().to_uppercase(), "text": "abc" }),
        json!({ "expected": format!("sha256:{}", sha256_of_abc()), "data": "YWJj" }),
    ] {
        let v = api::verify(&params).unwrap();
        assert_eq!(v["match"], true, "{params}");
        assert_eq!(v["algorithm"], "sha256");
        assert_eq!(v["actual"]["sha256"], sha256_of_abc());
        assert_eq!(v["size"], 3);
    }

    // Whichever algorithm it is: the hash of "abc" by each is accepted, and
    // said to be that one.
    for algorithm in Algorithm::ALL {
        let v = api::verify(&json!({ "expected": abc(algorithm), "text": "abc" })).unwrap();
        assert_eq!(v["match"], true, "{algorithm:?}");
        assert_eq!(v["algorithm"], algorithm.key(), "{algorithm:?}");
    }

    // A hash of the right length that is nobody's: a no, with every hash it
    // could have been.
    let v = api::verify(&json!({ "expected": "0".repeat(64), "text": "abc" })).unwrap();
    assert_eq!(v["match"], false);
    assert_eq!(v["algorithm"], Value::Null);
    assert_eq!(v["expected"], "0".repeat(64));
    assert_eq!(v["actual"]["sha256"], sha256_of_abc());
    assert_eq!(v["actual"].as_object().unwrap().len(), 5, "five algorithms are that long");

    // Named, it is held against that one alone.
    let v = api::verify(&json!({ "expected": format!("sha256:{}", abc(Algorithm::Blake3)), "text": "abc" })).unwrap();
    assert_eq!(v["match"], false);
    assert_eq!(v["actual"].as_object().unwrap().len(), 1);
}

#[test]
fn verify_refuses_what_it_cannot_judge() {
    // Not a hash.
    let e = api::verify(&json!({ "expected": "hello", "text": "abc" })).unwrap_err();
    assert_eq!(e.code, rpc::INVALID_PARAMS);
    // A hash, and nothing to check it against.
    let e = api::verify(&json!({ "expected": sha256_of_abc() })).unwrap_err();
    assert_eq!(e.code, rpc::INVALID_PARAMS);
    assert!(e.message.contains("path"), "{}", e.message);
}

#[test]
fn the_module_says_which_algorithms_it_has() {
    let listed = api::algorithms();
    let names: Vec<&str> =
        listed["algorithms"].as_array().unwrap().iter().map(|a| a["name"].as_str().unwrap()).collect();
    assert_eq!(names, Algorithm::ALL.map(Algorithm::key));
    assert_eq!(names.len(), 22);
    let sha3 = listed["algorithms"].as_array().unwrap().iter().find(|a| a["name"] == "sha3_256").unwrap();
    assert_eq!((sha3["label"].as_str(), sha3["hex_digits"].as_u64()), (Some("SHA3-256"), Some(64)));
}
