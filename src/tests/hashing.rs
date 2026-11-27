//! The digests: that they are the ones the standards define, however the data
//! arrives.

use super::*;

/// Every digest of "abc" and of nothing at all is the published one. If these
/// are right, the arithmetic is; everything else is plumbing.
#[test]
fn the_hashes_are_the_ones_the_standards_define() {
    let d = digest_bytes(b"abc", &Algorithm::ALL);
    assert_eq!(d.size, 3);
    for (algorithm, hash) in ABC {
        assert_eq!(d.of(algorithm), Some(hash), "{algorithm:?}");
    }

    // Every algorithm has a vector, and every vector is as long as it says.
    assert_eq!(ABC.map(|(a, _)| a), Algorithm::ALL);
    for (algorithm, hash) in ABC {
        assert_eq!(hash.len(), algorithm.hex_len(), "{algorithm:?}");
    }

    let empty = digest_bytes(b"", &Algorithm::ALL);
    assert_eq!(empty.size, 0);
    assert_eq!(empty.of(Algorithm::Crc32), Some("00000000"));
    // Adler-32 of nothing is one, not zero: its running sum starts there.
    assert_eq!(empty.of(Algorithm::Adler32), Some("00000001"));
    assert_eq!(empty.of(Algorithm::Xxh64), Some("ef46db3751d8e999"));
    assert_eq!(empty.of(Algorithm::Xxh3), Some("2d06800538d394c2"));
    assert_eq!(empty.of(Algorithm::Sha224), Some("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"));
    assert_eq!(
        empty.of(Algorithm::Blake3),
        Some("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")
    );
    assert_eq!(empty.of(Algorithm::Md5), Some("d41d8cd98f00b204e9800998ecf8427e"));
    assert_eq!(empty.of(Algorithm::Sha1), Some("da39a3ee5e6b4b0d3255bfef95601890afd80709"));
    assert_eq!(
        empty.of(Algorithm::Sha256),
        Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    );
}

/// "CRC-64" is several different checksums. This is the one `xz` and 7-Zip
/// use, and "123456789" is the input its catalogue entry is checked by.
#[test]
fn crc64_is_the_one_xz_uses() {
    let d = digest_bytes(b"123456789", &[Algorithm::Crc64, Algorithm::Crc32, Algorithm::Adler32]);
    assert_eq!(d.of(Algorithm::Crc64), Some("995dc9bbdf1939fa"));
    assert_eq!(d.of(Algorithm::Crc32), Some("cbf43926"));
    assert_eq!(d.of(Algorithm::Adler32), Some("091e01de"));
}

/// A reader that hands out a few bytes at a time, as a pipe or a slow disk
/// does: the hash must not depend on where the blocks happen to end.
struct Dribble<'a>(&'a [u8], usize);

impl std::io::Read for Dribble<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.1.min(self.0.len()).min(buf.len());
        buf[..n].copy_from_slice(&self.0[..n]);
        self.0 = &self.0[n..];
        Ok(n)
    }
}

#[test]
fn a_hash_does_not_depend_on_how_the_data_arrives() {
    // Longer than the block a file is read in, so the whole-file path crosses
    // a block boundary too.
    let data: Vec<u8> = (0..2_500_000u32).map(|i| (i % 251) as u8).collect();
    let whole = digest_bytes(&data, &Algorithm::ALL);
    assert_eq!(whole.size, data.len() as u64);
    for step in [4096, 1_048_577] {
        let dribbled = digest_reader(Dribble(&data, step), &Algorithm::ALL).unwrap();
        assert_eq!(dribbled, whole, "read {step} bytes at a time");
    }
    // A byte at a time, and seven: on less data, because that is slow.
    let short = &data[..10_000];
    for step in [1, 7] {
        let dribbled = digest_reader(Dribble(short, step), &Algorithm::ALL).unwrap();
        assert_eq!(dribbled, digest_bytes(short, &Algorithm::ALL), "read {step} bytes at a time");
    }
}

/// One million "a" — the long vector of the SHA standard, which a mistake in
/// how blocks are chained fails and a three-byte test does not.
#[test]
fn a_million_bytes_hash_to_the_published_value() {
    let data = vec![b'a'; 1_000_000];
    let d = digest_bytes(&data, &Algorithm::ALL);
    assert_eq!(d.of(Algorithm::Sha256), Some("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
    assert_eq!(d.of(Algorithm::Sha1), Some("34aa973cd4c4daa4f61eeb2bdbad27316534016f"));
    assert_eq!(d.of(Algorithm::Crc32), Some("dc25bfbc"));
    assert_eq!(
        d.of(Algorithm::Sha3_256),
        Some("5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1")
    );
    assert_eq!(
        d.of(Algorithm::Blake2b),
        Some(
            "98fb3efb7206fd19ebf69b6f312cf7b64e3b94dbe1a17107913975a793f177e1\
             d077609d7fba363cbba00d05f7aa4e4fa8715d6428104c0a75643b0ff3fd3eaf"
        )
    );
}

/// Only what was asked for is calculated, once each, in the listed order —
/// whatever order and however often it was asked for.
#[test]
fn only_the_algorithms_asked_for_are_run() {
    let d = digest_bytes(b"abc", &[Algorithm::Sha512, Algorithm::Md5, Algorithm::Md5]);
    assert_eq!(d.hashes.len(), 2);
    let which: Vec<Algorithm> = d.hashes.iter().map(|(a, _)| *a).collect();
    assert_eq!(which, [Algorithm::Md5, Algorithm::Sha512]);
    assert_eq!(d.of(Algorithm::Sha256), None);
}

#[test]
fn a_file_hashes_to_what_its_bytes_do() {
    let file = Scratch::with("file", b"abc");
    let d = digest_file(&file.path(), &Algorithm::ALL).unwrap();
    assert_eq!(d, digest_bytes(b"abc", &Algorithm::ALL));
}

/// What cannot be hashed says why, and which path it was about: "no such
/// file" and "is a directory" are different things to do next.
#[test]
fn what_cannot_be_read_says_why() {
    let missing = std::env::temp_dir().join("limen-hash-no-such-file-here").to_string_lossy().into_owned();
    let e = digest_file(&missing, &Algorithm::ALL).unwrap_err();
    assert!(e.starts_with(&missing), "{e}");

    let dir = std::env::temp_dir().to_string_lossy().into_owned();
    let e = digest_file(&dir, &Algorithm::ALL).unwrap_err();
    assert!(e.starts_with(&dir), "{e}");
}

/// An algorithm is known by any of the ways its name is written.
#[test]
fn an_algorithm_is_known_however_its_name_is_written() {
    for name in ["sha256", "SHA256", "SHA-256", "sha_256", " Sha-256 "] {
        assert_eq!(Algorithm::parse(name), Some(Algorithm::Sha256), "{name}");
    }
    assert_eq!(Algorithm::parse("SHA-1"), Some(Algorithm::Sha1));
    assert_eq!(Algorithm::parse("md5"), Some(Algorithm::Md5));
    // SHA-3 is not SHA-2 with a digit moved: the names differ by one
    // character, and the hashes by all of them.
    for name in ["sha3-256", "SHA3_256", "sha3256"] {
        assert_eq!(Algorithm::parse(name), Some(Algorithm::Sha3_256), "{name}");
    }
    assert_eq!(Algorithm::parse("SHA3-512"), Some(Algorithm::Sha3_512));
    assert_eq!(Algorithm::parse("BLAKE2b-512"), Some(Algorithm::Blake2b));
    assert_eq!(Algorithm::parse("b3"), None);
    assert_eq!(Algorithm::parse("SHA-512/256"), Some(Algorithm::Sha512_256));
    assert_eq!(Algorithm::parse("sha512"), Some(Algorithm::Sha512));
    assert_eq!(Algorithm::parse("RIPEMD-160"), Some(Algorithm::Ripemd160));
    assert_eq!(Algorithm::parse("rmd160"), Some(Algorithm::Ripemd160));
    assert_eq!(Algorithm::parse("BLAKE2s-256"), Some(Algorithm::Blake2s));
    assert_eq!(Algorithm::parse("XXH3_64"), Some(Algorithm::Xxh3));
    assert_eq!(Algorithm::parse("xxhash64"), Some(Algorithm::Xxh64));
    assert_eq!(Algorithm::parse("CRC-64/XZ"), Some(Algorithm::Crc64));
    assert_eq!(Algorithm::parse("adler-32"), Some(Algorithm::Adler32));
    assert_eq!(Algorithm::parse("BLAKE3"), Some(Algorithm::Blake3));
    assert_eq!(Algorithm::parse("CRC-32"), Some(Algorithm::Crc32));
    // Every algorithm answers to its own key and to its own label.
    for a in Algorithm::ALL {
        assert_eq!(Algorithm::parse(a.key()), Some(a));
        assert_eq!(Algorithm::parse(a.label()), Some(a));
    }
    assert_eq!(Algorithm::parse("SHA-512/224"), Some(Algorithm::Sha512_224));
    // SHA-2 is the family; its members are also written with it in front.
    assert_eq!(Algorithm::parse("SHA2-256"), Some(Algorithm::Sha256));
    assert_eq!(Algorithm::parse("sha2_512"), Some(Algorithm::Sha512));
    assert_eq!(Algorithm::parse("SHA2-512/256"), Some(Algorithm::Sha512_256));
    for name in ["", "sha3", "sha2", "sha-2", "sha2566", "sha-3", "tiger"] {
        assert_eq!(Algorithm::parse(name), None, "{name}");
    }
}

/// A hash arrives in more shapes than one, and every one of them is the same
/// hash — none should read as "does not match".
#[test]
fn a_given_hash_is_read_in_whatever_shape_it_came() {
    let sha256 = abc(Algorithm::Sha256);
    for given in [
        sha256.to_string(),
        sha256.to_uppercase(),
        format!("  {sha256}\n"),
        // A line of a checksum file: the hash, then the file's name.
        format!("{sha256}  setup.exe"),
        format!("{sha256} *setup.exe"),
    ] {
        let (could_be, hash) = expected_hash(&given).unwrap_or_else(|| panic!("{given:?}"));
        assert_eq!(hash, sha256, "{given:?}");
        // With no name on it, a 64-digit hash is any of the five that long.
        assert_eq!(
            could_be,
            [Algorithm::Sha256, Algorithm::Sha512_256, Algorithm::Sha3_256, Algorithm::Blake2s, Algorithm::Blake3],
            "{given:?}"
        );
    }
    // With its name in front it is that algorithm's and no other's.
    for given in [
        format!("sha256:{sha256}"),
        format!("SHA256={}", sha256.to_uppercase()),
        format!("SHA-256:{sha256}"),
    ] {
        assert_eq!(expected_hash(&given), Some((vec![Algorithm::Sha256], sha256.to_string())), "{given:?}");
    }
    assert_eq!(
        expected_hash(&format!("sha3-256:{}", abc(Algorithm::Sha3_256))).map(|(a, _)| a),
        Some(vec![Algorithm::Sha3_256])
    );

    // MD5 is the only one of its length, and is said outright.
    assert_eq!(expected_hash(abc(Algorithm::Md5)).map(|(a, _)| a), Some(vec![Algorithm::Md5]));
    // Every other length is shared, and every algorithm is among those its
    // own hash could be.
    for algorithm in Algorithm::ALL {
        let (could_be, _) = expected_hash(abc(algorithm)).unwrap();
        assert!(could_be.contains(&algorithm), "{algorithm:?}: {could_be:?}");
        assert!(could_be.iter().all(|a| a.hex_len() == algorithm.hex_len()));
    }
    assert_eq!(
        expected_hash(abc(Algorithm::Sha1)).map(|(a, _)| a),
        Some(vec![Algorithm::Sha1, Algorithm::Ripemd160])
    );
}

/// A hash with no name on it is held against every algorithm that long, and is
/// whichever one it turns out to be.
#[test]
fn an_unnamed_hash_matches_whichever_algorithm_it_is() {
    let d = digest_bytes(b"abc", &Algorithm::ALL);
    for algorithm in Algorithm::ALL {
        let (could_be, hash) = expected_hash(abc(algorithm)).unwrap();
        assert_eq!(which_matches(&d, &could_be, &hash), Some(algorithm), "{algorithm:?}");
    }
    // The right length and nobody's hash.
    let (could_be, hash) = expected_hash(&"0".repeat(64)).unwrap();
    assert_eq!(which_matches(&d, &could_be, &hash), None);
    // Named as one algorithm, it is not accepted as another's of the same
    // length: a BLAKE3 offered as "sha256:" is a wrong SHA-256.
    let (could_be, hash) = expected_hash(&format!("sha256:{}", abc(Algorithm::Blake3))).unwrap();
    assert_eq!(which_matches(&d, &could_be, &hash), None);
}

/// What is not a hash is not guessed at.
#[test]
fn what_is_not_a_hash_is_not_read_as_one() {
    for given in [
        "",
        "   ",
        "hello",
        // The right length, and not hex.
        "z00150983cd24fb0d6963f7d28e17f72",
        // Hex, and a length no algorithm here has.
        "900150983cd24fb0d6963f7d28e17f7",
        "900150983cd24fb0d6963f7d28e17f7200",
        // A name in front of something that is not a hash.
        "sha256:nothing",
        "sha256:",
        // A name in front of a hash of another length.
        "sha256:900150983cd24fb0d6963f7d28e17f72",
    ] {
        assert_eq!(expected_hash(given), None, "{given:?}");
    }
}

/// For a look at a real file: `HASH_FILE=/path cargo test show_a_file -- --ignored --nocapture`.
#[test]
#[ignore = "prints the hashes of the file named in HASH_FILE"]
fn show_a_file() {
    let path = std::env::var("HASH_FILE").expect("HASH_FILE names the file");
    let d = digest_file(&path, &Algorithm::ALL).unwrap();
    println!("size {}", d.size);
    for (algorithm, hash) in &d.hashes {
        println!("{} {hash}", algorithm.key());
    }
}

