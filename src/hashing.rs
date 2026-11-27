//! The digests themselves: which there are, how a stream is run through them,
//! and how a hash somebody was given is read and compared.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use blake2::{Blake2b512, Blake2s256};
use md5::Md5;
use ripemd::Ripemd160;
use sha1::Sha1;
use sha2::digest::DynDigest;
use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use whirlpool::Whirlpool;

/// How much of a file is held at once. A file is never read whole: an image of
/// a disk is hashed in the same memory as a text file.
const CHUNK: usize = 1024 * 1024;

/// CRC-64 as `xz` and 7-Zip compute it — the one a tool means when it says
/// "CRC-64" and no more. There are others; this is named so it is not a guess.
static CRC64: crc::Crc<u64> = crc::Crc::<u64>::new(&crc::CRC_64_XZ);

/// The digests this module calculates.
///
/// They are not interchangeable, and the list says which is which:
///
/// - **Adler-32, CRC-32, CRC-64, XXH64, XXH3** are checksums, not hashes: they
///   catch a damaged download or a bad copy, and stop nobody who means to
///   deceive.
/// - **MD5** and **SHA-1** are here because that is what the other side still
///   publishes and what older tooling keys on — to compare with, not to trust:
///   both can be made to collide on purpose.
/// - **RIPEMD-160** and **Whirlpool** are sound and rare; here for the tool
///   that prints them.
/// - **SHA-2** (224, 256, 384, 512, 512/224, 512/256), **SHA-3**, **BLAKE2** and
///   **BLAKE3** are the ones to rely on. SHA-256 is the one most often asked
///   for.
#[allow(non_camel_case_types)] // `Sha512_256` and `Sha3_256` are their names
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Algorithm {
    Adler32,
    Crc32,
    Crc64,
    Xxh64,
    Xxh3,
    Md5,
    Sha1,
    Ripemd160,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha512_224,
    Sha512_256,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Blake2s,
    Blake2b,
    Blake3,
    Whirlpool,
}

impl Algorithm {
    /// Every digest, in the order they are listed: the checksums, the ones that
    /// are only for comparing, then the families that can be relied on.
    pub(crate) const ALL: [Algorithm; 22] = [
        Algorithm::Adler32,
        Algorithm::Crc32,
        Algorithm::Crc64,
        Algorithm::Xxh64,
        Algorithm::Xxh3,
        Algorithm::Md5,
        Algorithm::Sha1,
        Algorithm::Ripemd160,
        Algorithm::Sha224,
        Algorithm::Sha256,
        Algorithm::Sha384,
        Algorithm::Sha512,
        Algorithm::Sha512_224,
        Algorithm::Sha512_256,
        Algorithm::Sha3_224,
        Algorithm::Sha3_256,
        Algorithm::Sha3_384,
        Algorithm::Sha3_512,
        Algorithm::Blake2s,
        Algorithm::Blake2b,
        Algorithm::Blake3,
        Algorithm::Whirlpool,
    ];

    /// The one a folder is hashed with unless another is chosen, and the one
    /// most often asked for.
    pub(crate) const USUAL: Algorithm = Algorithm::Sha256;

    /// The name other modules use, and the key of the hash in an answer.
    pub(crate) fn key(self) -> &'static str {
        match self {
            Algorithm::Adler32 => "adler32",
            Algorithm::Crc32 => "crc32",
            Algorithm::Crc64 => "crc64",
            Algorithm::Xxh64 => "xxh64",
            Algorithm::Xxh3 => "xxh3",
            Algorithm::Md5 => "md5",
            Algorithm::Sha1 => "sha1",
            Algorithm::Ripemd160 => "ripemd160",
            Algorithm::Sha224 => "sha224",
            Algorithm::Sha256 => "sha256",
            Algorithm::Sha384 => "sha384",
            Algorithm::Sha512 => "sha512",
            Algorithm::Sha512_224 => "sha512_224",
            Algorithm::Sha512_256 => "sha512_256",
            Algorithm::Sha3_224 => "sha3_224",
            Algorithm::Sha3_256 => "sha3_256",
            Algorithm::Sha3_384 => "sha3_384",
            Algorithm::Sha3_512 => "sha3_512",
            Algorithm::Blake2s => "blake2s",
            Algorithm::Blake2b => "blake2b",
            Algorithm::Blake3 => "blake3",
            Algorithm::Whirlpool => "whirlpool",
        }
    }

    /// The name as it is written for people.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Algorithm::Adler32 => "Adler-32",
            Algorithm::Crc32 => "CRC-32",
            Algorithm::Crc64 => "CRC-64",
            Algorithm::Xxh64 => "XXH64",
            Algorithm::Xxh3 => "XXH3",
            Algorithm::Md5 => "MD5",
            Algorithm::Sha1 => "SHA-1",
            Algorithm::Ripemd160 => "RIPEMD-160",
            Algorithm::Sha224 => "SHA-224",
            Algorithm::Sha256 => "SHA-256",
            Algorithm::Sha384 => "SHA-384",
            Algorithm::Sha512 => "SHA-512",
            Algorithm::Sha512_224 => "SHA-512/224",
            Algorithm::Sha512_256 => "SHA-512/256",
            Algorithm::Sha3_224 => "SHA3-224",
            Algorithm::Sha3_256 => "SHA3-256",
            Algorithm::Sha3_384 => "SHA3-384",
            Algorithm::Sha3_512 => "SHA3-512",
            Algorithm::Blake2s => "BLAKE2s",
            Algorithm::Blake2b => "BLAKE2b",
            Algorithm::Blake3 => "BLAKE3",
            Algorithm::Whirlpool => "Whirlpool",
        }
    }

    /// How many hex digits its hash has. Not enough to tell them apart —
    /// SHA-256, SHA-512/256, SHA3-256, BLAKE2s and BLAKE3 are all 64 — but
    /// enough to say which a hash with no name on it *could* be.
    pub(crate) fn hex_len(self) -> usize {
        match self {
            Algorithm::Adler32 | Algorithm::Crc32 => 8,
            Algorithm::Crc64 | Algorithm::Xxh64 | Algorithm::Xxh3 => 16,
            Algorithm::Md5 => 32,
            Algorithm::Sha1 | Algorithm::Ripemd160 => 40,
            Algorithm::Sha224 | Algorithm::Sha512_224 | Algorithm::Sha3_224 => 56,
            Algorithm::Sha256 | Algorithm::Sha512_256 | Algorithm::Sha3_256 | Algorithm::Blake2s | Algorithm::Blake3 => 64,
            Algorithm::Sha384 | Algorithm::Sha3_384 => 96,
            Algorithm::Sha512 | Algorithm::Sha3_512 | Algorithm::Blake2b | Algorithm::Whirlpool => 128,
        }
    }

    /// An algorithm by any of the ways its name is written: `sha256`,
    /// `SHA-256`, `sha_256`; `sha3-256`, `SHA3_256`; `SHA-512/256`;
    /// `blake2b-512`.
    ///
    /// Only letters and digits are compared, which is what keeps `SHA3-256`
    /// (`sha3256`) apart from `SHA-256` (`sha256`).
    pub(crate) fn parse(name: &str) -> Option<Algorithm> {
        let plain = |s: &str| -> String {
            s.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_ascii_lowercase()
        };
        let asked = plain(name);
        // The names tools print that are not the ones used here.
        let asked = match asked.as_str() {
            // SHA-2 is a family, not an algorithm: its members written with
            // the family's name in front (`SHA2-256`) are the plain ones.
            "sha2224" => "sha224",
            "sha2256" => "sha256",
            "sha2384" => "sha384",
            "sha2512" => "sha512",
            "sha2512224" => "sha512224",
            "sha2512256" => "sha512256",
            "blake2b512" | "blake2" => "blake2b",
            "blake2s256" => "blake2s",
            "crc" | "crc32b" => "crc32",
            "crc64xz" | "crc64ecma" => "crc64",
            "adler" => "adler32",
            "rmd160" | "ripemd" => "ripemd160",
            "xxhash64" | "xxhash" => "xxh64",
            "xxh364" | "xxhash3" | "xxh3_64" => "xxh3",
            other => other,
        };
        Algorithm::ALL.into_iter().find(|a| plain(a.key()) == asked)
    }

    /// The algorithms whose hashes are this long.
    pub(crate) fn of_len(hex_digits: usize) -> Vec<Algorithm> {
        Algorithm::ALL.into_iter().filter(|a| a.hex_len() == hex_digits).collect()
    }
}

/// One digest being fed.
///
/// Several kinds, because several libraries: the cryptographic hashes that
/// share one interface, BLAKE3, and the checksums each in their own.
enum Running {
    Hash(Box<dyn DynDigest>),
    Blake3(Box<blake3::Hasher>),
    Adler32(adler2::Adler32),
    Crc32(crc32fast::Hasher),
    Crc64(crc::Digest<'static, u64>),
    Xxh64(Box<xxhash_rust::xxh64::Xxh64>),
    Xxh3(Box<xxhash_rust::xxh3::Xxh3>),
}

impl Running {
    fn start(algorithm: Algorithm) -> Running {
        match algorithm {
            Algorithm::Adler32 => Running::Adler32(adler2::Adler32::new()),
            Algorithm::Crc32 => Running::Crc32(crc32fast::Hasher::new()),
            Algorithm::Crc64 => Running::Crc64(CRC64.digest()),
            // Seed zero, as every tool that prints one uses.
            Algorithm::Xxh64 => Running::Xxh64(Box::new(xxhash_rust::xxh64::Xxh64::new(0))),
            Algorithm::Xxh3 => Running::Xxh3(Box::new(xxhash_rust::xxh3::Xxh3::new())),
            Algorithm::Md5 => Running::Hash(Box::new(Md5::default())),
            Algorithm::Sha1 => Running::Hash(Box::new(Sha1::default())),
            Algorithm::Ripemd160 => Running::Hash(Box::new(Ripemd160::default())),
            Algorithm::Sha224 => Running::Hash(Box::new(Sha224::default())),
            Algorithm::Sha256 => Running::Hash(Box::new(Sha256::default())),
            Algorithm::Sha384 => Running::Hash(Box::new(Sha384::default())),
            Algorithm::Sha512 => Running::Hash(Box::new(Sha512::default())),
            Algorithm::Sha512_224 => Running::Hash(Box::new(Sha512_224::default())),
            Algorithm::Sha512_256 => Running::Hash(Box::new(Sha512_256::default())),
            Algorithm::Sha3_224 => Running::Hash(Box::new(Sha3_224::default())),
            Algorithm::Sha3_256 => Running::Hash(Box::new(Sha3_256::default())),
            Algorithm::Sha3_384 => Running::Hash(Box::new(Sha3_384::default())),
            Algorithm::Sha3_512 => Running::Hash(Box::new(Sha3_512::default())),
            Algorithm::Blake2s => Running::Hash(Box::new(Blake2s256::default())),
            Algorithm::Blake2b => Running::Hash(Box::new(Blake2b512::default())),
            Algorithm::Blake3 => Running::Blake3(Box::new(blake3::Hasher::new())),
            Algorithm::Whirlpool => Running::Hash(Box::new(Whirlpool::default())),
        }
    }

    fn feed(&mut self, bytes: &[u8]) {
        match self {
            Running::Hash(h) => h.update(bytes),
            Running::Blake3(h) => {
                h.update(bytes);
            }
            Running::Adler32(h) => h.write_slice(bytes),
            Running::Crc32(h) => h.update(bytes),
            Running::Crc64(h) => h.update(bytes),
            Running::Xxh64(h) => h.update(bytes),
            Running::Xxh3(h) => h.update(bytes),
        }
    }

    fn finish(self) -> String {
        // The checksums are numbers; they are written high byte first, as
        // every tool prints them.
        match self {
            Running::Hash(h) => hex(&h.finalize()),
            Running::Blake3(h) => hex(h.finalize().as_bytes()),
            Running::Adler32(h) => hex(&h.checksum().to_be_bytes()),
            Running::Crc32(h) => hex(&h.finalize().to_be_bytes()),
            Running::Crc64(h) => hex(&h.finalize().to_be_bytes()),
            Running::Xxh64(h) => hex(&h.digest().to_be_bytes()),
            Running::Xxh3(h) => hex(&h.digest().to_be_bytes()),
        }
    }
}

/// Bytes as lower-case hex, the way a hash is written.
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

/// What was hashed, and what came out.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Digests {
    /// How many bytes went through.
    pub size: u64,
    /// One hash per algorithm asked for, in the order of [`Algorithm::ALL`].
    pub hashes: Vec<(Algorithm, String)>,
}

impl Digests {
    pub(crate) fn of(&self, algorithm: Algorithm) -> Option<&str> {
        self.hashes.iter().find(|(a, _)| *a == algorithm).map(|(_, h)| h.as_str())
    }
}

/// The algorithms to run, in the listed order and each once, whatever order
/// and however often they were asked for.
fn ordered(algorithms: &[Algorithm]) -> Vec<Algorithm> {
    Algorithm::ALL.into_iter().filter(|a| algorithms.contains(a)).collect()
}

/// Run everything `source` gives through each of `algorithms`, in one pass.
///
/// One pass, because the reading is the slow part: a large file is read once
/// and every digest is fed from the same block.
pub(crate) fn digest_reader(mut source: impl Read, algorithms: &[Algorithm]) -> std::io::Result<Digests> {
    let wanted = ordered(algorithms);
    let mut running: Vec<Running> = wanted.iter().map(|&a| Running::start(a)).collect();
    let mut block = vec![0u8; CHUNK];
    let mut size: u64 = 0;
    loop {
        let got = match source.read(&mut block) {
            Ok(0) => break,
            Ok(n) => n,
            // A read that was merely interrupted is tried again, not failed.
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        size += got as u64;
        for r in &mut running {
            r.feed(&block[..got]);
        }
    }
    Ok(Digests { size, hashes: wanted.into_iter().zip(running.into_iter().map(Running::finish)).collect() })
}

/// The digests of bytes already in memory.
pub(crate) fn digest_bytes(bytes: &[u8], algorithms: &[Algorithm]) -> Digests {
    // Reading from a slice cannot fail.
    digest_reader(bytes, algorithms).expect("a slice is always readable")
}

/// The digests of the file at `path`.
///
/// The error is the system's own words with the path in front: "no such file",
/// "permission denied" and "is a directory" are three different things to do
/// next, and all three arrive here.
pub(crate) fn digest_file(path: &str, algorithms: &[Algorithm]) -> Result<Digests, String> {
    let said = |e: std::io::Error| format!("{path}: {e}");
    let file = File::open(Path::new(path)).map_err(said)?;
    // A directory opens on Unix and fails only when read, with a message that
    // names no cause; say it here instead.
    if file.metadata().map_err(said)?.is_dir() {
        return Err(format!("{path}: is a directory, not a file"));
    }
    digest_reader(file, algorithms).map_err(said)
}

/// A hash somebody was given: the hex it is, and which algorithms it could be
/// a hash of — or nothing, if it is not a hash at all.
///
/// Hashes arrive in more shapes than one: upper-case out of a Windows tool,
/// with the algorithm in front (`sha256:…`, `SHA256=…`), or as a whole line of
/// a checksum file with the file's name after it. All of those are the same
/// hash, and none of them should read as "does not match".
///
/// With a name in front it is that algorithm's and no other's. Without one the
/// length is all there is to go by, and several share a length — so it is held
/// against each of them, and matches if it is any one's.
pub(crate) fn expected_hash(given: &str) -> Option<(Vec<Algorithm>, String)> {
    // The first word: a checksum file's line is the hash, then the name.
    let word = given.split_whitespace().next()?;
    // The algorithm's name in front, if it has one — only when what precedes
    // the separator is a name, so that nothing is cut out of a bare hash.
    let (named, hash) = match word.split_once([':', '=']) {
        Some((name, rest)) if Algorithm::parse(name).is_some() => (Algorithm::parse(name), rest),
        _ => (None, word),
    };
    let hash = hash.to_ascii_lowercase();
    if hash.is_empty() || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let could_be = match named {
        // A named hash of the wrong length is not that algorithm's hash.
        Some(algorithm) if algorithm.hex_len() == hash.len() => vec![algorithm],
        Some(_) => return None,
        None => Algorithm::of_len(hash.len()),
    };
    (!could_be.is_empty()).then_some((could_be, hash))
}

/// Which of `could_be` the hash is, in `digests` — the first, if any.
pub(crate) fn which_matches(digests: &Digests, could_be: &[Algorithm], hash: &str) -> Option<Algorithm> {
    could_be.iter().copied().find(|&a| digests.of(a) == Some(hash))
}
