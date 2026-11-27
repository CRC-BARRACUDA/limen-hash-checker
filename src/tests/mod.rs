//! What the module is expected to do, in the language of what it is for.
//!
//! A cdylib has no rlib for an integration test to link against, so these live
//! inside the crate: one file per part, and what they share here.

use crate::*;

mod api;
mod folders;
mod hashing;
mod i18n;
mod views;

/// A file of its own for one test, removed when the test is done with it.
pub(crate) struct Scratch(pub std::path::PathBuf);

impl Scratch {
    pub(crate) fn with(test: &str, bytes: &[u8]) -> Scratch {
        let path = std::env::temp_dir().join(format!("limen-hash-{}-{test}", std::process::id()));
        std::fs::write(&path, bytes).expect("the temp directory can be written to");
        Scratch(path)
    }

    pub(crate) fn path(&self) -> String {
        self.0.to_string_lossy().into_owned()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// The hashes of "abc" — the one input every implementation is checked
/// against. From the standards and the algorithms' own published vectors, and
/// checked against other implementations (Python's hashlib and zlib, OpenSSL)
/// wherever one was to hand, rather than against the libraries used here.
pub(crate) const ABC: [(Algorithm, &str); 26] = [
    (Algorithm::Adler32, "024d0127"),
    (Algorithm::Crc32, "352441c2"),
    (Algorithm::Crc64, "2cd8094a1a277627"),
    (Algorithm::Xxh64, "44bc2cf5ad770999"),
    (Algorithm::Xxh3, "78af5f94892f3950"),
    (Algorithm::Md5, "900150983cd24fb0d6963f7d28e17f72"),
    (Algorithm::Sha1, "a9993e364706816aba3e25717850c26c9cd0d89d"),
    (Algorithm::Ripemd160, "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
    (Algorithm::Sha224, "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"),
    (Algorithm::Sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    (
        Algorithm::Sha384,
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
         8086072ba1e7cc2358baeca134c825a7",
    ),
    (
        Algorithm::Sha512,
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
         2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    ),
    (Algorithm::Sha512_224, "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa"),
    (Algorithm::Sha512_256, "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"),
    (Algorithm::Sha3_224, "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"),
    (Algorithm::Sha3_256, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
    (
        Algorithm::Sha3_384,
        "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b2\
         98d88cea927ac7f539f1edf228376d25",
    ),
    (
        Algorithm::Sha3_512,
        "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e\
         10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
    ),
    (Algorithm::Blake2s, "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"),
    (
        Algorithm::Blake2b,
        "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
         7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
    ),
    (Algorithm::Blake3, "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"),
    (
        Algorithm::Whirlpool,
        "4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c\
         7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5",
    ),
    // Ukraine's: checked against the vectors their standards publish — see
    // `the_ukrainian_hashes_are_the_ones_their_standards_define`.
    (Algorithm::Kupyna256, "0bd1b36109f1318411a0517315aa46b8839df06622a278676f5487996c9cfc04"),
    (
        Algorithm::Kupyna384,
        "72945012b0820c3132846ddc90da511f80bb7b70abd0cb1ab8df785d600c187b\
         9d0ac567e8b6f76fde8a0b417a2ebf88",
    ),
    (
        Algorithm::Kupyna512,
        "9e5be7daf7b68b49d2ecbd04c7a5b3af72945012b0820c3132846ddc90da511f\
         80bb7b70abd0cb1ab8df785d600c187b9d0ac567e8b6f76fde8a0b417a2ebf88",
    ),
    (Algorithm::Gost34311, "a34a53504d8ba070cb73a583146167a0a3c226d793440d9cea24465fe02251f2"),
];

/// The hash of "abc" by one algorithm.
pub(crate) fn abc(algorithm: Algorithm) -> &'static str {
    ABC.iter().find(|(a, _)| *a == algorithm).map(|(_, h)| *h).expect("every algorithm has a vector")
}
