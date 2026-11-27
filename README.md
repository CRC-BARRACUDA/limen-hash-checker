# limen-hash-checker

The hashes of a file, a folder or a piece of text, and whether one of them is
the hash you were given.

It calculates and compares, and that is all it does. A hash is worked out on
this machine and stays on it: nothing is looked up anywhere, because what a hash
*means* — known-good, known-bad — is another module's question.

## What it calculates

Everything below, in one pass over the data — a large file is read once.

| Algorithm | Hex digits | What it is |
|---|---|---|
| Adler-32 | 8 | Checksum |
| CRC-32 | 8 | Checksum — the one in zip, gzip and PNG |
| CRC-64 | 16 | Checksum — CRC-64/XZ, the one `xz` and 7-Zip use |
| XXH64 | 16 | Checksum, fast (seed 0) |
| XXH3 | 16 | Checksum, fast — the 64-bit XXH3 |
| MD5 | 32 | For comparing with what others still publish |
| SHA-1 | 40 | The same |
| RIPEMD-160 | 40 | Sound and rare |
| SHA-224 | 56 | SHA-2 |
| SHA-256 | 64 | SHA-2 — the one most often asked for |
| SHA-384 | 96 | SHA-2 |
| SHA-512 | 128 | SHA-2 |
| SHA-512/224 | 56 | SHA-2 |
| SHA-512/256 | 64 | SHA-2 |
| SHA3-224 | 56 | SHA-3 |
| SHA3-256 | 64 | SHA-3 |
| SHA3-384 | 96 | SHA-3 |
| SHA3-512 | 128 | SHA-3 |
| BLAKE2s | 64 | BLAKE2s-256 |
| BLAKE2b | 128 | BLAKE2b-512 |
| BLAKE3 | 64 | BLAKE3, 256-bit output |
| Whirlpool | 128 | Sound and rare |

**SHA-2 is a family, not one algorithm**: the six rows marked SHA-2 are all of
it. "SHA-256" and "SHA2-256" are two names for the same thing.

They are not interchangeable:

* A **checksum** catches a damaged download or a bad copy, and stops nobody who
  means to deceive: making another file with the same checksum is easy.
* **MD5** and **SHA-1** are for comparing with a published value, not for
  trusting: both can be made to collide on purpose.
* **SHA-2, SHA-3, BLAKE2 and BLAKE3** are the ones to rely on.

## On the screen

Choose **what to hash** — a file, a folder or text — fill in the one field that
goes with it, and press **Calculate**. Text is hashed exactly as typed, as
UTF-8, with nothing added at the end.

A folder given where a file was asked for is hashed as the folder it is, and the
other way round: the form follows the path.

Each hash can be copied: double-click its row, or right-click it.

### A folder

Every file under the folder is hashed, subfolders included, with the one
algorithm chosen in **Algorithm** (SHA-256 unless another is picked) — and the folder gets one hash for the whole.

The folder's hash is the hash of its **checksum list**: one line per file,

```
<hash of the file><two spaces><path inside the folder, with />
```

sorted by path, byte for byte. That is exactly what `sha256sum` prints, so the
number can be recomputed without this module:

```
cd the-folder
find . -type f | sed 's|^\./||' | LC_ALL=C sort | xargs -d '\n' sha256sum | sha256sum
```

It changes when any file changes, appears, disappears or moves, and two copies
of a folder have the same hash wherever they lie and whatever they are called.
**Copy the checksum list** puts the list itself on the clipboard, to save as a
`.sha256` file that `sha256sum -c` checks.

What is not in it, and is said on the screen when there is any:

* **Links are not followed** — following them is how a walk leaves the folder
  it was asked about, or never ends. They are counted.
* **Pipes, sockets and devices are not read.**
* **Empty folders**, and anything that is not a file's contents: owners,
  permissions, dates.
* **A file that cannot be read** is listed with the reason, the rest is still
  hashed — and the folder then gets *no* hash of its own, because a hash of
  part of a folder is not the folder's.

The table shows the first 500 files; all of them are hashed and all are in the
checksum list.

### Comparing with a hash you were given

Paste it into **Hash to compare with** and the screen says whether it matches.
It is read in whatever shape it came:

* upper or lower case;
* with the algorithm in front — `sha256:…`, `SHA256=…`, `SHA3-256:…`;
* as a whole line of a checksum file — the hash, then the file's name.

With a name in front, it is held against that algorithm alone. Without one the
length is all there is to go by, and most lengths are shared (five algorithms
give 64 digits), so it is held against each and matches if it is any one's.
Something that is not a hash at all is said to be that, not to "not match".

For a folder the hash is looked for twice: as the folder's own, and as the hash
of any file in it — "is that file in here" is as often the question as "is this
folder intact". A hash of another kind than the folder was hashed with is said
to be that, not reported as a mismatch.

## For other modules

Provides `hash.calc`. Every answer has the same shape —
`{"size": bytes, "hashes": {"sha256": "…", …}}` — and `algorithms` narrows what
is calculated; left out, all of them are.

```
algorithms                                  -> which digests there are
hash_file   {"path", "algorithms"?}         -> a file on this machine
hash_dir    {"path", "algorithm"?}          -> a folder: its files, and itself
hash_text   {"text", "algorithms"?}         -> text, as its UTF-8 bytes
hash_base64 {"data", "algorithms"?}         -> bytes the caller already holds
verify      {"expected", "path"|"text"|"data"}
                                            -> whether a hash is the right one
```

The names are `adler32`, `crc32`, `crc64`, `xxh64`, `xxh3`, `md5`, `sha1`,
`ripemd160`, `sha224`, `sha256`, `sha384`, `sha512`, `sha512_224`,
`sha512_256`, `sha3_224`, `sha3_256`, `sha3_384`, `sha3_512`, `blake2s`,
`blake2b`, `blake3` and `whirlpool`; they are also accepted as people write
them (`SHA-256`, `SHA2-256`, `sha3-256`, `SHA-512/256`). A name that is not one of them is an error, not a
quiet "all of them".

`hash_dir` takes one `algorithm` (SHA-256 if none is named), because it is run
over every file, and answers `{"path", "algorithm", "hash", "count", "size",
"files": [{"path", "size", "hash"}], "failed": [{"path", "error"}],
"links_skipped", "special_skipped"}`. `hash` is the folder's own, and `null`
when anything in it could not be read.

`verify` answers `{"match", "algorithm", "expected", "actual", "size"}`:
`algorithm` is the one the hash turned out to be (`null` when it is none), and
`actual` carries the hashes it was compared with, so a "no" can be shown rather
than only reported.

A caller that wants one hash of a large file should name it: twenty-two
digests of a disk image take twenty-two times the arithmetic.

## It needs very little

* `filesystem` — only what it is pointed at: the file or folder picked on its
  screen, or the path another module hands it. Files are read and nothing is
  written.
* `subprocess` — only to reach the clipboard on Linux and macOS, through the
  desktop's own tool (`wl-copy`, `xclip`, `xsel`; `pbcopy`). On Windows the
  system is asked directly.

No `network`: nothing leaves the machine.

## Building

```
scripts/package.sh
```

builds the library for this platform into `dist/`, with its checksum, and
refreshes the copy a locally-run Limen loads.

## Languages

English and Ukrainian.

## Licence

GPL-3.0-or-later.
