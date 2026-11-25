# AES-GCM encryption at rest

Encryption at rest ([docdb-encryption-at-rest.md](docdb-encryption-at-rest.md)) uses AES-CTR. CTR
keeps data confidential but does not detect modification: flipping a ciphertext bit flips the same
plaintext bit, and only RocksDB and WAL checksums, which an attacker can recompute, stand in the
way. AES-GCM adds a 16-byte authentication tag to each encrypted message, so reading modified data
fails with `Corruption`.

This document describes how GCM is applied to each kind of file, and why SST files and WAL segments
are handled differently.

## Summary

| File | Unit sealed with GCM | Nonce | Overhead |
|---|---|---|---|
| SST data (`.sst`, `.sblock.N`) | Each RocksDB block, plus the footer | File nonce XOR block offset, not stored | 16 B per block |
| WAL segment | Each record: header, entry batch, index block header and data, footer | Per-writer-session random base XOR record offset, stored with the record | 28 B per record |
| RocksDB MANIFEST | 4 KB chunks; a tail cut short by a crash is accepted | File nonce XOR chunk index | 16 B per 4 KB |
| Everything else (CURRENT, OPTIONS, tablet and consensus metadata) | 4 KB chunks, plus an empty final chunk | File nonce XOR chunk index | 16 B per 4 KB, plus 16 B |

The envelope scheme is unchanged: every file has its own random data key in its header, wrapped by
the universe key. The header records how the file was encrypted (`EncryptionParamsPB` fields 5–8),
so readers never consult the current setting, and files written in any mode stay readable.

## Selecting GCM

GCM is selected with the encryption algorithm introduced for AES-256 (#37096):
`yb-admin set_encryption_algorithm AES_256_GCM` (or `AES_128_GCM`) records it in
`UniverseKeyRegistryPB.encryption_algorithm`. The algorithm fixes both the cipher and the data-key
size; `encryption_algorithm_override` overrides it per tserver for diagnostics.

**Upgrade.** Older releases ignore the new header fields and would decrypt a GCM file as CTR,
producing garbage that only checksums catch. GCM files are therefore written only once the
`enable_encryption_gcm` AutoFlag (kLocalPersisted) is promoted:

- The master refuses `set_encryption_algorithm` with a GCM algorithm until then.
- A tserver that sees a GCM algorithm without the flag writes CTR with the same key size and logs a
  warning.

**Rollback** is not supported once GCM files exist.

**Migration** follows the AES-256 runbook: select the algorithm, restart tservers one at a time,
then run a full compaction. The compaction rewrites SST files; the restart moves each tablet's WAL
to a new segment (see [WAL reuse](#wal-segments-are-reused-after-a-restart)) and, with the first
version edit after it, the MANIFEST.

## GCM constraints that drive the design

- **A nonce must never repeat under one key.** Two messages under the same key and nonce reveal the
  XOR of their plaintexts *and* the GHASH key, after which an attacker can forge tags for any
  message under that key. Every design choice below is about where nonces come from and whether a
  position can be written twice.
- **A message is authenticated as a whole.** Reading any part of it means reading and verifying all
  of it, and a message can't be extended after its tag is written.

Each file has its own data key, so nonces only need to be unique within a file.

## SST files: one GCM message per block

RocksDB already reads SST files block by block through block handles (offset, size), writes each
block whole, and keeps a CRC trailer per block. Sealing at that unit costs no read amplification and
no new framing.

- `WriteRawBlock` seals the (possibly compressed) block. The handle size and the trailer CRC cover
  the sealed bytes, so framing, readahead and the CRC check are unchanged.
- `ReadBlockContents` checks the CRC (cheap, catches accidental corruption) and then opens the block
  before decompression. The block cache and the compressed block cache only ever hold plaintext.
- **Nonce = file nonce XOR block offset, not stored.** An SST file is written once, start to end,
  and never reopened, so each offset is sealed once. A write-once record file refuses to be reopened
  for append, which enforces this.
- **AAD = block offset + compression type**, so a genuine block can't be moved to another offset or
  reinterpreted with a different compression type.
- **The footer is sealed too** (a GMAC over its encoding, appended after it). It holds the index and
  metaindex handles; without a tag, a modified handle could point at another genuine block.

The file layer stays out of the way: for a record-mode file (`ENCRYPTION_CIPHER_MODE_GCM_RECORD`)
it writes the header and passes bytes through, and exposes a `yb::RecordCipher` through
`record_cipher()` for RocksDB to seal with. Which RocksDB files use records is chosen by name in
`GcmLayoutForFile` (`.sst`, `.sblock.`); an SST written under another name would silently get the
chunked layout.

**Rejected: fixed-size chunks in the file layer** (the first prototype, 4 KB chunks for every file).
It needs no RocksDB changes, but blocks don't line up with chunks, so a block read decrypts and
verifies up to two extra partial chunks, and the plaintext↔file offset mapping leaks into
`GetFileSize`. Making the chunk size equal the block size doesn't work either: blocks are variable
sized (compression, restart points), so chunks would need a length prefix and offsets would stop
being arithmetic. Sealing at the unit RocksDB already frames avoids both.

## WAL segments: one GCM message per record

The log writes the segment header, entry batches, index blocks and the footer as separate records,
each with its own length and CRC. Each is sealed individually:

| Record | AAD | Nonce position |
|---|---|---|
| Segment header PB | kind + offset | offset |
| Entry batch | kind + entry-header offset | data offset |
| Index block header / data | kind + index block start | start + 8 / start |
| Footer PB | kind + footer offset | footer offset |

The kind (`WalRecordKind`) is in the AAD so a record can't be replayed as a different kind. An index
block's header and data both use the block's start offset, because the header's size depends on the
data's sealed size. Lengths and CRCs cover the sealed bytes, so `ScanForValidEntryHeaders`, the log
index and readers are unchanged apart from opening each record.

### WAL segments are reused after a restart

Since #14138, a tablet that restarts reopens its last unclosed segment instead of starting a new one
(`Log::ReuseAsActiveSegment`, enabled by default with #18757). Repeated crash-restarts had been
creating a new segment each time, exhausting file descriptors. Encrypted segments are reopened
through `EncryptedFileFactory::NewWritableFile` with `OPEN_EXISTING` (#16698).

Reuse resumes writing at the end of the last valid entry. Whatever a crash left beyond that (a torn
batch, preallocated zeros) is **overwritten**. Raft itself never rewrites a position: truncating the
log after a leader change appends new entries after the old ones.

So the WAL, unlike SSTs, can write a position twice: once before the crash and once after the
restart, with different contents. A nonce derived only from the position would repeat, which in GCM
gives away the authentication key for the whole segment.

**Chosen: a per-writer-session nonce base, stored with every record (option A).**

- Each writable-file instance draws a random 12-byte base: the first open, then each reopen after a
  restart. A record's nonce is the base with its last 8 bytes XORed with the record's position.
- The nonce is stored with the record (12 B nonce + 16 B tag = 28 B), so readers don't need to know
  where sessions started.
- Two sessions collide only if their bases differ by exactly the XOR of two positions: about 2^-70
  for segments under 64 MiB.
- Cost: one `RAND_bytes` per writer session, and 12 B per record.

**Option B, kept in reserve if 12 B per record is too much:** store the base once per session — in
the segment header for the first session, and in a sealed "session start" record after each reopen.
Readers then need an offset → base map: sequential readers pick up the markers as they go, and
random readers through the log index need closed segments to list (start offset, base) pairs in the
footer, with recovery rebuilding the map for an active segment. It saves 12 B per batch (about 1–6%
of WAL bytes for 200 B–1 KB batches, negligible for large ones) at the cost of a new record kind, a
footer field and session tracking in `ReadableLogSegment`/`LogReader`. Segments written under
option A stay readable, since the choice is recorded per file (`record_nonce_stored`).

**Rejected alternatives:**

- *Disable WAL reuse under GCM.* Simple, but brings back the #14138 crash-loop behaviour for GCM
  universes.
- *Chunked GCM for the WAL with an unauthenticated tail* (the first prototype). A segment is synced
  at arbitrary points, so the open chunk can't be sealed until it fills; after a crash, up to one
  chunk of the tail is decrypted without authentication. Not acceptable to users who require every
  WAL byte read to be authenticated.
- *A random nonce per record.* Equivalent safety to option A, but a `RAND_bytes` call per record on
  the append path.

### Changing the algorithm or key across a restart

A reopened segment keeps the encryption recorded in its header. If it were reused after the
universe's encryption changed, appends would continue in the old encryption until the segment rolls
over (up to 64 MB per tablet). `EncryptedFileFactory::NewWritableFile` therefore reopens a segment
only if a new file would be encrypted the same way:

- encryption is enabled exactly when the segment is encrypted;
- the segment's universe key is the latest one;
- the segment's cipher (CTR or GCM) and data-key size match the current algorithm.

Otherwise it returns `NotSupported`, and `ReuseAsActiveSegment` rebuilds the old segment's footer
and starts a new segment. The tserver does not fail, and the change reaches the WAL on the first
restart. Independently of the current settings, chunked GCM files and write-once record files are
never reopened, since their tags or nonces can't be continued.

The key-size check comes with #37096, which lets the algorithm change without a key rotation; GCM
adds the cipher check.

## Other files

- **MANIFEST** is appended to for the life of a DB and must be readable after a crash, but its
  records are written by RocksDB's `log::Writer` with its own 32 KB block format. It stays chunked:
  full chunks are authenticated, and a reader accepts a missing final chunk and decrypts the
  remaining partial chunk (less than 4 KB plus a torn tag) without authentication; the MANIFEST's
  own CRCs then find its end. Sealing MANIFEST records in `log::Writer` would close this gap.
- **All other files** use strict chunks: closing the file appends an empty chunk with AAD final=1,
  and a missing final chunk is `Corruption`. Writers seal on destruction if `Close` was not called,
  because RocksDB writes CURRENT through `WriteStringToFile` without closing it.
- Chunked files are **never preallocated**: `fallocate` extends the file with zeros, which a reader
  can't tell apart from a corrupt chunk.

## What GCM does not protect

- **Truncation of the active WAL segment.** Dropping whole trailing records leaves a valid prefix.
  Closed segments are covered by the sealed footer; Raft replicas cover the active tail.
- **Swapping whole files.** Two complete encrypted files (header and body) can be exchanged without
  the encryption layer noticing; RocksDB and the log check file numbers and sequence numbers.
- **Data-key wrapping** is still AES-CTR under the universe key with a fixed nonce. A modified header
  is detected (a wrong data key fails authentication), but headers under one universe key share a
  keystream.
- **WAL copies** made by `ReadableLogSegment::CopyTo` are written unencrypted, as with CTR.

## Open items

- Benchmark CTR vs per-block/record GCM: block cache behaviour, SST read latency, WAL append
  latency, and the 28 B per WAL record.
- Seal MANIFEST records instead of chunks.
- YBA, yugabyted and Java client support for the GCM algorithms.
- Upgrade test promoting `enable_encryption_gcm`; backup/restore and xCluster with GCM.
