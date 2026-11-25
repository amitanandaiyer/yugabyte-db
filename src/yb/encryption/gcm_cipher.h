// Copyright (c) YugabyteDB, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.  You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied.  See the License for the specific language governing permissions and limitations
// under the License.
//

#pragma once

#include <memory>

#include "yb/encryption/encryption_util.h"

#include "yb/util/record_cipher.h"
#include "yb/util/slice.h"
#include "yb/util/status_fwd.h"

struct evp_cipher_ctx_st;

namespace yb::encryption {

// AES-GCM over a file split into chunks of gcm_chunk_size plaintext bytes. Each chunk is a separate
// GCM message: ciphertext of the same length followed by a 16-byte tag.
//
// The IV of chunk i is the file's 12-byte nonce with its last 8 bytes XORed with i, so chunks
// cannot be reordered, and the per-file random data key keeps IVs unique across files. The only
// additional authenticated data is a final flag, set on the empty chunk that ends a complete file,
// so a file truncated at a chunk boundary is detected.
//
// GCM encrypts with CTR starting at counter 2, so a chunk's ciphertext can be written as plaintext
// arrives and its tag appended once the chunk is full. Until then the bytes can be decrypted, but
// not authenticated, with DecryptUnauthenticated.
class GcmChunkCipher {
 public:
  static constexpr size_t kTagSize = 16;

  static Result<std::unique_ptr<GcmChunkCipher>> Create(const EncryptionParams& params);

  size_t chunk_size() const { return chunk_size_; }

  // Returns Corruption if the tag does not match.
  Status Open(
      uint64_t index, bool final, Slice ciphertext, Slice tag, uint8_t* plaintext) const;

  Status DecryptUnauthenticated(
      uint64_t index, size_t offset_in_chunk, Slice ciphertext, uint8_t* plaintext) const;

  // Encrypts one chunk at a time as plaintext arrives. Not thread safe.
  class Sealer {
   public:
    explicit Sealer(const GcmChunkCipher& cipher);
    ~Sealer();

    Status Begin(uint64_t index, bool final);
    Status Update(Slice plaintext, uint8_t* ciphertext);
    Status Finish(uint8_t* tag);

   private:
    const GcmChunkCipher& cipher_;
    evp_cipher_ctx_st* ctx_;
  };

 private:
  explicit GcmChunkCipher(const EncryptionParams& params);

  void ChunkIv(uint64_t index, uint8_t* iv) const;
  Status InitContext(evp_cipher_ctx_st* ctx, bool encrypt, uint64_t index, bool final) const;

  uint8_t key_[EncryptionParams::kMaxKeySize];
  uint32_t key_size_;
  uint8_t nonce_[EncryptionParams::kBlockSize - sizeof(uint32_t)];
  size_t chunk_size_;
};

// AES-GCM as a RecordCipher. A record's nonce is a 12-byte base with its last 8 bytes XORed with
// the record's position; a sealed record is the ciphertext and a 16-byte tag, preceded by the nonce
// if the file stores nonces (EncryptionParams::record_nonce_stored).
//
// - Files that are never rewritten (SSTs) use the file's nonce as the base and store nothing: the
//   file's key is unique and each position is written once.
// - WAL segments are reopened after a crash and rewritten from their last valid entry, so the same
//   position is sealed again with different data. Their base is drawn at random for each writable
//   file instance and the nonce is stored with each record; two writer sessions only collide if
//   their bases differ by the XOR of two positions, about 2^-70 for segments under 64 MiB.
class GcmRecordCipher : public RecordCipher {
 public:
  static constexpr size_t kNonceSize = 12;
  static constexpr size_t kTagSize = 16;

  static Result<std::unique_ptr<GcmRecordCipher>> Create(const EncryptionParams& params);

  size_t Overhead() const override { return (nonce_stored_ ? kNonceSize : 0) + kTagSize; }
  Status Seal(uint64_t position, Slice aad, Slice plaintext, uint8_t* sealed) const override;
  Status Open(uint64_t position, Slice aad, Slice sealed, uint8_t* plaintext) const override;

 private:
  explicit GcmRecordCipher(const EncryptionParams& params);

  void RecordNonce(uint64_t position, uint8_t* nonce) const;

  uint8_t key_[EncryptionParams::kMaxKeySize];
  uint32_t key_size_;
  const bool nonce_stored_;
  uint8_t base_nonce_[kNonceSize];
};

} // namespace yb::encryption
