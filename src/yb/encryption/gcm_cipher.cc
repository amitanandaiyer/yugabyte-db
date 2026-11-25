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

#include "yb/encryption/gcm_cipher.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "yb/gutil/casts.h"
#include "yb/gutil/endian.h"

#include "yb/util/result.h"
#include "yb/util/status_format.h"

namespace yb::encryption {

namespace {

constexpr size_t kIvSize = 12;
// GCM uses counter 1 for the tag and starts encrypting at counter 2.
constexpr uint32_t kFirstDataCounter = 2;

struct CtxDeleter {
  void operator()(EVP_CIPHER_CTX* ctx) const { EVP_CIPHER_CTX_free(ctx); }
};
using CtxPtr = std::unique_ptr<EVP_CIPHER_CTX, CtxDeleter>;

Result<CtxPtr> NewContext() {
  CtxPtr ctx(EVP_CIPHER_CTX_new());
  SCHECK(ctx, InternalError, "EVP_CIPHER_CTX_new failed");
  return ctx;
}

const EVP_CIPHER* GcmCipher(uint32_t key_size) {
  switch (key_size) {
    case 16: return EVP_aes_128_gcm();
    case 24: return EVP_aes_192_gcm();
    case 32: return EVP_aes_256_gcm();
  }
  return nullptr;
}

const EVP_CIPHER* CtrCipher(uint32_t key_size) {
  switch (key_size) {
    case 16: return EVP_aes_128_ctr();
    case 24: return EVP_aes_192_ctr();
    case 32: return EVP_aes_256_ctr();
  }
  return nullptr;
}

Status CheckOpenSsl(int result, const char* call) {
  SCHECK_EQ(result, 1, InternalError, Format("$0 failed", call));
  return Status::OK();
}

} // namespace

Result<std::unique_ptr<GcmChunkCipher>> GcmChunkCipher::Create(const EncryptionParams& params) {
  SCHECK(params.cipher_mode == CipherMode::kGcm, InvalidArgument, "Not a GCM file");
  SCHECK_GT(params.gcm_chunk_size, 0U, Corruption, "GCM chunk size is 0");
  SCHECK(GcmCipher(params.key_size), InvalidArgument,
         Format("Unsupported key size $0", params.key_size));
  return std::unique_ptr<GcmChunkCipher>(new GcmChunkCipher(params));
}

GcmChunkCipher::GcmChunkCipher(const EncryptionParams& params)
    : key_size_(params.key_size), chunk_size_(params.gcm_chunk_size) {
  memcpy(key_, params.key, sizeof(key_));
  memcpy(nonce_, params.nonce, sizeof(nonce_));
}

void GcmChunkCipher::ChunkIv(uint64_t index, uint8_t* iv) const {
  static_assert(sizeof(nonce_) == kIvSize);
  memcpy(iv, nonce_, kIvSize);
  uint8_t index_bytes[sizeof(uint64_t)];
  BigEndian::Store64(index_bytes, index);
  for (size_t i = 0; i < sizeof(index_bytes); ++i) {
    iv[kIvSize - sizeof(index_bytes) + i] ^= index_bytes[i];
  }
}

Status GcmChunkCipher::InitContext(
    EVP_CIPHER_CTX* ctx, bool encrypt, uint64_t index, bool final) const {
  uint8_t iv[kIvSize];
  ChunkIv(index, iv);
  // The default GCM IV length is 12 bytes, so no EVP_CTRL_GCM_SET_IVLEN is needed.
  RETURN_NOT_OK(CheckOpenSsl(
      EVP_CipherInit_ex(ctx, GcmCipher(key_size_), nullptr, key_, iv, encrypt ? 1 : 0),
      "EVP_CipherInit_ex"));
  const uint8_t aad = final ? 1 : 0;
  int len;
  return CheckOpenSsl(EVP_CipherUpdate(ctx, nullptr, &len, &aad, 1), "EVP_CipherUpdate(aad)");
}

Status GcmChunkCipher::Open(
    uint64_t index, bool final, Slice ciphertext, Slice tag, uint8_t* plaintext) const {
  SCHECK_EQ(tag.size(), kTagSize, InvalidArgument, "Bad GCM tag size");
  auto ctx = VERIFY_RESULT(NewContext());
  RETURN_NOT_OK(InitContext(ctx.get(), /* encrypt= */ false, index, final));
  int len = 0;
  if (!ciphertext.empty()) {
    RETURN_NOT_OK(CheckOpenSsl(
        EVP_DecryptUpdate(
            ctx.get(), plaintext, &len, ciphertext.data(), narrow_cast<int>(ciphertext.size())),
        "EVP_DecryptUpdate"));
  }
  RETURN_NOT_OK(CheckOpenSsl(
      EVP_CIPHER_CTX_ctrl(
          ctx.get(), EVP_CTRL_GCM_SET_TAG, kTagSize, const_cast<uint8_t*>(tag.data())),
      "EVP_CTRL_GCM_SET_TAG"));
  uint8_t final_buf[EncryptionParams::kBlockSize];
  if (EVP_DecryptFinal_ex(ctx.get(), final_buf, &len) != 1) {
    return STATUS_FORMAT(Corruption, "AES-GCM authentication failed for chunk $0", index);
  }
  return Status::OK();
}

Status GcmChunkCipher::DecryptUnauthenticated(
    uint64_t index, size_t offset_in_chunk, Slice ciphertext, uint8_t* plaintext) const {
  if (ciphertext.empty()) {
    return Status::OK();
  }
  constexpr size_t kBlock = EncryptionParams::kBlockSize;
  uint8_t iv[kBlock];
  ChunkIv(index, iv);
  BigEndian::Store32(
      iv + kIvSize, narrow_cast<uint32_t>(kFirstDataCounter + offset_in_chunk / kBlock));

  auto ctx = VERIFY_RESULT(NewContext());
  RETURN_NOT_OK(CheckOpenSsl(
      EVP_DecryptInit_ex(ctx.get(), CtrCipher(key_size_), nullptr, key_, iv),
      "EVP_DecryptInit_ex"));
  // Discard the keystream before offset_in_chunk within its block.
  const size_t skip = offset_in_chunk % kBlock;
  int len;
  if (skip > 0) {
    uint8_t scratch[kBlock] = {0};
    RETURN_NOT_OK(CheckOpenSsl(
        EVP_DecryptUpdate(ctx.get(), scratch, &len, scratch, narrow_cast<int>(skip)),
        "EVP_DecryptUpdate"));
  }
  return CheckOpenSsl(
      EVP_DecryptUpdate(
          ctx.get(), plaintext, &len, ciphertext.data(), narrow_cast<int>(ciphertext.size())),
      "EVP_DecryptUpdate");
}

GcmChunkCipher::Sealer::Sealer(const GcmChunkCipher& cipher)
    : cipher_(cipher), ctx_(EVP_CIPHER_CTX_new()) {}

GcmChunkCipher::Sealer::~Sealer() {
  EVP_CIPHER_CTX_free(ctx_);
}

Status GcmChunkCipher::Sealer::Begin(uint64_t index, bool final) {
  SCHECK(ctx_, InternalError, "EVP_CIPHER_CTX_new failed");
  return cipher_.InitContext(ctx_, /* encrypt= */ true, index, final);
}

Status GcmChunkCipher::Sealer::Update(Slice plaintext, uint8_t* ciphertext) {
  if (plaintext.empty()) {
    return Status::OK();
  }
  int len;
  return CheckOpenSsl(
      EVP_EncryptUpdate(
          ctx_, ciphertext, &len, plaintext.data(), narrow_cast<int>(plaintext.size())),
      "EVP_EncryptUpdate");
}

Status GcmChunkCipher::Sealer::Finish(uint8_t* tag) {
  uint8_t final_buf[EncryptionParams::kBlockSize];
  int len;
  RETURN_NOT_OK(CheckOpenSsl(EVP_EncryptFinal_ex(ctx_, final_buf, &len), "EVP_EncryptFinal_ex"));
  return CheckOpenSsl(
      EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_GET_TAG, kTagSize, tag), "EVP_CTRL_GCM_GET_TAG");
}

Result<std::unique_ptr<GcmRecordCipher>> GcmRecordCipher::Create(const EncryptionParams& params) {
  SCHECK(params.cipher_mode == CipherMode::kGcmRecord, InvalidArgument,
         "Not a GCM record file");
  SCHECK(GcmCipher(params.key_size), InvalidArgument,
         Format("Unsupported key size $0", params.key_size));
  std::unique_ptr<GcmRecordCipher> cipher(new GcmRecordCipher(params));
  if (cipher->nonce_stored_) {
    // A new base for each writable file instance, i.e. each writer session. Readers take the nonce
    // from the record and never use it.
    RETURN_NOT_OK(CheckOpenSsl(RAND_bytes(cipher->base_nonce_, kNonceSize), "RAND_bytes"));
  }
  return cipher;
}

GcmRecordCipher::GcmRecordCipher(const EncryptionParams& params)
    : key_size_(params.key_size), nonce_stored_(params.record_nonce_stored) {
  memcpy(key_, params.key, sizeof(key_));
  static_assert(sizeof(params.nonce) == kNonceSize);
  memcpy(base_nonce_, params.nonce, kNonceSize);
}

void GcmRecordCipher::RecordNonce(uint64_t position, uint8_t* nonce) const {
  memcpy(nonce, base_nonce_, kNonceSize);
  uint8_t position_bytes[sizeof(uint64_t)];
  BigEndian::Store64(position_bytes, position);
  for (size_t i = 0; i < sizeof(position_bytes); ++i) {
    nonce[kNonceSize - sizeof(position_bytes) + i] ^= position_bytes[i];
  }
}

Status GcmRecordCipher::Seal(
    uint64_t position, Slice aad, Slice plaintext, uint8_t* sealed) const {
  uint8_t nonce_buf[kNonceSize];
  uint8_t* nonce = nonce_stored_ ? sealed : nonce_buf;
  RecordNonce(position, nonce);
  uint8_t* ciphertext = sealed + (nonce_stored_ ? kNonceSize : 0);
  uint8_t* tag = ciphertext + plaintext.size();

  auto ctx = VERIFY_RESULT(NewContext());
  RETURN_NOT_OK(CheckOpenSsl(
      EVP_EncryptInit_ex(ctx.get(), GcmCipher(key_size_), nullptr, key_, nonce),
      "EVP_EncryptInit_ex"));
  int len;
  if (!aad.empty()) {
    RETURN_NOT_OK(CheckOpenSsl(
        EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(), narrow_cast<int>(aad.size())),
        "EVP_EncryptUpdate(aad)"));
  }
  if (!plaintext.empty()) {
    RETURN_NOT_OK(CheckOpenSsl(
        EVP_EncryptUpdate(
            ctx.get(), ciphertext, &len, plaintext.data(), narrow_cast<int>(plaintext.size())),
        "EVP_EncryptUpdate"));
  }
  uint8_t final_buf[EncryptionParams::kBlockSize];
  RETURN_NOT_OK(CheckOpenSsl(
      EVP_EncryptFinal_ex(ctx.get(), final_buf, &len), "EVP_EncryptFinal_ex"));
  return CheckOpenSsl(
      EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, kTagSize, tag),
      "EVP_CTRL_GCM_GET_TAG");
}

Status GcmRecordCipher::Open(
    uint64_t position, Slice aad, Slice sealed, uint8_t* plaintext) const {
  SCHECK_GE(sealed.size(), Overhead(), Corruption, "Sealed record is too short");
  uint8_t nonce_buf[kNonceSize];
  const uint8_t* nonce = nonce_buf;
  if (nonce_stored_) {
    nonce = sealed.data();
    sealed.remove_prefix(kNonceSize);
  } else {
    RecordNonce(position, nonce_buf);
  }
  Slice ciphertext = sealed.Prefix(sealed.size() - kTagSize);
  Slice tag = sealed.Suffix(kTagSize);

  auto ctx = VERIFY_RESULT(NewContext());
  RETURN_NOT_OK(CheckOpenSsl(
      EVP_DecryptInit_ex(ctx.get(), GcmCipher(key_size_), nullptr, key_, nonce),
      "EVP_DecryptInit_ex"));
  int len;
  if (!aad.empty()) {
    RETURN_NOT_OK(CheckOpenSsl(
        EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad.data(), narrow_cast<int>(aad.size())),
        "EVP_DecryptUpdate(aad)"));
  }
  if (!ciphertext.empty()) {
    RETURN_NOT_OK(CheckOpenSsl(
        EVP_DecryptUpdate(
            ctx.get(), plaintext, &len, ciphertext.data(), narrow_cast<int>(ciphertext.size())),
        "EVP_DecryptUpdate"));
  }
  RETURN_NOT_OK(CheckOpenSsl(
      EVP_CIPHER_CTX_ctrl(
          ctx.get(), EVP_CTRL_GCM_SET_TAG, kTagSize, const_cast<uint8_t*>(tag.data())),
      "EVP_CTRL_GCM_SET_TAG"));
  uint8_t final_buf[EncryptionParams::kBlockSize];
  if (EVP_DecryptFinal_ex(ctx.get(), final_buf, &len) != 1) {
    return STATUS(Corruption, "AES-GCM record authentication failed");
  }
  return Status::OK();
}

} // namespace yb::encryption
