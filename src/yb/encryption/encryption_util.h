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

#include <stdint.h>

#include <cstdarg>
#include <optional>
#include <string>
#include <vector>

#include "yb/encryption/cipher_stream.h"
#include "yb/encryption/encryption.pb.h"
#include "yb/encryption/encryption_fwd.h"
#include "yb/encryption/header_manager.h"

#include "yb/util/status_fwd.h"
#include "yb/util/file_system.h"
#include "yb/util/result.h"
#include "yb/util/status_format.h"

namespace yb {
namespace encryption {

class EncryptionParamsPB;
class HeaderManager;
class BlockAccessCipherStream;

// Struct generated for encryption status of existing files.
struct FileEncryptionStatus {
  bool is_encrypted;
  uint32_t header_size;
};

// Encryption params consisting of key size 16, 24, or 32, nonce size 12, and counter size 4.
struct EncryptionParams {
  static constexpr uint32_t kBlockSize = 16;
  static constexpr uint32_t kMaxKeySize = 32;
  static constexpr uint32_t kAes128KeySize = 16;
  static constexpr uint32_t kAes256KeySize = 32;
  // A universe key blob is the nonce and initial counter followed by the AES key; see FromSlice.
  static constexpr uint32_t kUniverseKeyPrefixSize = kBlockSize;

  uint8_t key[kMaxKeySize];
  // Nonce of 12 bytes for encryption.
  uint8_t nonce[kBlockSize - sizeof(uint32_t)];
  // Counter of 4 bytes incremented for each block.
  uint32_t counter;
  uint32_t key_size;

  // When computing counter increment, do we want to overflow the counter into the rest of the
  // initialization vector as part of the new format.
  bool openssl_compatible_counter_overflow;

  CipherMode cipher_mode = CipherMode::kCtr;
  // The following apply to kGcm only; see EncryptionParamsPB.
  uint32_t gcm_chunk_size = 0;
  // kGcmRecord only; see EncryptionParamsPB.
  bool record_nonce_stored = false;

  void ToEncryptionParamsPB(EncryptionParamsPB* encryption_header) const;

  static Result<std::unique_ptr<EncryptionParams>> FromEncryptionParamsPB(
      const EncryptionParamsPB& encryption_header);

  // Given a slice, convert contents to encryption params. Used to read latest universe key.
  static Result<std::unique_ptr<EncryptionParams>> FromSlice(const Slice& s);

  // Random key, nonce and counter, with the key size and cipher of algorithm. For AES-GCM,
  // gcm_layout picks how the file is sealed, and chunked files take their chunk size from
  // encryption_gcm_chunk_size_bytes.
  static Result<std::unique_ptr<EncryptionParams>> NewEncryptionParams(
      EncryptionAlgorithmPB algorithm, GcmFileLayout gcm_layout = GcmFileLayout::kChunks);

  static Status IsValidKeySize(size_t size);

  bool Equals(const EncryptionParams& other);
};

typedef std::unique_ptr<EncryptionParams> EncryptionParamsPtr;

// Algorithms are named by their EncryptionAlgorithmPB value without the ENCRYPTION_ALGORITHM_
// prefix, such as AES_256_CTR.
std::vector<std::string> EncryptionAlgorithmNames();
Result<EncryptionAlgorithmPB> ParseEncryptionAlgorithm(const std::string& name);
std::string EncryptionAlgorithmName(EncryptionAlgorithmPB algorithm);

// Size of the data keys of new files encrypted with algorithm.
Result<uint32_t> DataKeySize(EncryptionAlgorithmPB algorithm);

// kCtr or kGcm. NotSupported for a value this release does not know.
Result<CipherMode> AlgorithmCipherMode(EncryptionAlgorithmPB algorithm);

// The CTR algorithm with the same key size as algorithm.
Result<EncryptionAlgorithmPB> CtrAlgorithmWithKeySizeOf(EncryptionAlgorithmPB algorithm);

// encryption_new_universe_algorithm.
Result<EncryptionAlgorithmPB> NewUniverseEncryptionAlgorithm();

// encryption_algorithm_override, or std::nullopt when it is empty.
std::optional<EncryptionAlgorithmPB> EncryptionAlgorithmOverride();

// Flag callback of both algorithm flags.
void ReloadEncryptionAlgorithmFlags();

// Size of a universe key blob (nonce, counter and AES key) whose key is as long as the data keys
// of algorithm.
Result<uint32_t> UniverseKeySize(EncryptionAlgorithmPB algorithm);

// UniverseKeySize for encryption_new_universe_algorithm.
uint32_t DefaultUniverseKeySize();

// Since this will typically be passed in by an external user (YW or yb-admin), UniverseKeyId
// will be a generic string for ease of use.
using UniverseKeyId = std::string;

struct UniverseKeyParams {
  UniverseKeyId version_id;
  EncryptionParamsPtr params;
};

// Thread local buffer for any encryption operations.
class EncryptionBuffer {
 public:
  void* GetBuffer(size_t size_needed);
  ~EncryptionBuffer();
  static EncryptionBuffer* Get();
 private:
  size_t size = 0;
  void* buffer = nullptr;
};


struct FileEncryptionHeader {
  EncryptionParamsPtr params;
  uint32_t header_size;
  UniverseKeyId universe_key_id;
};

// Reads and decodes a file's encryption header. Returns nullopt if the file is not encrypted.
// universe_key_id, if given, is set as soon as the header names its universe key, so a caller can
// tell which key is missing when decoding the data key fails.
template <typename BufType, typename Readable>
Result<std::optional<FileEncryptionHeader>> ReadFileEncryptionHeader(
    HeaderManager* header_manager, Readable* underlying_r,
    std::string* universe_key_id = nullptr) {
  if (!header_manager) {
    return STATUS(InvalidArgument, "header_manager must be non-null.");
  }

  Slice encryption_info;
  auto metadata_start = header_manager->GetEncryptionMetadataStartIndex();
  auto buf = std::unique_ptr<BufType[]>(new BufType[metadata_start]);
  RETURN_NOT_OK(underlying_r->Read(0, metadata_start, &encryption_info, buf.get()));
  auto encryption_status = VERIFY_RESULT(
      header_manager->GetFileEncryptionStatusFromPrefix(encryption_info));
  if (!encryption_status.is_encrypted) {
    return std::nullopt;
  }

  FileEncryptionHeader header;
  header.header_size = metadata_start + encryption_status.header_size;
  buf = std::unique_ptr<BufType[]>(new BufType[header.header_size]);
  RETURN_NOT_OK(underlying_r->Read(
      metadata_start, encryption_status.header_size, &encryption_info, buf.get()));
  auto params = header_manager->DecodeEncryptionParamsFromEncryptionMetadata(
      encryption_info, &header.universe_key_id);
  if (universe_key_id) {
    *universe_key_id = header.universe_key_id;
  }
  header.params = VERIFY_RESULT(std::move(params));
  return header;
}

// Given a readable CTR-encrypted file, generate a cipher stream and header size for that file.
// Returns NotSupported for a GCM file, which must be read through NewGcmRandomAccessFile.
template <typename BufType, typename Readable>
Result<bool> GetEncryptionInfoFromFile(HeaderManager* header_manager,
                                       Readable* underlying_r,
                                       std::unique_ptr<BlockAccessCipherStream>* stream,
                                       uint32_t* header_size,
                                       std::string* universe_key_id = nullptr) {
  auto header = VERIFY_RESULT(ReadFileEncryptionHeader<BufType>(
      header_manager, underlying_r, universe_key_id));
  if (!header) {
    return false;
  }
  SCHECK(header->params->cipher_mode == CipherMode::kCtr, NotSupported,
         "File is encrypted with AES-GCM");
  *header_size = header->header_size;
  *stream = std::make_unique<BlockAccessCipherStream>(std::move(header->params));
  RETURN_NOT_OK((*stream)->Init());
  return true;
}

// Defined in gcm_encrypted_file.cc. Both handle chunked (kGcm) and record (kGcmRecord) files.
Result<std::unique_ptr<yb::RandomAccessFile>> NewGcmRandomAccessFile(
    std::unique_ptr<yb::RandomAccessFile> underlying, const FileEncryptionHeader& header);
// Writes header to underlying and returns a file that encrypts what is appended to it, or, for
// kGcmRecord, that exposes the record cipher to the writer.
Result<std::unique_ptr<yb::WritableFile>> NewGcmWritableFile(
    std::unique_ptr<yb::WritableFile> underlying, const EncryptionParams& params,
    const std::string& header);
// Continues appending to a kGcmRecord file. underlying must be positioned after the existing
// contents, header included.
Result<std::unique_ptr<yb::WritableFile>> ReopenGcmRecordWritableFile(
    std::unique_ptr<yb::WritableFile> underlying, const FileEncryptionHeader& header);

Status CompleteCreateEncryptionInfoForWrite(
    const std::string& header, std::unique_ptr<EncryptionParams> encryption_params,
    std::unique_ptr<BlockAccessCipherStream>* stream, uint32_t* header_size);

// Given a writable file, generate a new stream and header for that file.
template <typename Writable>
Status CreateEncryptionInfoForWrite(HeaderManager* header_manager,
                                    Writable* underlying_w,
                                    std::unique_ptr<BlockAccessCipherStream>* stream,
                                    uint32_t* header_size) {
  auto algorithm = VERIFY_RESULT(header_manager->GetEncryptionAlgorithm());
  auto encryption_params = VERIFY_RESULT(EncryptionParams::NewEncryptionParams(algorithm));
  std::string header = VERIFY_RESULT(
      header_manager->SerializeEncryptionParams(*encryption_params.get()));
  RETURN_NOT_OK(underlying_w->Append(header));
  return CompleteCreateEncryptionInfoForWrite(
      header, std::move(encryption_params), stream, header_size);
}

template <typename EncryptedFile, typename BufType, typename ReadablePtr>
Status CreateRandomAccessFile(ReadablePtr* result,
                              HeaderManager* header_manager,
                              ReadablePtr underlying) {
  result->reset();
  auto header = VERIFY_RESULT(ReadFileEncryptionHeader<BufType>(header_manager, underlying.get()));
  if (!header) {
    *result = std::move(underlying);
    return Status::OK();
  }

  if (header->params->cipher_mode != CipherMode::kCtr) {
    *result = VERIFY_RESULT(NewGcmRandomAccessFile(std::move(underlying), *header));
    return Status::OK();
  }

  auto stream = VERIFY_RESULT(BlockAccessCipherStream::FromEncryptionParams(
      std::move(header->params)));
  result->reset(new EncryptedFile(std::move(underlying), std::move(stream), header->header_size));
  return Status::OK();
}

template <typename EncryptedFile, typename WritablePtr>
Status CreateWritableFile(WritablePtr* result,
                          HeaderManager* header_manager,
                          WritablePtr underlying,
                          GcmFileLayout gcm_layout = GcmFileLayout::kChunks) {
  result->reset();
  if (!VERIFY_RESULT(header_manager->IsEncryptionEnabled())) {
    *result = std::move(underlying);
    return Status::OK();
  }

  const auto algorithm = VERIFY_RESULT(header_manager->GetEncryptionAlgorithm());
  if (VERIFY_RESULT(AlgorithmCipherMode(algorithm)) == CipherMode::kGcm) {
    auto params = VERIFY_RESULT(EncryptionParams::NewEncryptionParams(algorithm, gcm_layout));
    auto header = VERIFY_RESULT(header_manager->SerializeEncryptionParams(*params));
    *result = VERIFY_RESULT(NewGcmWritableFile(std::move(underlying), *params, header));
    return Status::OK();
  }

  std::unique_ptr<BlockAccessCipherStream> stream;
  uint32_t header_size = 0;
  RETURN_NOT_OK(CreateEncryptionInfoForWrite(
      header_manager, underlying.get(), &stream, &header_size));
  result->reset(new EncryptedFile(std::move(underlying), std::move(stream), header_size));
  return Status::OK();
}

Result<uint32_t> GetHeaderSize(SequentialFile* file, HeaderManager* header_manager);

} // namespace encryption
} // namespace yb
