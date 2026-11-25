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

#include "yb/encryption/gcm_encrypted_file.h"

#include <vector>

#include "yb/util/flags.h"
#include "yb/util/result.h"
#include "yb/util/status_log.h"
#include "yb/util/status_format.h"

DEFINE_test_flag(bool, encryption_gcm_skip_close_on_destroy, false,
                 "Leave an AES-GCM file without its final chunk when it is destroyed without "
                 "Close, as a crash would.");

namespace yb::encryption {

namespace {

constexpr size_t kTagSize = GcmChunkCipher::kTagSize;

} // namespace

GcmRandomAccessFile::GcmRandomAccessFile(
    std::unique_ptr<yb::RandomAccessFile> file, std::unique_ptr<GcmChunkCipher> cipher,
    uint64_t header_size, bool allow_unauthenticated_tail)
    : RandomAccessFileWrapper(std::move(file)), cipher_(std::move(cipher)),
      header_size_(header_size), allow_unauthenticated_tail_(allow_unauthenticated_tail) {}

Result<GcmRandomAccessFile::Layout> GcmRandomAccessFile::GetLayout() const {
  {
    std::lock_guard l(mutex_);
    if (complete_layout_) {
      return *complete_layout_;
    }
  }
  auto layout = VERIFY_RESULT(ComputeLayout());
  if (layout.complete) {
    std::lock_guard l(mutex_);
    complete_layout_ = layout;
  }
  return layout;
}

Result<GcmRandomAccessFile::Layout> GcmRandomAccessFile::ComputeLayout() const {
  const uint64_t raw_size = VERIFY_RESULT(RandomAccessFileWrapper::Size());
  SCHECK_GE(raw_size, header_size_, Corruption, "File is shorter than its encryption header");
  const uint64_t body = raw_size - header_size_;
  const uint64_t chunk_size = cipher_->chunk_size();
  const uint64_t stride = chunk_size + kTagSize;

  if (body >= kTagSize) {
    // Interpret the last kTagSize bytes as the final chunk, preceded by full chunks and an
    // optional sealed partial chunk.
    const uint64_t before_final = body - kTagSize;
    const uint64_t full_chunks = before_final / stride;
    const uint64_t rem = before_final % stride;
    if (rem == 0 || rem > kTagSize) {
      const uint64_t final_index = full_chunks + (rem == 0 ? 0 : 1);
      uint8_t tag[kTagSize];
      Slice tag_slice;
      RETURN_NOT_OK(RandomAccessFileWrapper::Read(
          header_size_ + before_final, kTagSize, &tag_slice, tag));
      if (tag_slice.size() == kTagSize &&
          cipher_->Open(final_index, /* final= */ true, Slice(), tag_slice, nullptr).ok()) {
        const size_t partial = rem == 0 ? 0 : rem - kTagSize;
        return Layout{
            .full_chunks = full_chunks,
            .complete = true,
            .tail_size = partial,
            .plaintext_size = full_chunks * chunk_size + partial,
        };
      }
    }
  }

  if (!allow_unauthenticated_tail_) {
    return STATUS_FORMAT(
        Corruption, "$0: AES-GCM encrypted file has no valid final chunk", filename());
  }
  // Bytes after the last full chunk, possibly including a sealed partial chunk's tag or a torn
  // final chunk, are returned without authentication; the caller's own format must find where its
  // data ends.
  const uint64_t full_chunks = body / stride;
  const size_t tail = std::min<uint64_t>(body % stride, chunk_size);
  return Layout{
      .full_chunks = full_chunks,
      .complete = false,
      .tail_size = tail,
      .plaintext_size = full_chunks * chunk_size + tail,
  };
}

Result<uint64_t> GcmRandomAccessFile::Size() const {
  return VERIFY_RESULT(GetLayout()).plaintext_size;
}

Status GcmRandomAccessFile::Read(
    uint64_t offset, size_t n, Slice* result, uint8_t* scratch) const {
  const auto layout = VERIFY_RESULT(GetLayout());
  if (offset >= layout.plaintext_size) {
    *result = Slice(scratch, size_t(0));
    return Status::OK();
  }
  n = std::min<uint64_t>(n, layout.plaintext_size - offset);

  const uint64_t chunk_size = cipher_->chunk_size();
  const uint64_t stride = chunk_size + kTagSize;
  std::vector<uint8_t> raw(stride);
  std::vector<uint8_t> plain(chunk_size);

  size_t done = 0;
  while (done < n) {
    const uint64_t pos = offset + done;
    const uint64_t index = pos / chunk_size;
    const size_t offset_in_chunk = pos % chunk_size;
    const size_t chunk_len = index < layout.full_chunks ? chunk_size : layout.tail_size;
    const size_t take = std::min<size_t>(n - done, chunk_len - offset_in_chunk);
    const uint64_t chunk_start = header_size_ + index * stride;
    Slice raw_slice;

    if (index < layout.full_chunks || layout.complete) {
      RETURN_NOT_OK(RandomAccessFileWrapper::Read(
          chunk_start, chunk_len + kTagSize, &raw_slice, raw.data()));
      SCHECK_EQ(raw_slice.size(), chunk_len + kTagSize, Corruption,
                Format("$0: short read of AES-GCM chunk $1", filename(), index));
      RETURN_NOT_OK_PREPEND(
          cipher_->Open(
              index, /* final= */ false, raw_slice.Prefix(chunk_len),
              raw_slice.Suffix(kTagSize), plain.data()),
          filename());
      memcpy(scratch + done, plain.data() + offset_in_chunk, take);
    } else {
      RETURN_NOT_OK(RandomAccessFileWrapper::Read(
          chunk_start + offset_in_chunk, take, &raw_slice, raw.data()));
      SCHECK_EQ(raw_slice.size(), take, Corruption,
                Format("$0: short read of AES-GCM tail", filename()));
      RETURN_NOT_OK(cipher_->DecryptUnauthenticated(
          index, offset_in_chunk, raw_slice, scratch + done));
    }
    done += take;
  }
  *result = Slice(scratch, n);
  return Status::OK();
}

GcmWritableFile::GcmWritableFile(
    std::unique_ptr<yb::WritableFile> file, std::unique_ptr<GcmChunkCipher> cipher)
    : WritableFileWrapper(std::move(file)), cipher_(std::move(cipher)), sealer_(*cipher_) {}

// Some writers, such as RocksDB's WriteStringToFile for CURRENT, rely on the destructor to close
// the file, as PosixWritableFile does. A process that crashes runs no destructor, so its files keep
// their unauthenticated tail.
GcmWritableFile::~GcmWritableFile() {
  if (!closed_ && !FLAGS_TEST_encryption_gcm_skip_close_on_destroy) {
    WARN_NOT_OK(Close(), Format("Failed to close AES-GCM encrypted file $0", filename()));
  }
}

Status GcmWritableFile::SealChunk(bool final, std::string* out) {
  if (!chunk_started_) {
    RETURN_NOT_OK(sealer_.Begin(chunk_index_, final));
  }
  uint8_t tag[kTagSize];
  RETURN_NOT_OK(sealer_.Finish(tag));
  out->append(reinterpret_cast<const char*>(tag), kTagSize);
  ++chunk_index_;
  bytes_in_chunk_ = 0;
  chunk_started_ = false;
  return Status::OK();
}

Status GcmWritableFile::Append(const Slice& data) {
  SCHECK(!closed_, IllegalState, "Append to a closed AES-GCM file");
  if (data.empty()) {
    return Status::OK();
  }
  const size_t chunk_size = cipher_->chunk_size();
  std::string out;
  out.reserve(data.size() + (data.size() / chunk_size + 1) * kTagSize);
  Slice remaining = data;
  while (!remaining.empty()) {
    if (!chunk_started_) {
      RETURN_NOT_OK(sealer_.Begin(chunk_index_, /* final= */ false));
      chunk_started_ = true;
    }
    const size_t take = std::min(remaining.size(), chunk_size - bytes_in_chunk_);
    const size_t out_pos = out.size();
    out.resize(out_pos + take);
    RETURN_NOT_OK(sealer_.Update(
        remaining.Prefix(take), reinterpret_cast<uint8_t*>(out.data() + out_pos)));
    bytes_in_chunk_ += take;
    remaining.remove_prefix(take);
    if (bytes_in_chunk_ == chunk_size) {
      RETURN_NOT_OK(SealChunk(/* final= */ false, &out));
    }
  }
  RETURN_NOT_OK(WritableFileWrapper::Append(Slice(out)));
  plaintext_size_ += data.size();
  return Status::OK();
}

Status GcmWritableFile::AppendSlices(const Slice* slices, size_t num) {
  for (size_t i = 0; i != num; ++i) {
    RETURN_NOT_OK(Append(slices[i]));
  }
  return Status::OK();
}

Status GcmWritableFile::PositionedAppend(const Slice& data, uint64_t offset) {
  return STATUS(NotSupported, "PositionedAppend is not supported for AES-GCM encrypted files");
}

Status GcmWritableFile::Truncate(uint64_t size) {
  // WritableFileWriter::Close truncates to the size it wrote, which is always the current size.
  if (size == plaintext_size_) {
    return Status::OK();
  }
  return STATUS_FORMAT(
      NotSupported, "Cannot truncate AES-GCM encrypted file from $0 to $1 bytes",
      plaintext_size_, size);
}

Status GcmWritableFile::Close() {
  if (!closed_) {
    std::string out;
    if (bytes_in_chunk_ > 0) {
      RETURN_NOT_OK(SealChunk(/* final= */ false, &out));
    }
    RETURN_NOT_OK(SealChunk(/* final= */ true, &out));
    RETURN_NOT_OK(WritableFileWrapper::Append(Slice(out)));
    closed_ = true;
  }
  return WritableFileWrapper::Close();
}

GcmRecordRandomAccessFile::GcmRecordRandomAccessFile(
    std::unique_ptr<yb::RandomAccessFile> file, std::unique_ptr<GcmRecordCipher> cipher,
    uint64_t header_size)
    : RandomAccessFileWrapper(std::move(file)), cipher_(std::move(cipher)),
      header_size_(header_size) {}

Status GcmRecordRandomAccessFile::Read(
    uint64_t offset, size_t n, Slice* result, uint8_t* scratch) const {
  return RandomAccessFileWrapper::Read(offset + header_size_, n, result, scratch);
}

Result<uint64_t> GcmRecordRandomAccessFile::Size() const {
  const auto raw_size = VERIFY_RESULT(RandomAccessFileWrapper::Size());
  SCHECK_GE(raw_size, header_size_, Corruption, "File is shorter than its encryption header");
  return raw_size - header_size_;
}

GcmRecordWritableFile::GcmRecordWritableFile(
    std::unique_ptr<yb::WritableFile> file, std::unique_ptr<GcmRecordCipher> cipher,
    uint64_t header_size)
    : WritableFileWrapper(std::move(file)), cipher_(std::move(cipher)),
      header_size_(header_size) {}

Result<std::unique_ptr<yb::RandomAccessFile>> NewGcmRandomAccessFile(
    std::unique_ptr<yb::RandomAccessFile> underlying, const FileEncryptionHeader& header) {
  if (header.params->cipher_mode == CipherMode::kGcmRecord) {
    return std::make_unique<GcmRecordRandomAccessFile>(
        std::move(underlying), VERIFY_RESULT(GcmRecordCipher::Create(*header.params)),
        header.header_size);
  }
  auto cipher = VERIFY_RESULT(GcmChunkCipher::Create(*header.params));
  return std::make_unique<GcmRandomAccessFile>(
      std::move(underlying), std::move(cipher), header.header_size,
      header.params->allow_unauthenticated_tail);
}

Result<std::unique_ptr<yb::WritableFile>> NewGcmWritableFile(
    std::unique_ptr<yb::WritableFile> underlying, const EncryptionParams& params,
    const std::string& header) {
  if (params.cipher_mode == CipherMode::kGcmRecord) {
    auto cipher = VERIFY_RESULT(GcmRecordCipher::Create(params));
    RETURN_NOT_OK(underlying->Append(header));
    return std::make_unique<GcmRecordWritableFile>(
        std::move(underlying), std::move(cipher), header.size());
  }
  auto cipher = VERIFY_RESULT(GcmChunkCipher::Create(params));
  RETURN_NOT_OK(underlying->Append(header));
  return std::make_unique<GcmWritableFile>(std::move(underlying), std::move(cipher));
}

Result<std::unique_ptr<yb::WritableFile>> ReopenGcmRecordWritableFile(
    std::unique_ptr<yb::WritableFile> underlying, const FileEncryptionHeader& header) {
  return std::make_unique<GcmRecordWritableFile>(
      std::move(underlying), VERIFY_RESULT(GcmRecordCipher::Create(*header.params)),
      header.header_size);
}

GcmSequentialFile::GcmSequentialFile(std::unique_ptr<yb::RandomAccessFile> file)
    : file_(std::move(file)) {}

Status GcmSequentialFile::Read(size_t n, Slice* result, uint8_t* scratch) {
  RETURN_NOT_OK(file_->Read(offset_, n, result, scratch));
  offset_ += result->size();
  return Status::OK();
}

Status GcmSequentialFile::Skip(uint64_t n) {
  offset_ += n;
  return Status::OK();
}

} // namespace yb::encryption
