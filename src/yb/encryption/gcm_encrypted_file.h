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
#include <mutex>
#include <optional>

#include "yb/encryption/gcm_cipher.h"

#include "yb/util/file_system.h"

namespace yb::encryption {

// On-disk layout after the encryption header, with B = chunk size and T = 16-byte tag:
//
//   [chunk 0: B bytes][T] ... [chunk n-1: B bytes][T] [partial chunk: 1..B-1 bytes][T] [final: T]
//
// The partial chunk is present only when the plaintext size is not a multiple of B. The final
// chunk is empty, authenticated with the final flag, and written on Close, so a complete file ends
// with it. A file without it was cut short by a crash: its full chunks are authenticated and the
// bytes after them are decrypted without authentication, which is accepted only for files whose
// header sets allow_unauthenticated_tail.
class GcmRandomAccessFile : public RandomAccessFileWrapper {
 public:
  GcmRandomAccessFile(
      std::unique_ptr<yb::RandomAccessFile> file, std::unique_ptr<GcmChunkCipher> cipher,
      uint64_t header_size, bool allow_unauthenticated_tail);

  Status Read(uint64_t offset, size_t n, Slice* result, uint8_t* scratch) const override;

  Result<uint64_t> Size() const override;

  uint64_t GetEncryptionHeaderSize() const override { return header_size_; }

  bool IsEncrypted() const override { return true; }

 private:
  struct Layout {
    uint64_t full_chunks;
    // Whether the file ends with a valid final chunk.
    bool complete;
    // Complete: plaintext bytes in the sealed partial chunk, 0 if there is none.
    // Not complete: plaintext bytes after the full chunks, which are not authenticated.
    size_t tail_size;
    uint64_t plaintext_size;
  };

  Result<Layout> GetLayout() const;
  Result<Layout> ComputeLayout() const;

  std::unique_ptr<GcmChunkCipher> cipher_;
  const uint64_t header_size_;
  const bool allow_unauthenticated_tail_;

  // A complete file never changes, so its layout is computed once.
  mutable std::mutex mutex_;
  mutable std::optional<Layout> complete_layout_;
};

// Encrypts as data is appended, writing each chunk's tag once the chunk is full and the partial and
// final chunks on Close. Data appended since the last full chunk is durable after Sync but not
// authenticated until Close.
class GcmWritableFile : public WritableFileWrapper {
 public:
  GcmWritableFile(std::unique_ptr<WritableFile> file, std::unique_ptr<GcmChunkCipher> cipher);
  ~GcmWritableFile();

  Status Append(const Slice& data) override;
  Status AppendSlices(const Slice* slices, size_t num) override;
  Status PositionedAppend(const Slice& data, uint64_t offset) override;
  Status Truncate(uint64_t size) override;
  Status Close() override;
  uint64_t Size() const override { return plaintext_size_; }

  // Preallocating would extend the file with zeros, which a reader cannot tell apart from a corrupt
  // chunk.
  Status PreAllocate(uint64_t size) override { return Status::OK(); }

 protected:
  Status Allocate(uint64_t offset, uint64_t len) override { return Status::OK(); }

 private:
  Status SealChunk(bool final, std::string* out);

  std::unique_ptr<GcmChunkCipher> cipher_;
  GcmChunkCipher::Sealer sealer_;
  uint64_t chunk_index_ = 0;
  size_t bytes_in_chunk_ = 0;
  bool chunk_started_ = false;
  uint64_t plaintext_size_ = 0;
  bool closed_ = false;
};

// A kGcmRecord file as read by its owner: the file layer only skips the encryption header, and the
// reader opens each record with record_cipher().
class GcmRecordRandomAccessFile : public RandomAccessFileWrapper {
 public:
  GcmRecordRandomAccessFile(
      std::unique_ptr<yb::RandomAccessFile> file, std::unique_ptr<GcmRecordCipher> cipher,
      uint64_t header_size);

  Status Read(uint64_t offset, size_t n, Slice* result, uint8_t* scratch) const override;
  Result<uint64_t> Size() const override;
  uint64_t GetEncryptionHeaderSize() const override { return header_size_; }
  bool IsEncrypted() const override { return true; }
  const RecordCipher* record_cipher() const override { return cipher_.get(); }

 private:
  std::unique_ptr<GcmRecordCipher> cipher_;
  const uint64_t header_size_;
};

// A kGcmRecord file as written by its owner, which seals each record with record_cipher() before
// appending it. Unlike chunked files, it can be reopened for append and preallocated: nothing in
// the file layer depends on where the data ends.
class GcmRecordWritableFile : public WritableFileWrapper {
 public:
  GcmRecordWritableFile(
      std::unique_ptr<yb::WritableFile> file, std::unique_ptr<GcmRecordCipher> cipher,
      uint64_t header_size);

  uint64_t Size() const override { return WritableFileWrapper::Size() - header_size_; }
  const RecordCipher* record_cipher() const override { return cipher_.get(); }

 private:
  std::unique_ptr<GcmRecordCipher> cipher_;
  const uint64_t header_size_;
};

// Sequential reads through a GcmRandomAccessFile or GcmRecordRandomAccessFile.
class GcmSequentialFile : public yb::SequentialFile {
 public:
  explicit GcmSequentialFile(std::unique_ptr<yb::RandomAccessFile> file);

  Status Read(size_t n, Slice* result, uint8_t* scratch) override;
  Status Skip(uint64_t n) override;
  const std::string& filename() const override { return file_->filename(); }

 private:
  std::unique_ptr<yb::RandomAccessFile> file_;
  uint64_t offset_ = 0;
};

} // namespace yb::encryption
