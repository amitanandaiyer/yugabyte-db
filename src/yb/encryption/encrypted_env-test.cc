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

#include <string>

#include "yb/util/logging.h"
#include <gtest/gtest.h>

#include "yb/encryption/encrypted_file_factory.h"
#include "yb/encryption/encryption_test_util.h"
#include "yb/encryption/encryption_util.h"
#include "yb/encryption/header_manager_mock_impl.h"

#include "yb/gutil/casts.h"

#include "yb/util/flags.h"
#include "yb/util/random_util.h"
#include "yb/util/record_cipher.h"
#include "yb/util/status_log.h"
#include "yb/util/status_fwd.h"
#include "yb/util/test_macros.h"
#include "yb/util/test_util.h"

DECLARE_uint32(encryption_gcm_chunk_size_bytes);
DECLARE_bool(TEST_encryption_gcm_skip_close_on_destroy);

using std::string;

namespace yb {
namespace encryption {

constexpr uint32_t kDataSize = 1000;

class TestEncryptedEnv : public YBTest {};

TEST_F(TestEncryptedEnv, FileOps) {
  auto header_manager = GetMockHeaderManager();
  HeaderManager* hm_ptr = header_manager.get();

  auto env = NewEncryptedEnv(std::move(header_manager));
  auto fname_template = "test-fileXXXXXX";
  auto bytes = RandomBytes(kDataSize*2);
  Slice first_half_data(bytes.data(), kDataSize);
  Slice second_half_data(bytes.data()+kDataSize, kDataSize);
  Slice total_data(bytes.data(), kDataSize*2);

  for (bool encrypted : {false, true}) {
    down_cast<HeaderManagerMockImpl*>(hm_ptr)->SetFileEncryption(encrypted);

    string fname;
    std::unique_ptr<WritableFile> writable_file;
    ASSERT_OK(env->NewTempWritableFile(
        WritableFileOptions(), fname_template, &fname, &writable_file));
    TestWrites(writable_file.get(), first_half_data);

    std::unique_ptr<yb::RandomAccessFile> ra_file;
    ASSERT_OK(env->NewRandomAccessFile(fname, &ra_file));
    TestRandomAccessReads<uint8_t>(ra_file.get(), first_half_data);

    auto opt = WritableFileOptions();
    opt.mode = EnvWrapper::OPEN_EXISTING;
    opt.initial_offset = kDataSize;
    ASSERT_OK(env->NewWritableFile(opt, fname, &writable_file));
    ASSERT_OK(writable_file->Append(second_half_data));

    ASSERT_OK(env->NewRandomAccessFile(fname, &ra_file));
    TestRandomAccessReads<uint8_t>(ra_file.get(), total_data);

    ASSERT_OK(env->DeleteFile(fname));
  }
}

class TestGcmEncryptedEnv : public YBTest {
 protected:
  void SetUp() override {
    YBTest::SetUp();
    ANNOTATE_UNPROTECTED_WRITE(FLAGS_encryption_gcm_chunk_size_bytes) = kChunkSize;
    auto header_manager = GetMockHeaderManager();
    auto* mock = down_cast<HeaderManagerMockImpl*>(header_manager.get());
    mock->SetFileEncryption(true);
    mock->SetEncryptionAlgorithm(ENCRYPTION_ALGORITHM_AES_256_GCM);
    env_ = NewEncryptedEnv(std::move(header_manager));
  }

  // Writes data in random-sized appends and returns the file name.
  string WriteFile(const Slice& data, bool close) {
    WritableFileOptions opts;
    string fname;
    std::unique_ptr<WritableFile> file;
    CHECK_OK(env_->NewTempWritableFile(opts, GetTestPath("gcm-XXXXXX"), &fname, &file));
    if (!data.empty()) {
      TestWrites(file.get(), data);
    }
    CHECK_EQ(file->Size(), data.size());
    if (close) {
      CHECK_OK(file->Close());
    } else {
      // Destroy the file the way a crash would, without writing the final chunk.
      CHECK_OK(file->Sync());
      ANNOTATE_UNPROTECTED_WRITE(FLAGS_TEST_encryption_gcm_skip_close_on_destroy) = true;
      file.reset();
      ANNOTATE_UNPROTECTED_WRITE(FLAGS_TEST_encryption_gcm_skip_close_on_destroy) = false;
    }
    return fname;
  }

  void ModifyRawFile(const string& fname, const std::function<void(string*)>& modify) {
    faststring raw;
    ASSERT_OK(ReadFileToString(Env::Default(), fname, &raw));
    string contents = raw.ToString();
    modify(&contents);
    ASSERT_OK(WriteStringToFile(Env::Default(), Slice(contents), fname));
  }

  static constexpr uint32_t kChunkSize = 64;
  std::unique_ptr<Env> env_;
};

TEST_F(TestGcmEncryptedEnv, WriteRead) {
  // Sizes around chunk boundaries, including an empty file.
  for (size_t size : {0UL, 1UL, 63UL, 64UL, 65UL, 640UL, 1000UL}) {
    auto bytes = RandomBytes(size);
    Slice data(bytes.data(), size);
    auto fname = WriteFile(data, /* close= */ true);

    std::unique_ptr<RandomAccessFile> file;
    ASSERT_OK(env_->NewRandomAccessFile(fname, &file));
    ASSERT_EQ(ASSERT_RESULT(file->Size()), size);
    if (size > 0) {
      TestRandomAccessReads<uint8_t>(file.get(), data);
    }
    // The raw file holds a tag per chunk, so its size differs from the plaintext size.
    ASSERT_GT(ASSERT_RESULT(Env::Default()->GetFileSize(fname)), size);
  }
}

TEST_F(TestGcmEncryptedEnv, DetectsModifiedChunk) {
  auto bytes = RandomBytes(1000);
  auto fname = WriteFile(Slice(bytes.data(), bytes.size()), /* close= */ true);
  const auto header_size = [&] {
    std::unique_ptr<RandomAccessFile> file;
    CHECK_OK(env_->NewRandomAccessFile(fname, &file));
    return file->GetEncryptionHeaderSize();
  }();
  // Flip a bit in the third chunk.
  ASSERT_NO_FATALS(ModifyRawFile(fname, [&](string* raw) {
    (*raw)[header_size + 2 * (kChunkSize + 16) + 5] ^= 0x01;
  }));

  std::unique_ptr<RandomAccessFile> file;
  ASSERT_OK(env_->NewRandomAccessFile(fname, &file));
  uint8_t buf[1000];
  Slice result;
  ASSERT_OK(file->Read(0, 2 * kChunkSize, &result, buf));
  auto s = file->Read(2 * kChunkSize, 10, &result, buf);
  ASSERT_TRUE(s.IsCorruption()) << s;
}

TEST_F(TestGcmEncryptedEnv, DetectsTruncation) {
  auto bytes = RandomBytes(10 * kChunkSize);
  auto fname = WriteFile(Slice(bytes.data(), bytes.size()), /* close= */ true);
  // Drop the final chunk and the last data chunk: what remains is a valid sequence of chunks.
  ASSERT_NO_FATALS(ModifyRawFile(fname, [&](string* raw) {
    raw->resize(raw->size() - 16 - (kChunkSize + 16));
  }));
  std::unique_ptr<RandomAccessFile> file;
  auto s = env_->NewRandomAccessFile(fname, &file);
  if (s.ok()) {
    s = ResultToStatus(file->Size());
  }
  ASSERT_TRUE(s.IsCorruption()) << s;
}

// A chunked file cut short by a crash has no final chunk, which readers report as corruption.
// RocksDB MANIFEST files are the exception; see EncryptedGcmSSTableTest.ManifestTail.
TEST_F(TestGcmEncryptedEnv, MissingFinalChunk) {
  auto bytes = RandomBytes(10 * kChunkSize + 17);
  auto fname = WriteFile(Slice(bytes.data(), bytes.size()), /* close= */ false);
  std::unique_ptr<RandomAccessFile> file;
  auto s = env_->NewRandomAccessFile(fname, &file);
  if (s.ok()) {
    s = ResultToStatus(file->Size());
  }
  ASSERT_TRUE(s.IsCorruption()) << s;
}

TEST_F(TestGcmEncryptedEnv, ReopenForAppendNotSupported) {
  auto bytes = RandomBytes(100);
  auto fname = WriteFile(Slice(bytes.data(), bytes.size()), /* close= */ false);
  WritableFileOptions opts;
  opts.mode = Env::OPEN_EXISTING;
  opts.initial_offset = 50;
  std::unique_ptr<WritableFile> file;
  auto s = env_->NewWritableFile(opts, fname, &file);
  ASSERT_TRUE(s.IsNotSupported()) << s;
}

// A file whose writer seals its own records: the file layer stores them as written, and readers and
// a writer reopening the file get the same record cipher.
TEST_F(TestGcmEncryptedEnv, RecordFile) {
  WritableFileOptions opts;
  opts.encryption_writer_seals_records = true;
  string fname;
  std::unique_ptr<WritableFile> writable;
  ASSERT_OK(env_->NewTempWritableFile(opts, GetTestPath("gcm-record-XXXXXX"), &fname, &writable));
  ASSERT_NE(writable->record_cipher(), nullptr);
  const auto overhead = writable->record_cipher()->Overhead();

  // Seals a record with its offset as the AAD and appends it.
  auto append_record = [&](WritableFile* file, const string& plaintext) {
    const uint64_t offset = file->Size();
    string sealed(plaintext.size() + overhead, '\0');
    ASSERT_OK(file->record_cipher()->Seal(
        offset, Slice(reinterpret_cast<const char*>(&offset), sizeof(offset)), plaintext,
        reinterpret_cast<uint8_t*>(sealed.data())));
    ASSERT_OK(file->Append(sealed));
  };
  const std::vector<string> records = {"first record", string(5000, 'x'), "third"};
  ASSERT_NO_FATALS(append_record(writable.get(), records[0]));
  ASSERT_NO_FATALS(append_record(writable.get(), records[1]));
  ASSERT_OK(writable->Sync());
  writable.reset();

  // Reopen for append after the second record, as the log does after a crash.
  opts.mode = Env::OPEN_EXISTING;
  opts.initial_offset = records[0].size() + records[1].size() + 2 * overhead;
  ASSERT_OK(env_->NewWritableFile(opts, fname, &writable));
  ASSERT_NE(writable->record_cipher(), nullptr);
  ASSERT_EQ(writable->Size(), *opts.initial_offset);
  ASSERT_NO_FATALS(append_record(writable.get(), records[2]));
  ASSERT_OK(writable->Close());

  std::unique_ptr<RandomAccessFile> file;
  ASSERT_OK(env_->NewRandomAccessFile(fname, &file));
  const auto* cipher = file->record_cipher();
  ASSERT_NE(cipher, nullptr);
  uint64_t offset = 0;
  for (const auto& record : records) {
    const size_t sealed_size = record.size() + overhead;
    std::vector<uint8_t> sealed(sealed_size), plain(record.size());
    Slice slice;
    ASSERT_OK(file->Read(offset, sealed_size, &slice, sealed.data()));
    Slice aad(reinterpret_cast<const char*>(&offset), sizeof(offset));
    ASSERT_OK(cipher->Open(offset, aad, slice, plain.data()));
    ASSERT_EQ(Slice(plain.data(), plain.size()), Slice(record));

    // Wrong position or modified bytes fail authentication.
    const uint64_t wrong_offset = offset + 1;
    ASSERT_TRUE(cipher->Open(
        offset, Slice(reinterpret_cast<const char*>(&wrong_offset), sizeof(wrong_offset)), slice,
        plain.data()).IsCorruption());
    sealed[sealed_size / 2] ^= 0x01;
    ASSERT_TRUE(
        cipher->Open(offset, aad, Slice(sealed.data(), sealed_size), plain.data()).IsCorruption());
    offset += sealed_size;
  }
  ASSERT_EQ(ASSERT_RESULT(file->Size()), offset);
}

} // namespace encryption
} // namespace yb
