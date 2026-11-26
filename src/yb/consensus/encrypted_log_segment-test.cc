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

#include <gtest/gtest.h>

#include "yb/consensus/consensus.messages.h"
#include "yb/consensus/log.messages.h"
#include "yb/consensus/log_util.h"

#include "yb/encryption/encrypted_file_factory.h"
#include "yb/encryption/header_manager_impl.h"
#include "yb/encryption/universe_key_manager.h"

#include "yb/util/coding-inl.h"
#include "yb/util/coding.h"
#include "yb/util/crc.h"
#include "yb/util/env.h"
#include "yb/util/flags.h"
#include "yb/util/pb_util.h"
#include "yb/util/random_util.h"
#include "yb/util/record_cipher.h"
#include "yb/util/test_util.h"

DECLARE_string(encryption_algorithm_override);
DECLARE_bool(enable_encryption_gcm);

namespace yb::log {

namespace {

constexpr const char* kTabletId = "encrypted-log-tablet-id";
constexpr int kNumBatches = 3;

} // namespace

// With AES-GCM, every record in a WAL segment is sealed by the log: header, entry batches and
// footer.
class EncryptedLogSegmentTest : public YBTest {
 protected:
  void SetUp() override {
    YBTest::SetUp();
    ASSERT_OK(SET_FLAG(encryption_algorithm_override, "AES_256_GCM"));
    ANNOTATE_UNPROTECTED_WRITE(FLAGS_enable_encryption_gcm) = true;
    auto key = RandomBytes(48);
    universe_key_manager_ = ASSERT_RESULT(encryption::UniverseKeyManager::FromKey(
        "key", Slice(key.data(), key.size())));
    encrypted_env_ = encryption::NewEncryptedEnv(
        encryption::DefaultHeaderManager(universe_key_manager_.get()));
  }

  // Writes a closed segment with kNumBatches entry batches and returns its path.
  Result<std::string> WriteSegment() {
    WritableFileOptions opts;
    opts.encryption_writer_seals_records = true;
    std::string path;
    std::unique_ptr<WritableFile> file;
    RETURN_NOT_OK(encrypted_env_->NewTempWritableFile(
        opts, GetTestPath("wal-XXXXXX"), &path, &file));
    SCHECK(file->record_cipher(), IllegalState, "WAL segment is not in record mode");
    // WAL records store their nonce, since segments are rewritten after a crash.
    SCHECK_EQ(file->record_cipher()->Overhead(), 28U, IllegalState, "Unexpected overhead");
    WritableLogSegment segment(path, std::shared_ptr<WritableFile>(file.release()));

    LogSegmentHeaderPB header;
    header.set_major_version(1);
    header.set_minor_version(0);
    header.set_unused_tablet_id(kTabletId);
    header.set_sequence_number(1);
    header.mutable_deprecated_schema();
    RETURN_NOT_OK(segment.WriteHeader(header));

    for (int i = 0; i < kNumBatches; ++i) {
      LogEntryBatchPB batch;
      batch.set_mono_time(1000 + i);
      auto* entry = batch.add_entry();
      entry->set_type(REPLICATE);
      auto* replicate = entry->mutable_replicate();
      replicate->mutable_id()->set_term(1);
      replicate->mutable_id()->set_index(i + 1);
      replicate->set_hybrid_time(1000 + i);
      replicate->set_op_type(consensus::NO_OP);
      faststring data;
      RETURN_NOT_OK(pb_util::AppendToString(batch, &data));
      RETURN_NOT_OK(segment.WriteEntryBatch(Slice(data)));
    }

    LogSegmentFooterPB footer;
    footer.set_num_entries(kNumBatches);
    RETURN_NOT_OK(segment.WriteIndexWithFooterAndClose(/* log_index= */ nullptr, &footer));
    return path;
  }

  std::unique_ptr<encryption::UniverseKeyManager> universe_key_manager_;
  std::unique_ptr<Env> encrypted_env_;
};

TEST_F(EncryptedLogSegmentTest, SealsEveryRecord) {
  const auto path = ASSERT_RESULT(WriteSegment());

  // The header PB, which holds the tablet ID, is not stored in the clear.
  faststring raw;
  ASSERT_OK(ReadFileToString(Env::Default(), path, &raw));
  ASSERT_EQ(raw.ToString().find(kTabletId), std::string::npos);

  auto segment = ASSERT_RESULT(ReadableLogSegment::Open(encrypted_env_.get(), path, nullptr));
  ASSERT_EQ(segment->header().unused_tablet_id(), kTabletId);
  ASSERT_TRUE(segment->HasFooter());
  ASSERT_EQ(segment->footer().num_entries(), kNumBatches);

  auto read_entries = segment->ReadEntries();
  ASSERT_OK(read_entries.status);
  ASSERT_EQ(read_entries.entries.size(), kNumBatches);
  for (int i = 0; i < kNumBatches; ++i) {
    ASSERT_EQ(read_entries.entries[i]->replicate().id().index(), i + 1);
  }
}

// A modified entry fails authentication even when its CRCs are recomputed, which the CRCs alone
// would not catch.
TEST_F(EncryptedLogSegmentTest, DetectsModifiedEntry) {
  const auto path = ASSERT_RESULT(WriteSegment());
  int64_t first_entry_offset;
  uint64_t encryption_header_size;
  {
    auto segment = ASSERT_RESULT(ReadableLogSegment::Open(encrypted_env_.get(), path, nullptr));
    first_entry_offset = segment->first_entry_offset();
    encryption_header_size = segment->readable_file()->GetEncryptionHeaderSize();
  }

  faststring raw;
  ASSERT_OK(ReadFileToString(Env::Default(), path, &raw));
  uint8_t* entry_header = raw.data() + encryption_header_size + first_entry_offset;
  const uint32_t msg_length = DecodeFixed32(entry_header);
  uint8_t* payload = entry_header + kEntryHeaderSize;
  payload[msg_length / 2] ^= 0x01;
  InlineEncodeFixed32(entry_header + 4, crc::Crc32c(payload, msg_length));
  InlineEncodeFixed32(entry_header + 8, crc::Crc32c(entry_header, 8));
  ASSERT_OK(WriteStringToFile(Env::Default(), Slice(raw), path));

  auto segment = ASSERT_RESULT(ReadableLogSegment::Open(encrypted_env_.get(), path, nullptr));
  auto read_entries = segment->ReadEntries();
  ASSERT_NOK(read_entries.status);
  ASSERT_TRUE(read_entries.status.IsCorruption()) << read_entries.status;
  ASSERT_STR_CONTAINS(read_entries.status.ToString(), "authentication failed");
  ASSERT_TRUE(read_entries.entries.empty());
}

} // namespace yb::log
