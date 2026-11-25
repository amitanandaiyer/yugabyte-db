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

#include "yb/util/logging.h"
#include <gtest/gtest.h>

#include "yb/encryption/encrypted_file.h"
#include "yb/encryption/encryption_util.h"
#include "yb/encryption/header_manager.h"
#include "yb/encryption/header_manager_impl.h"
#include "yb/encryption/universe_key_manager.h"

#include "yb/rocksdb/db/dbformat.h"
#include "yb/rocksdb/table/block_based_table_factory.h"
#include "yb/rocksdb/table/internal_iterator.h"
#include "yb/rocksdb/table/table_builder.h"
#include "yb/rocksdb/util/file_reader_writer.h"

#include "yb/rocksutil/rocksdb_encrypted_file_factory.h"

#include "yb/tserver/universe_key_test_util.h"

#include "yb/util/format.h"
#include "yb/util/path_util.h"
#include "yb/util/record_cipher.h"
#include "yb/util/random_util.h"
#include "yb/util/status_fwd.h"
#include "yb/util/test_util.h"

using std::string;

using namespace std::literals;

using yb::tserver::GenerateTestUniverseKeyManager;

DECLARE_int64(encryption_counter_min);
DECLARE_int64(encryption_counter_max);
DECLARE_bool(TEST_encryption_use_openssl_compatible_counter_overflow);
DECLARE_string(encryption_algorithm_override);
DECLARE_bool(enable_encryption_gcm);
DECLARE_bool(TEST_encryption_gcm_skip_close_on_destroy);

namespace yb {

namespace {

std::string GetKey(int i) {
  return Format("key$0SSSSSSSS", ZeroPadded(i, 9));
}

std::string GetValue(int i) {
  return Format("value%d", i);
}

}  // anonymous namespace

class EncryptedSSTableTest : public YBTest, public testing::WithParamInterface<bool> {
 protected:
  void CounterOverflow(
      int num_keys, int64_t initial_counter);
};

INSTANTIATE_TEST_CASE_P(
    UseOpensslCompatibleCounterOverflow, EncryptedSSTableTest, ::testing::Bool());

void EncryptedSSTableTest::CounterOverflow(
    int num_keys, int64_t initial_counter) {
  ANNOTATE_UNPROTECTED_WRITE(FLAGS_encryption_counter_min) = initial_counter;
  ANNOTATE_UNPROTECTED_WRITE(FLAGS_encryption_counter_max) = initial_counter;
  ANNOTATE_UNPROTECTED_WRITE(
      FLAGS_TEST_encryption_use_openssl_compatible_counter_overflow) = GetParam();

  string test_dir;
  ASSERT_OK(Env::Default()->GetTestDirectory(&test_dir));

  rocksdb::Options opts;
  const rocksdb::ImmutableCFOptions imoptions(opts);
  auto ikc = std::make_shared<rocksdb::InternalKeyComparator>(opts.comparator);
  std::vector<std::unique_ptr<rocksdb::IntTblPropCollectorFactory> >
    block_based_table_factories;
  rocksdb::CompressionOptions compression_opts;
  rocksdb::TableBuilderOptions table_builder_options(
      imoptions,
      ikc,
      block_based_table_factories,
      rocksdb::CompressionType::kSnappyCompression,
      compression_opts,
      /* skip_filters */ false);

  rocksdb::TableReaderOptions table_reader_options(
      imoptions,
      rocksdb::EnvOptions(),
      ikc,
      /*skip_filters=*/ false);

  auto universe_key_manager = GenerateTestUniverseKeyManager();

  auto header_manager = DefaultHeaderManager(universe_key_manager.get());
  auto env = yb::NewRocksDBEncryptedEnv(std::move(header_manager));

  auto file_name = JoinPathSegments(test_dir, "test-file");

  std::unique_ptr<rocksdb::WritableFile> base_file;
  ASSERT_OK(env->NewWritableFile(file_name, &base_file, rocksdb::EnvOptions()));
  rocksdb::WritableFileWriter base_writer(std::move(base_file), rocksdb::EnvOptions(),
      /* suspender */ nullptr);

  string data_file_name = file_name + ".sblock.0";
  std::unique_ptr<rocksdb::WritableFile> data_file;
  ASSERT_OK(env->NewWritableFile(data_file_name, &data_file, rocksdb::EnvOptions()));
  rocksdb::WritableFileWriter data_writer(std::move(data_file), rocksdb::EnvOptions(),
      /* suspender */ nullptr);

  rocksdb::BlockBasedTableFactory blk_based_tbl_factory;
  auto table_builder = blk_based_tbl_factory.NewTableBuilder(
      table_builder_options, 0, &base_writer, &data_writer);

  for (int i = 0; i < num_keys; ++i) {
    string key = GetKey(i);
    table_builder->Add(key, GetValue(i));
  }
  ASSERT_OK(table_builder->Finish());
  LOG(INFO) << "Wrote a file of total size " << table_builder->TotalFileSize()
      << ", base file size: " << table_builder->BaseFileSize();
  ASSERT_OK(base_writer.Flush());
  ASSERT_OK(data_writer.Flush());
  ASSERT_OK(base_writer.Close());
  ASSERT_OK(data_writer.Close());

  std::unique_ptr<rocksdb::RandomAccessFile> random_access_file;
  ASSERT_OK(env->NewRandomAccessFile(file_name, &random_access_file, rocksdb::EnvOptions()));
  auto base_file_size = ASSERT_RESULT(random_access_file->Size());
  ASSERT_EQ(base_file_size, table_builder->BaseFileSize());

  std::unique_ptr<rocksdb::RandomAccessFile> random_access_data_file;
  ASSERT_OK(env->NewRandomAccessFile(
      data_file_name, &random_access_data_file, rocksdb::EnvOptions()));
  auto data_file_reader = std::make_unique<rocksdb::RandomAccessFileReader>(
      std::move(random_access_data_file), env.get());

  auto* eraf = down_cast<encryption::EncryptedRandomAccessFile*>(random_access_file.get());
  auto* eraf_data = down_cast<encryption::EncryptedRandomAccessFile*>(random_access_file.get());

  ASSERT_TRUE(eraf != nullptr);
  ASSERT_TRUE(eraf_data != nullptr);
  ASSERT_EQ(0, eraf->TEST_GetNumOverflowWorkarounds());
  ASSERT_EQ(0, eraf_data->TEST_GetNumOverflowWorkarounds());

  size_t raw_size = ASSERT_RESULT(Env::Default()->GetFileSize(file_name));
  LOG(INFO) << "Raw file size: " << raw_size;

  auto random_access_file_reader = std::make_unique<rocksdb::RandomAccessFileReader>(
      std::move(random_access_file));

  std::unique_ptr<rocksdb::TableReader> table_reader;

  ASSERT_OK(blk_based_tbl_factory.NewTableReader(
      table_reader_options, std::move(random_access_file_reader),
      base_file_size,
      &table_reader,
      rocksdb::DataIndexLoadMode::PRELOAD_ON_OPEN,
      rocksdb::PrefetchFilter::YES));

  table_reader->SetDataFileReader(std::move(data_file_reader));

  auto it = std::unique_ptr<rocksdb::InternalIterator>(
      table_reader->NewIterator(rocksdb::ReadOptions()));
  it->SeekToFirst();
  int i = 0;
  while (ASSERT_RESULT(it->CheckedValid())) {
    ASSERT_EQ(it->key(), GetKey(i));
    ASSERT_EQ(it->value(), GetValue(i));
    i++;
    it->Next();
  }
  ASSERT_EQ(num_keys, i);
  ASSERT_GE(eraf->TEST_GetNumOverflowWorkarounds(), 0);
  ASSERT_GE(eraf_data->TEST_GetNumOverflowWorkarounds(), 0);
}

// Writes an SST file pair with AES-GCM, reads it back, then flips one byte of the data file and
// checks that the read fails.
TEST(EncryptedGcmSSTableTest, WriteReadAndDetectTampering) {
  ASSERT_OK(SET_FLAG(encryption_algorithm_override, "AES_256_GCM"));
  ANNOTATE_UNPROTECTED_WRITE(FLAGS_enable_encryption_gcm) = true;
  constexpr int kNumKeys = 100000;

  string test_dir;
  ASSERT_OK(Env::Default()->GetTestDirectory(&test_dir));
  rocksdb::Options opts;
  const rocksdb::ImmutableCFOptions imoptions(opts);
  auto ikc = std::make_shared<rocksdb::InternalKeyComparator>(opts.comparator);
  std::vector<std::unique_ptr<rocksdb::IntTblPropCollectorFactory>> collector_factories;
  rocksdb::CompressionOptions compression_opts;
  rocksdb::TableBuilderOptions table_builder_options(
      imoptions, ikc, collector_factories, rocksdb::CompressionType::kSnappyCompression,
      compression_opts, /* skip_filters */ false);
  rocksdb::TableReaderOptions table_reader_options(
      imoptions, rocksdb::EnvOptions(), ikc, /* skip_filters= */ false);

  auto universe_key_manager = GenerateTestUniverseKeyManager();
  auto env = yb::NewRocksDBEncryptedEnv(DefaultHeaderManager(universe_key_manager.get()));
  auto file_name = JoinPathSegments(test_dir, "000010.sst");
  auto data_file_name = file_name + ".sblock.0";
  rocksdb::BlockBasedTableFactory table_factory;

  {
    std::unique_ptr<rocksdb::WritableFile> base_file, data_file;
    ASSERT_OK(env->NewWritableFile(file_name, &base_file, rocksdb::EnvOptions()));
    ASSERT_OK(env->NewWritableFile(data_file_name, &data_file, rocksdb::EnvOptions()));
    rocksdb::WritableFileWriter base_writer(
        std::move(base_file), rocksdb::EnvOptions(), /* suspender */ nullptr);
    rocksdb::WritableFileWriter data_writer(
        std::move(data_file), rocksdb::EnvOptions(), /* suspender */ nullptr);
    auto table_builder = table_factory.NewTableBuilder(
        table_builder_options, 0, &base_writer, &data_writer);
    for (int i = 0; i < kNumKeys; ++i) {
      table_builder->Add(GetKey(i), GetValue(i));
    }
    ASSERT_OK(table_builder->Finish());
    ASSERT_OK(base_writer.Close());
    ASSERT_OK(data_writer.Close());
  }

  // Returns the number of keys read, or the first error. Uses a new table factory each time so
  // that the second read does not come from the first one's block cache.
  auto read_all = [&]() -> Result<int> {
    rocksdb::BlockBasedTableFactory table_factory;
    std::unique_ptr<rocksdb::RandomAccessFile> base_file, data_file;
    RETURN_NOT_OK(env->NewRandomAccessFile(file_name, &base_file, rocksdb::EnvOptions()));
    RETURN_NOT_OK(env->NewRandomAccessFile(data_file_name, &data_file, rocksdb::EnvOptions()));
    SCHECK(base_file->IsEncrypted(), IllegalState, "File is not encrypted");
    // SST blocks are sealed one by one, not by the file layer.
    SCHECK(base_file->record_cipher() && data_file->record_cipher(), IllegalState,
           "SST files are not using block-level AES-GCM");
    // SST blocks derive their nonce from their offset, so only the tag is stored.
    SCHECK_EQ(base_file->record_cipher()->Overhead(), 16U, IllegalState, "Unexpected overhead");
    const auto base_size = VERIFY_RESULT(base_file->Size());
    std::unique_ptr<rocksdb::TableReader> table_reader;
    RETURN_NOT_OK(table_factory.NewTableReader(
        table_reader_options,
        std::make_unique<rocksdb::RandomAccessFileReader>(std::move(base_file)), base_size,
        &table_reader, rocksdb::DataIndexLoadMode::PRELOAD_ON_OPEN,
        rocksdb::PrefetchFilter::YES));
    table_reader->SetDataFileReader(
        std::make_unique<rocksdb::RandomAccessFileReader>(std::move(data_file), env.get()));
    std::unique_ptr<rocksdb::InternalIterator> it(
        table_reader->NewIterator(rocksdb::ReadOptions()));
    int i = 0;
    for (it->SeekToFirst(); VERIFY_RESULT(it->CheckedValid()); it->Next()) {
      SCHECK_EQ(it->key(), GetKey(i), IllegalState, "Unexpected key");
      SCHECK_EQ(it->value(), GetValue(i), IllegalState, "Unexpected value");
      ++i;
    }
    return i;
  };

  ASSERT_EQ(ASSERT_RESULT(read_all()), kNumKeys);

  faststring raw;
  ASSERT_OK(ReadFileToString(Env::Default(), data_file_name, &raw));
  raw.data()[raw.size() / 2] ^= 0x01;
  ASSERT_OK(WriteStringToFile(Env::Default(), Slice(raw), data_file_name));
  auto result = read_all();
  ASSERT_NOK(result);
  ASSERT_TRUE(result.status().IsCorruption()) << result.status();
}

// A RocksDB MANIFEST is appended to for the life of the DB, so after a crash it ends without a
// final chunk, and must still be readable.
TEST(EncryptedGcmSSTableTest, ManifestTail) {
  ASSERT_OK(SET_FLAG(encryption_algorithm_override, "AES_256_GCM"));
  ANNOTATE_UNPROTECTED_WRITE(FLAGS_enable_encryption_gcm) = true;
  string test_dir;
  ASSERT_OK(Env::Default()->GetTestDirectory(&test_dir));
  auto universe_key_manager = GenerateTestUniverseKeyManager();
  auto env = yb::NewRocksDBEncryptedEnv(DefaultHeaderManager(universe_key_manager.get()));
  const auto data = RandomHumanReadableString(10000);

  for (const auto* name : {"MANIFEST-000001", "OPTIONS-000001"}) {
    const auto path = JoinPathSegments(test_dir, name);
    std::unique_ptr<rocksdb::WritableFile> file;
    ASSERT_OK(env->NewWritableFile(path, &file, rocksdb::EnvOptions()));
    ASSERT_OK(file->Append(data));
    ASSERT_OK(file->Sync());
    ANNOTATE_UNPROTECTED_WRITE(FLAGS_TEST_encryption_gcm_skip_close_on_destroy) = true;
    file.reset();
    ANNOTATE_UNPROTECTED_WRITE(FLAGS_TEST_encryption_gcm_skip_close_on_destroy) = false;

    std::unique_ptr<rocksdb::RandomAccessFile> reader;
    auto s = env->NewRandomAccessFile(path, &reader, rocksdb::EnvOptions());
    Result<uint64_t> size = s.ok() ? reader->Size() : Result<uint64_t>(s);
    if (std::string(name).starts_with("MANIFEST-")) {
      ASSERT_EQ(ASSERT_RESULT(std::move(size)), data.size());
      std::vector<uint8_t> buf(data.size());
      Slice result;
      ASSERT_OK(reader->Read(0, data.size(), &result, buf.data()));
      ASSERT_EQ(result, Slice(data));
    } else {
      // Other files without their final chunk are reported as corrupt.
      ASSERT_NOK(size);
      ASSERT_TRUE(size.status().IsCorruption()) << size.status();
    }
  }
}

TEST_P(EncryptedSSTableTest, CounterOverflow10MKeys) {
  // Note that only three zeros are there in the end of the initial counter below. We are trying to
  // get a counter that is 65536 bytes (4096 encryption blocks) away from overflow.
  CounterOverflow(10 * 1000 * 1000, 0xfffff000);
}

TEST_P(EncryptedSSTableTest, CounterOverflow100000Keys) {
  // This test fails if meta block checksums are not being verified.
  // https://github.com/yugabyte/yugabyte-db/issues/3974
  CounterOverflow(100 * 1000, 0xffffff00);
}

} // namespace yb
