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

#include "yb/encryption/encryption.pb.h"
#include "yb/encryption/encryption_util.h"
#include "yb/encryption/header_manager_impl.h"
#include "yb/encryption/universe_key_manager.h"

#include "yb/gutil/endian.h"

#include "yb/tserver/universe_key_test_util.h"

#include "yb/util/flags.h"
#include "yb/util/random_util.h"
#include "yb/util/status_fwd.h"
#include "yb/util/test_util.h"

DECLARE_uint32(encryption_data_key_size_bytes);

using std::string;

using yb::tserver::GenerateTestUniverseKeyManager;

namespace yb {

class TestHeaderManagerImpl : public YBTest {};

TEST_F(TestHeaderManagerImpl, FileOps) {
  auto universe_key_manger = GenerateTestUniverseKeyManager();
  auto header_manager =
      DefaultHeaderManager(universe_key_manger.get());
  using encryption::EncryptionParams;
  for (auto key_size : {EncryptionParams::kAes128KeySize, EncryptionParams::kAes256KeySize}) {
    auto params = EncryptionParams::NewEncryptionParams(key_size);
    string header = ASSERT_RESULT(header_manager->SerializeEncryptionParams(*params.get()));
    auto start_idx = header_manager->GetEncryptionMetadataStartIndex();
    auto status = ASSERT_RESULT(header_manager->GetFileEncryptionStatusFromPrefix(
        Slice(header.c_str(), start_idx)));
    ASSERT_TRUE(status.is_encrypted);
    Slice s = Slice(header.c_str() + start_idx, status.header_size);
    auto new_params =
        ASSERT_RESULT(header_manager->DecodeEncryptionParamsFromEncryptionMetadata(s));
    ASSERT_EQ(new_params->key_size, key_size);
    ASSERT_TRUE(params->Equals(*new_params.get()));
  }
}

TEST_F(TestHeaderManagerImpl, DataKeySize) {
  using encryption::EncryptionParams;
  // A registry without a recorded size predates the field, so its universe stays on AES-128.
  auto key = RandomBytes(encryption::DefaultUniverseKeySize());
  auto legacy_manager = ASSERT_RESULT(encryption::UniverseKeyManager::FromKey(
      "legacy", Slice(key.data(), key.size())));
  ASSERT_EQ(ASSERT_RESULT(legacy_manager->GetDataKeySize()), EncryptionParams::kAes128KeySize);

  auto new_manager = GenerateTestUniverseKeyManager();
  ASSERT_EQ(ASSERT_RESULT(new_manager->GetDataKeySize()), EncryptionParams::kAes256KeySize);

  ANNOTATE_UNPROTECTED_WRITE(FLAGS_encryption_data_key_size_bytes) =
      EncryptionParams::kAes256KeySize;
  ASSERT_EQ(ASSERT_RESULT(legacy_manager->GetDataKeySize()), EncryptionParams::kAes256KeySize);
  ANNOTATE_UNPROTECTED_WRITE(FLAGS_encryption_data_key_size_bytes) = 0;

  // A size this release does not support fails file creation instead of crashing the tserver.
  encryption::UniverseKeyRegistryPB registry;
  registry.set_encryption_enabled(true);
  auto params = ASSERT_RESULT(EncryptionParams::FromSlice(Slice(key.data(), key.size())));
  params->ToEncryptionParamsPB(&(*registry.mutable_universe_keys())["bad"]);
  registry.set_latest_version_id("bad");
  registry.set_data_key_size_bytes(20);
  encryption::UniverseKeyManager bad_manager;
  bad_manager.SetUniverseKeyRegistry(registry);
  ASSERT_NOK(bad_manager.GetDataKeySize());
}

} // namespace yb
