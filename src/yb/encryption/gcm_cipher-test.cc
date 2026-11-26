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

#include <vector>

#include <gtest/gtest.h>

#include "yb/encryption/encryption_util.h"
#include "yb/encryption/gcm_cipher.h"

#include "yb/rpc/secure_stream.h"

#include "yb/util/random_util.h"
#include "yb/util/record_cipher.h"
#include "yb/util/test_macros.h"
#include "yb/util/test_util.h"

namespace yb::encryption {

class GcmCipherTest : public YBTest, public testing::WithParamInterface<EncryptionAlgorithmPB> {
 protected:
  void SetUp() override {
    YBTest::SetUp();
    rpc::InitOpenSSL();
    auto params = ASSERT_RESULT(EncryptionParams::NewEncryptionParams(GetParam()));
    params->gcm_chunk_size = kChunkSize;
    cipher_ = ASSERT_RESULT(GcmChunkCipher::Create(*params));
  }

  // Seals plaintext as chunk `index`, feeding it to the sealer in uneven pieces.
  void Seal(uint64_t index, bool final, const std::vector<uint8_t>& plaintext,
            std::vector<uint8_t>* ciphertext, std::vector<uint8_t>* tag) {
    GcmChunkCipher::Sealer sealer(*cipher_);
    ASSERT_OK(sealer.Begin(index, final));
    ciphertext->resize(plaintext.size());
    size_t pos = 0;
    while (pos < plaintext.size()) {
      const size_t take = std::min<size_t>(RandomUniformInt(1, 37), plaintext.size() - pos);
      ASSERT_OK(sealer.Update(Slice(plaintext.data() + pos, take), ciphertext->data() + pos));
      pos += take;
    }
    tag->resize(GcmChunkCipher::kTagSize);
    ASSERT_OK(sealer.Finish(tag->data()));
  }

  static constexpr size_t kChunkSize = 256;
  std::unique_ptr<GcmChunkCipher> cipher_;
};

INSTANTIATE_TEST_SUITE_P(
    KeySizes, GcmCipherTest,
    ::testing::Values(ENCRYPTION_ALGORITHM_AES_128_GCM, ENCRYPTION_ALGORITHM_AES_256_GCM));

TEST_P(GcmCipherTest, RoundTripAndTamperDetection) {
  auto plaintext = RandomBytes(kChunkSize);
  std::vector<uint8_t> ciphertext, tag;
  ASSERT_NO_FATALS(Seal(7, /* final= */ false, plaintext, &ciphertext, &tag));
  ASSERT_NE(ciphertext, plaintext);

  auto open = [&](uint64_t index, bool final, const std::vector<uint8_t>& ct,
                  const std::vector<uint8_t>& t, uint8_t* out) {
    return cipher_->Open(index, final, Slice(ct.data(), ct.size()), Slice(t.data(), t.size()), out);
  };
  std::vector<uint8_t> decrypted(kChunkSize);
  ASSERT_OK(open(7, false, ciphertext, tag, decrypted.data()));
  ASSERT_EQ(decrypted, plaintext);

  // A chunk only opens with the index and final flag it was sealed with.
  ASSERT_TRUE(open(8, false, ciphertext, tag, decrypted.data()).IsCorruption());
  ASSERT_TRUE(open(7, true, ciphertext, tag, decrypted.data()).IsCorruption());

  auto bad_ciphertext = ciphertext;
  bad_ciphertext[RandomUniformInt<size_t>(0, kChunkSize - 1)] ^= 0x01;
  ASSERT_TRUE(open(7, false, bad_ciphertext, tag, decrypted.data()).IsCorruption());

  auto bad_tag = tag;
  bad_tag[0] ^= 0x80;
  ASSERT_TRUE(open(7, false, ciphertext, bad_tag, decrypted.data()).IsCorruption());
}

TEST_P(GcmCipherTest, EmptyFinalChunk) {
  std::vector<uint8_t> ciphertext, tag;
  ASSERT_NO_FATALS(Seal(3, /* final= */ true, {}, &ciphertext, &tag));
  Slice tag_slice(tag.data(), tag.size());
  ASSERT_OK(cipher_->Open(3, true, Slice(), tag_slice, nullptr));
  ASSERT_TRUE(cipher_->Open(3, false, Slice(), tag_slice, nullptr).IsCorruption());
  ASSERT_TRUE(cipher_->Open(4, true, Slice(), tag_slice, nullptr).IsCorruption());
}

class GcmRecordCipherTest : public YBTest, public testing::WithParamInterface<bool> {
 protected:
  void SetUp() override {
    YBTest::SetUp();
    rpc::InitOpenSSL();
    params_ = ASSERT_RESULT(EncryptionParams::NewEncryptionParams(
        ENCRYPTION_ALGORITHM_AES_256_GCM,
        GetParam() ? GcmFileLayout::kRecords : GcmFileLayout::kWriteOnceRecords));
  }

  Result<std::string> Seal(
      const RecordCipher& cipher, uint64_t position, Slice aad, Slice plaintext) {
    std::string sealed(plaintext.size() + cipher.Overhead(), '\0');
    RETURN_NOT_OK(cipher.Seal(
        position, aad, plaintext, reinterpret_cast<uint8_t*>(sealed.data())));
    return sealed;
  }

  Status Open(const RecordCipher& cipher, uint64_t position, Slice aad, Slice sealed) {
    std::string plaintext(sealed.size() - cipher.Overhead(), '\0');
    return cipher.Open(position, aad, sealed, reinterpret_cast<uint8_t*>(plaintext.data()));
  }

  EncryptionParamsPtr params_;
};

INSTANTIATE_TEST_SUITE_P(NonceStored, GcmRecordCipherTest, ::testing::Bool());

TEST_P(GcmRecordCipherTest, SealAndOpen) {
  const bool nonce_stored = GetParam();
  auto cipher = ASSERT_RESULT(GcmRecordCipher::Create(*params_));
  ASSERT_EQ(cipher->Overhead(),
            GcmRecordCipher::kTagSize + (nonce_stored ? GcmRecordCipher::kNonceSize : 0));

  const std::string plaintext = "record contents";
  const std::string aad = "aad";
  auto sealed = ASSERT_RESULT(Seal(*cipher, 1000, aad, plaintext));
  std::string opened(plaintext.size(), '\0');
  ASSERT_OK(cipher->Open(1000, aad, sealed, reinterpret_cast<uint8_t*>(opened.data())));
  ASSERT_EQ(opened, plaintext);

  ASSERT_TRUE(Open(*cipher, 1000, "other aad", sealed).IsCorruption());
  auto modified = sealed;
  modified[modified.size() / 2] ^= 0x01;
  ASSERT_TRUE(Open(*cipher, 1000, aad, modified).IsCorruption());

  // Without a stored nonce, the record only opens at the position it was sealed at.
  auto other_position = Open(*cipher, 1001, aad, sealed);
  if (nonce_stored) {
    ASSERT_OK(other_position);
  } else {
    ASSERT_TRUE(other_position.IsCorruption()) << other_position;
  }

  // A reader is a separate cipher instance built from the same file parameters.
  auto reader = ASSERT_RESULT(GcmRecordCipher::Create(*params_));
  ASSERT_OK(Open(*reader, 1000, aad, sealed));
}

// Sealing the same position twice, as the log does when it rewrites a torn tail after reopening a
// segment, must not repeat a nonce. Each writable file instance gets its own cipher.
TEST_P(GcmRecordCipherTest, RewriteAfterReopen) {
  const bool nonce_stored = GetParam();
  auto first_session = ASSERT_RESULT(GcmRecordCipher::Create(*params_));
  auto second_session = ASSERT_RESULT(GcmRecordCipher::Create(*params_));
  auto first = ASSERT_RESULT(Seal(*first_session, 500, "", "torn entry"));
  auto second = ASSERT_RESULT(Seal(*second_session, 500, "", "torn entry"));
  if (nonce_stored) {
    ASSERT_NE(first.substr(0, GcmRecordCipher::kNonceSize),
              second.substr(0, GcmRecordCipher::kNonceSize));
  } else {
    // Write-once files derive the nonce from the position alone; they must never be rewritten.
    ASSERT_EQ(first, second);
  }
}

} // namespace yb::encryption
