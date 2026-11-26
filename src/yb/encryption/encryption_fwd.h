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

#include "yb/util/enums.h"

namespace yb {
namespace encryption {

// kGcm is chunked AES-GCM applied by the file layer; kGcmRecord is AES-GCM applied by the writer to
// each record. UniverseKeyManager and HeaderManager only ever select kCtr or kGcm; kGcm becomes
// kGcmRecord for files whose writer seals its own records (see GcmFileLayout).
YB_DEFINE_ENUM(CipherMode, (kCtr)(kGcm)(kGcmRecord));

// How a new file is encrypted when AES-GCM is selected.
YB_DEFINE_ENUM(GcmFileLayout,
    // Fixed-size chunks sealed by the file layer; a missing final chunk is corruption.
    (kChunks)
    // The writer seals each record with record_cipher(), and the file is never rewritten: each
    // nonce is derived from the record's position and not stored (SST blocks, MANIFEST records).
    (kWriteOnceRecords)
    // The writer seals each record with record_cipher(), and may rewrite records after reopening
    // the file: each record stores its nonce (WAL entries).
    (kRecords));

class HeaderManager;
class UniverseKeyManager;
class UniverseKeysPB;

}  // namespace encryption
}  // namespace yb
