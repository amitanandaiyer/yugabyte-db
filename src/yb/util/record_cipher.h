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

#include <cstddef>
#include <cstdint>

#include "yb/util/slice.h"
#include "yb/util/status_fwd.h"

namespace yb {

// Authenticated encryption of self-contained records (an SST block, a WAL entry batch), provided by
// a file whose encryption layer leaves the record contents to the writer. A sealed record is longer
// than its plaintext by Overhead() bytes.
//
// position is the record's offset in the file, from which the cipher may derive the record's nonce.
// A writer must not seal two records at the same position within one writable file instance, and
// the reader must pass the position the record was sealed at.
//
// aad is authenticated but not stored; the reader must supply the same bytes, so that records
// cannot be moved within or between files or passed off as another kind of record.
class RecordCipher {
 public:
  virtual ~RecordCipher() = default;

  virtual size_t Overhead() const = 0;

  // sealed must have room for plaintext.size() + Overhead() bytes.
  virtual Status Seal(uint64_t position, Slice aad, Slice plaintext, uint8_t* sealed) const = 0;

  // plaintext must have room for sealed.size() - Overhead() bytes. Returns Corruption if the
  // record, its position or aad was modified.
  virtual Status Open(uint64_t position, Slice aad, Slice sealed, uint8_t* plaintext) const = 0;
};

} // namespace yb
