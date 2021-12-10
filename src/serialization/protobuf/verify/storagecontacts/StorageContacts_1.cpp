// Copyright (c) 2010-2021 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "internal/protobuf/verify/StorageContacts.hpp"  // IWYU pragma: associated

#include <stdexcept>
#include <utility>

#include "internal/protobuf/Basic.hpp"
#include "internal/protobuf/Check.hpp"
#include "internal/protobuf/verify/StorageContactAddressIndex.hpp"  // IWYU pragma: keep
#include "internal/protobuf/verify/StorageIDList.hpp"    // IWYU pragma: keep
#include "internal/protobuf/verify/StorageItemHash.hpp"  // IWYU pragma: keep
#include "internal/protobuf/verify/VerifyStorage.hpp"
#include "serialization/protobuf/StorageContactAddressIndex.pb.h"
#include "serialization/protobuf/StorageContacts.pb.h"
#include "serialization/protobuf/StorageIDList.pb.h"
#include "serialization/protobuf/StorageItemHash.pb.h"
#include "serialization/protobuf/verify/Check.hpp"

#define PROTO_NAME "contact storage index"

namespace opentxs::proto
{
auto CheckProto_1(const StorageContacts& input, const bool silent) -> bool
{
    for (auto& merge : input.merge()) {
        try {
            const bool valid = Check(
                merge,
                StorageContactsAllowedList().at(input.version()).first,
                StorageContactsAllowedList().at(input.version()).second,
                silent);

            if (!valid) { FAIL_1("invalid merge") }
        } catch (const std::out_of_range&) {
            FAIL_2(
                "allowed storage id list version not defined for version",
                input.version())
        }
    }

    for (auto& hash : input.contact()) {
        try {
            const bool valid = Check(
                hash,
                StorageContactsAllowedStorageItemHash()
                    .at(input.version())
                    .first,
                StorageContactsAllowedStorageItemHash()
                    .at(input.version())
                    .second,
                silent);

            if (!valid) { FAIL_1("invalid hash") }
        } catch (const std::out_of_range&) {
            FAIL_2(
                "allowed storage item hash version not defined for version",
                input.version())
        }
    }

    for (auto& index : input.address()) {
        try {
            const bool valid = Check(
                index,
                StorageContactsAllowedAddress().at(input.version()).first,
                StorageContactsAllowedAddress().at(input.version()).second,
                silent);

            if (!valid) { FAIL_1("invalid address index") }
        } catch (const std::out_of_range&) {
            FAIL_2(
                "allowed address index version not defined for version",
                input.version())
        }
    }

    if (0 < input.nym().size()) {
        FAIL_2("nym index not allowed for version", input.version())
    }

    return true;
}
}  // namespace opentxs::proto