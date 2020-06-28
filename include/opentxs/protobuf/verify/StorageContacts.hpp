// Copyright (c) 2010-2020 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef OPENTXS_PROTOBUF_STORAGECONTACTS_HPP
#define OPENTXS_PROTOBUF_STORAGECONTACTS_HPP

#include "opentxs/Version.hpp"  // IWYU pragma: associated

#include "opentxs/protobuf/verify/VerifyStorage.hpp"

namespace opentxs
{
namespace proto
{
class StorageContacts;
}  // namespace proto
}  // namespace opentxs

namespace opentxs
{
namespace proto
{
OPENTXS_EXPORT bool CheckProto_1(
    const StorageContacts& contact,
    const bool silent);
OPENTXS_EXPORT bool CheckProto_2(const StorageContacts&, const bool);
OPENTXS_EXPORT bool CheckProto_3(const StorageContacts&, const bool);
OPENTXS_EXPORT bool CheckProto_4(const StorageContacts&, const bool);
OPENTXS_EXPORT bool CheckProto_5(const StorageContacts&, const bool);
OPENTXS_EXPORT bool CheckProto_6(const StorageContacts&, const bool);
OPENTXS_EXPORT bool CheckProto_7(const StorageContacts&, const bool);
OPENTXS_EXPORT bool CheckProto_8(const StorageContacts&, const bool);
OPENTXS_EXPORT bool CheckProto_9(const StorageContacts&, const bool);
OPENTXS_EXPORT bool CheckProto_10(const StorageContacts&, const bool);
OPENTXS_EXPORT bool CheckProto_11(const StorageContacts&, const bool);
OPENTXS_EXPORT bool CheckProto_12(const StorageContacts&, const bool);
OPENTXS_EXPORT bool CheckProto_13(const StorageContacts&, const bool);
OPENTXS_EXPORT bool CheckProto_14(const StorageContacts&, const bool);
OPENTXS_EXPORT bool CheckProto_15(const StorageContacts&, const bool);
OPENTXS_EXPORT bool CheckProto_16(const StorageContacts&, const bool);
OPENTXS_EXPORT bool CheckProto_17(const StorageContacts&, const bool);
OPENTXS_EXPORT bool CheckProto_18(const StorageContacts&, const bool);
OPENTXS_EXPORT bool CheckProto_19(const StorageContacts&, const bool);
OPENTXS_EXPORT bool CheckProto_20(const StorageContacts&, const bool);
}  // namespace proto
}  // namespace opentxs

#endif  // OPENTXS_PROTOBUF_STORAGECONTACTS_HPP
