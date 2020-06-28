// Copyright (c) 2010-2020 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef OPENTXS_PROTOBUF_HD_ACCOUNT_HPP
#define OPENTXS_PROTOBUF_HD_ACCOUNT_HPP

#include "opentxs/Version.hpp"  // IWYU pragma: associated

#include "opentxs/protobuf/verify/VerifyBlockchain.hpp"

namespace opentxs
{
namespace proto
{
class HDAccount;
}  // namespace proto
}  // namespace opentxs

namespace opentxs
{
namespace proto
{
OPENTXS_EXPORT bool CheckProto_1(const HDAccount& account, const bool silent);
OPENTXS_EXPORT bool CheckProto_2(const HDAccount&, const bool);
OPENTXS_EXPORT bool CheckProto_3(const HDAccount&, const bool);
OPENTXS_EXPORT bool CheckProto_4(const HDAccount&, const bool);
OPENTXS_EXPORT bool CheckProto_5(const HDAccount&, const bool);
OPENTXS_EXPORT bool CheckProto_6(const HDAccount&, const bool);
OPENTXS_EXPORT bool CheckProto_7(const HDAccount&, const bool);
OPENTXS_EXPORT bool CheckProto_8(const HDAccount&, const bool);
OPENTXS_EXPORT bool CheckProto_9(const HDAccount&, const bool);
OPENTXS_EXPORT bool CheckProto_10(const HDAccount&, const bool);
OPENTXS_EXPORT bool CheckProto_11(const HDAccount&, const bool);
OPENTXS_EXPORT bool CheckProto_12(const HDAccount&, const bool);
OPENTXS_EXPORT bool CheckProto_13(const HDAccount&, const bool);
OPENTXS_EXPORT bool CheckProto_14(const HDAccount&, const bool);
OPENTXS_EXPORT bool CheckProto_15(const HDAccount&, const bool);
OPENTXS_EXPORT bool CheckProto_16(const HDAccount&, const bool);
OPENTXS_EXPORT bool CheckProto_17(const HDAccount&, const bool);
OPENTXS_EXPORT bool CheckProto_18(const HDAccount&, const bool);
OPENTXS_EXPORT bool CheckProto_19(const HDAccount&, const bool);
OPENTXS_EXPORT bool CheckProto_20(const HDAccount&, const bool);
}  // namespace proto
}  // namespace opentxs

#endif  // OPENTXS_PROTOBUF_HD_ACCOUNT_HPP
