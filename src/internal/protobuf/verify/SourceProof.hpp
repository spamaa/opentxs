// Copyright (c) 2010-2021 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include "opentxs/Version.hpp"  // IWYU pragma: associated

namespace opentxs
{
namespace proto
{
class SourceProof;
}  // namespace proto
}  // namespace opentxs

namespace opentxs
{
namespace proto
{
auto CheckProto_1(
    const SourceProof& proot,
    const bool silent,
    bool& ExpectSourceSignature) -> bool;
auto CheckProto_2(const SourceProof&, const bool, bool&) -> bool;
auto CheckProto_3(const SourceProof&, const bool, bool&) -> bool;
auto CheckProto_4(const SourceProof&, const bool, bool&) -> bool;
auto CheckProto_5(const SourceProof&, const bool, bool&) -> bool;
auto CheckProto_6(const SourceProof&, const bool, bool&) -> bool;
auto CheckProto_7(const SourceProof&, const bool, bool&) -> bool;
auto CheckProto_8(const SourceProof&, const bool, bool&) -> bool;
auto CheckProto_9(const SourceProof&, const bool, bool&) -> bool;
auto CheckProto_10(const SourceProof&, const bool, bool&) -> bool;
auto CheckProto_11(const SourceProof&, const bool, bool&) -> bool;
auto CheckProto_12(const SourceProof&, const bool, bool&) -> bool;
auto CheckProto_13(const SourceProof&, const bool, bool&) -> bool;
auto CheckProto_14(const SourceProof&, const bool, bool&) -> bool;
auto CheckProto_15(const SourceProof&, const bool, bool&) -> bool;
auto CheckProto_16(const SourceProof&, const bool, bool&) -> bool;
auto CheckProto_17(const SourceProof&, const bool, bool&) -> bool;
auto CheckProto_18(const SourceProof&, const bool, bool&) -> bool;
auto CheckProto_19(const SourceProof&, const bool, bool&) -> bool;
auto CheckProto_20(const SourceProof&, const bool, bool&) -> bool;
}  // namespace proto
}  // namespace opentxs