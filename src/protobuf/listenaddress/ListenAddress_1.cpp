// Copyright (c) 2010-2020 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "opentxs/protobuf/ContractEnums.pb.h"
#include "opentxs/protobuf/ListenAddress.pb.h"
#include "opentxs/protobuf/verify/ListenAddress.hpp"
#include "protobuf/Check.hpp"

#define PROTO_NAME "listen address"

namespace opentxs
{
namespace proto
{

auto CheckProto_1(const ListenAddress& input, const bool silent) -> bool
{
    CHECK_EXISTS(type);

    if ((ADDRESSTYPE_IPV4 > input.type()) || (ADDRESSTYPE_EEP < input.type())) {
        FAIL_1("invalid type")
    }

    if (!input.has_protocol()) { FAIL_1("missing protocol") }

    if ((PROTOCOLVERSION_ERROR == input.protocol()) ||
        (PROTOCOLVERSION_NOTIFY < input.protocol())) {
        FAIL_1("invalid protocol")
    }

    CHECK_EXISTS(host);
    CHECK_EXISTS(port);

    if (MAX_VALID_PORT < input.port()) { FAIL_1("invalid port") }

    return true;
}

auto CheckProto_2(const ListenAddress& input, const bool silent) -> bool
{
    CHECK_EXISTS(type);

    if ((ADDRESSTYPE_IPV4 > input.type()) ||
        (ADDRESSTYPE_INPROC < input.type())) {
        FAIL_1("invalid type")
    }

    if (!input.has_protocol()) { FAIL_1("missing protocol") }

    if ((PROTOCOLVERSION_ERROR == input.protocol()) ||
        (PROTOCOLVERSION_NOTIFY < input.protocol())) {
        FAIL_1("invalid protocol")
    }

    CHECK_EXISTS(host);
    CHECK_EXISTS(port);

    if (MAX_VALID_PORT < input.port()) { FAIL_1("invalid port") }

    return true;
}

auto CheckProto_3(const ListenAddress& input, const bool silent) -> bool
{
    UNDEFINED_VERSION(3)
}

auto CheckProto_4(const ListenAddress& input, const bool silent) -> bool
{
    UNDEFINED_VERSION(4)
}

auto CheckProto_5(const ListenAddress& input, const bool silent) -> bool
{
    UNDEFINED_VERSION(5)
}

auto CheckProto_6(const ListenAddress& input, const bool silent) -> bool
{
    UNDEFINED_VERSION(6)
}

auto CheckProto_7(const ListenAddress& input, const bool silent) -> bool
{
    UNDEFINED_VERSION(7)
}

auto CheckProto_8(const ListenAddress& input, const bool silent) -> bool
{
    UNDEFINED_VERSION(8)
}

auto CheckProto_9(const ListenAddress& input, const bool silent) -> bool
{
    UNDEFINED_VERSION(9)
}

auto CheckProto_10(const ListenAddress& input, const bool silent) -> bool
{
    UNDEFINED_VERSION(10)
}

auto CheckProto_11(const ListenAddress& input, const bool silent) -> bool
{
    UNDEFINED_VERSION(11)
}

auto CheckProto_12(const ListenAddress& input, const bool silent) -> bool
{
    UNDEFINED_VERSION(12)
}

auto CheckProto_13(const ListenAddress& input, const bool silent) -> bool
{
    UNDEFINED_VERSION(13)
}

auto CheckProto_14(const ListenAddress& input, const bool silent) -> bool
{
    UNDEFINED_VERSION(14)
}

auto CheckProto_15(const ListenAddress& input, const bool silent) -> bool
{
    UNDEFINED_VERSION(15)
}

auto CheckProto_16(const ListenAddress& input, const bool silent) -> bool
{
    UNDEFINED_VERSION(16)
}

auto CheckProto_17(const ListenAddress& input, const bool silent) -> bool
{
    UNDEFINED_VERSION(17)
}

auto CheckProto_18(const ListenAddress& input, const bool silent) -> bool
{
    UNDEFINED_VERSION(18)
}

auto CheckProto_19(const ListenAddress& input, const bool silent) -> bool
{
    UNDEFINED_VERSION(19)
}

auto CheckProto_20(const ListenAddress& input, const bool silent) -> bool
{
    UNDEFINED_VERSION(20)
}
}  // namespace proto
}  // namespace opentxs
