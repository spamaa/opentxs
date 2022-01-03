// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include "opentxs/Version.hpp"  // IWYU pragma: associated

#include "opentxs/Types.hpp"
#include "opentxs/util/Numbers.hpp"
#include "opentxs/util/rpc/request/Base.hpp"

namespace opentxs
{
namespace proto
{
class RPCCommand;
}  // namespace proto
}  // namespace opentxs

namespace opentxs
{
namespace rpc
{
namespace request
{
class OPENTXS_EXPORT ListNyms final : public Base
{
public:
    static auto DefaultVersion() noexcept -> VersionNumber;

    /// throws std::runtime_error for invalid constructor arguments
    ListNyms(SessionIndex session, const AssociateNyms& nyms = {}) noexcept(
        false);
    OPENTXS_NO_EXPORT ListNyms(const proto::RPCCommand& serialized) noexcept(
        false);
    ListNyms() noexcept;

    ~ListNyms() final;

private:
    ListNyms(const ListNyms&) = delete;
    ListNyms(ListNyms&&) = delete;
    auto operator=(const ListNyms&) -> ListNyms& = delete;
    auto operator=(ListNyms&&) -> ListNyms& = delete;
};
}  // namespace request
}  // namespace rpc
}  // namespace opentxs
