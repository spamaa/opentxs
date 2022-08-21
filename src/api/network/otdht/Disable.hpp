// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// IWYU pragma: no_include "opentxs/blockchain/BlockchainType.hpp"

#pragma once

#include <string_view>
#include <variant>

#include "api/network/otdht/OTDHT.hpp"
#include "opentxs/blockchain/Types.hpp"

// NOLINTBEGIN(modernize-concat-nested-namespaces)
namespace opentxs  // NOLINT
{
// inline namespace v1
// {
namespace network
{
namespace otdht
{
class Server;
}  // namespace otdht
}  // namespace network
// }  // namespace v1
}  // namespace opentxs
// NOLINTEND(modernize-concat-nested-namespaces)

namespace opentxs::api::network::implementation
{
class OTDHT::DisableChain
{
public:
    auto operator()(std::monostate& val) const noexcept -> void;
    auto operator()(opentxs::network::otdht::Server& val) const noexcept
        -> void;

    DisableChain(opentxs::blockchain::Type chain) noexcept;
    DisableChain() = delete;
    DisableChain(const DisableChain&) = delete;
    DisableChain(DisableChain&&) = delete;
    auto operator=(const DisableChain&) -> DisableChain& = delete;
    auto operator=(DisableChain&&) -> DisableChain& = delete;

private:
    const opentxs::blockchain::Type chain_;
};
}  // namespace opentxs::api::network::implementation
