// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <variant>

#include "api/network/otdht/OTDHT.hpp"

// NOLINTBEGIN(modernize-concat-nested-namespaces)
namespace opentxs  // NOLINT
{
// inline namespace v1
// {
namespace api
{
namespace network
{
class Blockchain;
}  // namespace network
}  // namespace api

namespace network
{
namespace otdht
{
class Client;
class Server;
}  // namespace otdht
}  // namespace network
// }  // namespace v1
}  // namespace opentxs
// NOLINTEND(modernize-concat-nested-namespaces)

namespace opentxs::api::network::implementation
{
class OTDHT::Init
{
public:
    auto operator()(std::monostate& val) const noexcept -> void;
    auto operator()(opentxs::network::otdht::Client& val) const noexcept
        -> void;
    auto operator()(opentxs::network::otdht::Server& val) const noexcept
        -> void;

    Init(const api::network::Blockchain& blockchain) noexcept;
    Init() = delete;
    Init(const Init&) = delete;
    Init(Init&&) = delete;
    auto operator=(const Init&) -> Init& = delete;
    auto operator=(Init&&) -> Init& = delete;

private:
    const api::network::Blockchain& blockchain_;
};
}  // namespace opentxs::api::network::implementation
