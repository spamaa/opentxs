// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <string_view>
#include <variant>

#include "api/network/otdht/OTDHT.hpp"

// NOLINTBEGIN(modernize-concat-nested-namespaces)
namespace opentxs  // NOLINT
{
// inline namespace v1
// {
namespace network
{
namespace otdht
{
class Node;
class Server;
}  // namespace otdht
}  // namespace network
// }  // namespace v1
}  // namespace opentxs
// NOLINTEND(modernize-concat-nested-namespaces)

namespace opentxs::api::network::implementation
{
class OTDHT::StartServer
{
public:
    auto operator()(std::monostate& val) const noexcept -> bool;
    auto operator()(opentxs::network::otdht::Server& val) const noexcept
        -> bool;
    auto operator()(opentxs::network::otdht::Node& val) const noexcept -> bool;

    StartServer(
        std::string_view bindInternal,
        std::string_view bindPublic,
        std::string_view publishInternal,
        std::string_view publishPublic) noexcept;
    StartServer() = delete;
    StartServer(const StartServer&) = delete;
    StartServer(StartServer&&) = delete;
    auto operator=(const StartServer&) -> StartServer& = delete;
    auto operator=(StartServer&&) -> StartServer& = delete;

private:
    const std::string_view bind_internal_;
    const std::string_view bind_public_;
    const std::string_view publish_internal_;
    const std::string_view publish_public_;
};
}  // namespace opentxs::api::network::implementation
