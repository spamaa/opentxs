// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <cs_shared_guarded.h>
#include <memory>
#include <shared_mutex>
#include <string_view>
#include <variant>

#include "internal/api/network/OTDHT.hpp"
#include "internal/network/otdht/Node.hpp"
#include "internal/network/otdht/Server.hpp"
#include "opentxs/api/network/OTDHT.hpp"
#include "opentxs/util/Allocator.hpp"

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

class Session;
}  // namespace api

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
class OTDHT final : public internal::OTDHT
{
public:
    auto AddPeer(std::string_view endpoint) const noexcept -> bool final;
    auto ConnectedPeers() const noexcept -> Endpoints final;
    auto DeletePeer(std::string_view endpoint) const noexcept -> bool final;
    auto Disable(const Chain chain) const noexcept -> void final;
    auto Enable(const Chain chain) const noexcept -> void final;
    auto Endpoint(const Chain chain) const noexcept -> std::string_view final;
    auto KnownPeers(alloc::Default alloc) const noexcept -> Endpoints final;
    auto StartListener(
        std::string_view syncEndpoint,
        std::string_view publicSyncEndpoint,
        std::string_view updateEndpoint,
        std::string_view publicUpdateEndpoint) const noexcept -> bool final;

    auto Start(std::shared_ptr<const api::Session> api) noexcept -> void final;

    OTDHT(const api::Session& api, const api::network::Blockchain& blockchain)
    noexcept;
    OTDHT() = delete;
    OTDHT(const OTDHT&) = delete;
    OTDHT(OTDHT&&) = delete;
    auto operator=(const OTDHT&) -> OTDHT& = delete;
    auto operator=(OTDHT&&) -> OTDHT& = delete;

    ~OTDHT() final;

private:
    class ChainEndpoint;
    class DisableChain;
    class EnableChain;
    class StartServer;

    using Node = std::variant<std::monostate, opentxs::network::otdht::Server>;
    using GuardedNode = libguarded::shared_guarded<Node, std::shared_mutex>;

    const api::Session& api_;
    const api::network::Blockchain& blockchain_;
    mutable GuardedNode node_;
};
}  // namespace opentxs::api::network::implementation
