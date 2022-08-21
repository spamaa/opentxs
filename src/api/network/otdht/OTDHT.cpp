// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "0_stdafx.hpp"                      // IWYU pragma: associated
#include "1_Internal.hpp"                    // IWYU pragma: associated
#include "api/network/otdht/OTDHT.hpp"       // IWYU pragma: associated
#include "internal/api/network/Factory.hpp"  // IWYU pragma: associated

#include "api/network/otdht/ChainEndpoint.hpp"
#include "api/network/otdht/Disable.hpp"
#include "api/network/otdht/Enable.hpp"
#include "api/network/otdht/Start.hpp"
#include "internal/api/network/Blockchain.hpp"
#include "internal/network/otdht/Node.hpp"
#include "internal/network/otdht/Server.hpp"
#include "opentxs/api/network/Blockchain.hpp"
#include "opentxs/api/network/Network.hpp"
#include "opentxs/api/session/Session.hpp"
#include "opentxs/util/BlockchainProfile.hpp"
#include "opentxs/util/Container.hpp"
#include "opentxs/util/Options.hpp"

namespace opentxs::factory
{
auto OTDHT(
    const api::Session& api,
    const api::network::Blockchain& blockchain) noexcept
    -> std::unique_ptr<api::network::OTDHT>
{
    using ReturnType = api::network::implementation::OTDHT;

    return std::make_unique<ReturnType>(api, blockchain);
}
}  // namespace opentxs::factory

namespace opentxs::api::network::implementation
{
OTDHT::OTDHT(
    const api::Session& api,
    const api::network::Blockchain& blockchain) noexcept
    : api_(api)
    , blockchain_(blockchain)
    , node_()
{
}

auto OTDHT::AddPeer(std::string_view endpoint) const noexcept -> bool
{
    return blockchain_.Internal().AddSyncServer(endpoint);
}

auto OTDHT::ConnectedPeers() const noexcept -> Endpoints
{
    return blockchain_.Internal().ConnectedSyncServers();
}

auto OTDHT::DeletePeer(std::string_view endpoint) const noexcept -> bool
{
    return blockchain_.Internal().DeleteSyncServer(endpoint);
}

auto OTDHT::Disable(const Chain chain) const noexcept -> void
{
    const auto visitor = DisableChain{chain};
    std::visit(visitor, *node_.lock());
}

auto OTDHT::Enable(const Chain chain) const noexcept -> void
{
    const auto visitor = EnableChain{chain};
    std::visit(visitor, *node_.lock());
}

auto OTDHT::Endpoint(const Chain chain) const noexcept -> std::string_view
{
    static const auto visitor = ChainEndpoint{chain};

    return std::visit(visitor, *node_.lock_shared());
}

auto OTDHT::KnownPeers(alloc::Default alloc) const noexcept -> Endpoints
{
    return blockchain_.Internal().GetSyncServers(alloc);
}

auto OTDHT::Start(std::shared_ptr<const api::Session> api) noexcept -> void
{
    static const auto defaultServers = Vector<CString>{
        "tcp://metier1.opentransactions.org:8814",
        "tcp://metier2.opentransactions.org:8814",
        "tcp://ot01.matterfi.net:8814",
    };
    const auto& options = api_.GetOptions();
    const auto existing = [&] {
        auto out = Set<CString>{};

        // TODO allocator
        for (const auto& server : KnownPeers({})) {
            // TODO GetSyncServers should return pmr strings
            out.emplace(server.c_str());
        }

        for (const auto& server : defaultServers) {
            if (0 == out.count(server)) {
                if (false == options.TestMode()) { AddPeer(server); }

                out.emplace(server);
            }
        }

        return out;
    }();

    try {
        for (const auto& endpoint : options.RemoteBlockchainSyncServers()) {
            if (0 == existing.count(endpoint)) { AddPeer(endpoint); }
        }
    } catch (...) {
    }

    switch (options.BlockchainProfile()) {
        case BlockchainProfile::mobile:
        case BlockchainProfile::desktop: {
            opentxs::network::otdht::Node{api_}.Init(api);
        } break;
        case BlockchainProfile::server: {
            if (options.ProvideBlockchainSyncServer()) {
                *node_.lock() = opentxs::network::otdht::Server{
                    api_, api_.Network().ZeroMQ()};
            }
        } break;
        case BlockchainProfile::desktop_native:
        default: {
        }
    }
}

auto OTDHT::StartListener(
    std::string_view syncEndpoint,
    std::string_view publicSyncEndpoint,
    std::string_view updateEndpoint,
    std::string_view publicUpdateEndpoint) const noexcept -> bool
{
    const auto visitor = StartServer{
        syncEndpoint, publicSyncEndpoint, updateEndpoint, publicUpdateEndpoint};

    return std::visit(visitor, *node_.lock());
}

OTDHT::~OTDHT() { *node_.lock() = std::monostate{}; }
}  // namespace opentxs::api::network::implementation
