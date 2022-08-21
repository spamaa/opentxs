// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// IWYU pragma: no_include <boost/smart_ptr/detail/operator_bool.hpp>

#include "0_stdafx.hpp"                  // IWYU pragma: associated
#include "1_Internal.hpp"                // IWYU pragma: associated
#include "network/otdht/node/Actor.hpp"  // IWYU pragma: associated

#include <boost/smart_ptr/shared_ptr.hpp>
#include <chrono>
#include <memory>
#include <utility>

#include "internal/api/session/Endpoints.hpp"
#include "internal/api/session/Session.hpp"
#include "internal/network/otdht/Peer.hpp"
#include "internal/network/zeromq/Context.hpp"
#include "internal/util/LogMacros.hpp"
#include "internal/util/P0330.hpp"
#include "opentxs/api/network/Blockchain.hpp"
#include "opentxs/api/network/BlockchainHandle.hpp"
#include "opentxs/api/network/Network.hpp"
#include "opentxs/api/network/OTDHT.hpp"
#include "opentxs/api/session/Endpoints.hpp"
#include "opentxs/api/session/Session.hpp"
#include "opentxs/blockchain/BlockchainType.hpp"
#include "opentxs/blockchain/block/Position.hpp"
#include "opentxs/blockchain/block/Types.hpp"
#include "opentxs/blockchain/node/FilterOracle.hpp"
#include "opentxs/blockchain/node/Manager.hpp"
#include "opentxs/network/zeromq/Context.hpp"
#include "opentxs/network/zeromq/ZeroMQ.hpp"
#include "opentxs/network/zeromq/message/Frame.hpp"
#include "opentxs/network/zeromq/message/FrameSection.hpp"
#include "opentxs/network/zeromq/message/Message.hpp"
#include "opentxs/network/zeromq/socket/SocketType.hpp"
#include "opentxs/network/zeromq/socket/Types.hpp"
#include "opentxs/util/Container.hpp"
#include "opentxs/util/Log.hpp"
#include "opentxs/util/WorkType.hpp"

namespace opentxs::network::otdht
{
Node::Actor::Actor(
    std::shared_ptr<const api::Session> api,
    boost::shared_ptr<Shared> shared,
    zeromq::BatchID batchID,
    allocator_type alloc) noexcept
    : opentxs::Actor<Node::Actor, NodeJob>(
          *api,
          LogTrace(),
          {"OTDHT node", alloc},
          0ms,
          batchID,
          alloc,
          [&] {
              using Dir = zeromq::socket::Direction;
              auto sub = zeromq::EndpointArgs{alloc};
              sub.emplace_back(
                  CString{api->Endpoints().Shutdown(), alloc}, Dir::Connect);
              sub.emplace_back(
                  CString{
                      api->Endpoints().BlockchainSyncServerUpdated(), alloc},
                  Dir::Connect);
              sub.emplace_back(
                  CString{api->Endpoints().BlockchainNewFilter(), alloc},
                  Dir::Connect);
              sub.emplace_back(
                  CString{api->Endpoints().BlockchainStateChange(), alloc},
                  Dir::Connect);

              return sub;
          }(),
          [&] {
              using Dir = zeromq::socket::Direction;
              auto pull = zeromq::EndpointArgs{alloc};
              pull.emplace_back(
                  CString{api->Endpoints().Internal().OTDHTNode(), alloc},
                  Dir::Bind);

              return pull;
          }())
    , api_p_(std::move(api))
    , shared_p_(std::move(shared))
    , api_(*api_p_)
    , data_(shared_p_->data_)
    , peers_(alloc)
{
}

auto Node::Actor::do_shutdown() noexcept -> void
{
    shared_p_.reset();
    api_p_.reset();
}

auto Node::Actor::do_startup() noexcept -> bool
{
    if (api_.Internal().ShuttingDown()) { return true; }

    load_positions();
    load_peers();

    return false;
}

auto Node::Actor::load_peers() noexcept -> void
{
    for (const auto& peer :
         api_.Network().OTDHT().KnownPeers(get_allocator())) {
        process_peer(peer);
    }
}

auto Node::Actor::load_positions() noexcept -> void
{
    for (const auto& chain : Shared::Chains()) {
        try {
            const auto handle = api_.Network().Blockchain().GetChain(chain);

            if (false == handle.IsValid()) { continue; }

            const auto& filter = handle.get().FilterOracle();
            process_cfilter(chain, filter.FilterTip(filter.DefaultType()));
        } catch (...) {
        }
    }
}

auto Node::Actor::pipeline(const Work work, Message&& msg) noexcept -> void
{
    switch (work) {
        case Work::chain_state: {
            process_chain_state(std::move(msg));
        } break;
        case Work::new_cfilter: {
            process_new_cfilter(std::move(msg));
        } break;
        case Work::new_peer: {
            process_new_peer(std::move(msg));
        } break;
        case Work::shutdown:
        case Work::init:
        case Work::statemachine:
        default: {
            LogAbort()(OT_PRETTY_CLASS())(name_)(": unhandled message type ")(
                static_cast<OTZMQWorkType>(work))
                .Abort();
        }
    }
}

auto Node::Actor::process_cfilter(
    opentxs::blockchain::Type chain,
    opentxs::blockchain::block::Position&& tip) noexcept -> void
{
    auto handle = data_.lock();
    auto& map = handle->state_;

    if (auto it = map.find(chain); map.end() != it) {
        it->second = std::move(tip);
    }
}

auto Node::Actor::process_chain_state(Message&& msg) noexcept -> void
{
    const auto body = msg.Body();

    if (2 >= body.size()) {
        LogAbort()(OT_PRETTY_CLASS())(name_)(": invalid message").Abort();
    }

    const auto chain = body.at(1).as<opentxs::blockchain::Type>();
    auto enabled = body.at(2).as<bool>();
    auto tip = [&]() -> opentxs::blockchain::block::Position {
        try {
            const auto& network = api_.Network().Blockchain().GetChain(chain);
            const auto& filter = network.get().FilterOracle();

            return filter.FilterTip(filter.DefaultType());
        } catch (...) {
            enabled = false;

            return {};
        }
    }();

    auto handle = data_.lock();
    auto& map = handle->state_;

    if (enabled) {
        if (auto it = map.find(chain); map.end() != it) {
            it->second = std::move(tip);
        } else {
            const auto [i, rc] = map.try_emplace(chain, std::move(tip));

            OT_ASSERT(rc);
        }
    } else {
        map.erase(chain);
    }

    for (auto& [key, value] : peers_) {
        auto& [endpoint, socket] = value;
        socket.SendDeferred(Message{msg}, __FILE__, __LINE__);
    }
}

auto Node::Actor::process_new_cfilter(Message&& msg) noexcept -> void
{
    const auto body = msg.Body();

    if (4 >= body.size()) {
        LogAbort()(OT_PRETTY_CLASS())(name_)(": invalid message").Abort();
    }

    process_cfilter(
        body.at(1).as<opentxs::blockchain::Type>(),
        {body.at(3).as<opentxs::blockchain::block::Height>(),
         body.at(4).Bytes()});
}

auto Node::Actor::process_new_peer(Message&& msg) noexcept -> void
{
    const auto body = msg.Body();

    if (2 >= body.size()) {
        LogAbort()(OT_PRETTY_CLASS())(name_)(": invalid message").Abort();
    }

    const auto active = body.at(2).as<bool>();

    if (active) { process_peer(body.at(1).Bytes()); }
}

auto Node::Actor::process_peer(std::string_view endpoint) noexcept -> void
{
    // TODO c++20 use contains
    if (0_uz < peers_.count(endpoint)) { return; }

    auto alloc = get_allocator();
    using Socket = zeromq::socket::Type;
    auto [it, rc] = peers_.try_emplace(
        CString{endpoint, alloc},
        zeromq::MakeArbitraryInproc(alloc),
        api_.Network().ZeroMQ().Internal().RawSocket(Socket::Push));

    OT_ASSERT(rc);

    auto& [pushEndpoint, socket] = it->second;

    rc = socket.Connect(pushEndpoint.data());

    OT_ASSERT(rc);

    Peer{api_p_, shared_p_, endpoint, pushEndpoint};
}

auto Node::Actor::work() noexcept -> bool { return false; }

Node::Actor::~Actor() = default;
}  // namespace opentxs::network::otdht
