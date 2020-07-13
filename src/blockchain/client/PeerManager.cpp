// Copyright (c) 2010-2020 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "0_stdafx.hpp"                       // IWYU pragma: associated
#include "1_Internal.hpp"                     // IWYU pragma: associated
#include "blockchain/client/PeerManager.hpp"  // IWYU pragma: associated

#include <chrono>
#include <memory>
#include <optional>
#include <string_view>

#include "core/Worker.hpp"
#include "internal/blockchain/client/Client.hpp"
#include "internal/blockchain/client/Factory.hpp"
#include "internal/blockchain/p2p/P2P.hpp"  // IWYU pragma: keep
#include "opentxs/Bytes.hpp"
#include "opentxs/Pimpl.hpp"
#include "opentxs/api/Core.hpp"
#include "opentxs/blockchain/block/bitcoin/Transaction.hpp"
#include "opentxs/core/Flag.hpp"
#include "opentxs/core/Log.hpp"
#include "opentxs/core/LogSource.hpp"
#include "opentxs/network/zeromq/Frame.hpp"
#include "opentxs/network/zeromq/FrameSection.hpp"
#include "opentxs/network/zeromq/Message.hpp"
#include "opentxs/network/zeromq/Pipeline.hpp"

#define OT_METHOD "opentxs::blockchain::client::implementation::PeerManager::"

namespace opentxs::factory
{
auto BlockchainPeerManager(
    const api::Core& api,
    const blockchain::client::internal::Network& network,
    const blockchain::client::internal::PeerDatabase& database,
    const blockchain::client::internal::IO& io,
    const blockchain::Type type,
    const std::string& seednode,
    const std::string& shutdown) noexcept
    -> std::unique_ptr<blockchain::client::internal::PeerManager>
{
    using ReturnType = blockchain::client::implementation::PeerManager;

    return std::make_unique<ReturnType>(
        api, network, database, io, type, seednode, shutdown);
}
}  // namespace opentxs::factory

namespace opentxs::blockchain::client::implementation
{
PeerManager::PeerManager(
    const api::Core& api,
    const internal::Network& network,
    const internal::PeerDatabase& database,
    const blockchain::client::internal::IO& io,
    const Type chain,
    const std::string& seednode,
    const std::string& shutdown) noexcept
    : internal::PeerManager()
    , Worker(api, std::chrono::milliseconds(100))
    , database_(database)
    , io_context_(io)
    , jobs_(api)
    , peers_(
          api,
          network,
          database_,
          *this,
          running_,
          shutdown,
          chain,
          seednode,
          io_context_,
          peer_target(database_))
    , init_promise_()
    , init_(init_promise_.get_future())
{
    init_executor({shutdown});
}

auto PeerManager::AddPeer(const p2p::Address& address) const noexcept -> bool
{
    if (false == running_.get()) { return false; }

    auto promise = std::promise<bool>{};
    auto future = promise.get_future();
    auto work = MakeWork(Work::AddPeer);
    work->AddFrame(reinterpret_cast<std::uintptr_t>(&address));
    work->AddFrame(reinterpret_cast<std::uintptr_t>(&promise));
    pipeline_->Push(work);

    while (running_.get()) {
        if (std::future_status::ready ==
            future.wait_for(std::chrono::seconds(5))) {
            return future.get();
        }
    }

    return false;
}

auto PeerManager::BroadcastTransaction(
    const block::bitcoin::Transaction& tx) const noexcept -> bool
{
    if (false == running_.get()) { return false; }

    if (0 == peers_.Count()) { return false; }

    auto bytes = Space{};

    if (false == tx.Serialize(writer(bytes))) { return false; }

    const auto view = reader(bytes);
    auto work = jobs_.Work(Task::BroadcastTransaction);
    work->AddFrame(view.data(), view.size());
    jobs_.Dispatch(work);

    return true;
}

auto PeerManager::Connect() noexcept -> bool
{
    if (false == running_.get()) { return false; }

    trigger();

    return true;
}

auto PeerManager::Disconnect(const int id) const noexcept -> void
{
    auto work = MakeWork(Work::Disconnect);
    work->AddFrame(id);
    pipeline_->Push(work);
}

auto PeerManager::init() noexcept -> void
{
    init_promise_.set_value();
    trigger();
}

auto PeerManager::peer_target(const internal::PeerDatabase& db) noexcept
    -> std::size_t
{
    switch (db.BlockPolicy()) {
        case api::client::blockchain::BlockStorage::All: {

            return 8;
        }
        case api::client::blockchain::BlockStorage::Cache: {

            return 2;
        }
        case api::client::blockchain::BlockStorage::None:
        default: {

            return 1;
        }
    }
}

auto PeerManager::pipeline(zmq::Message& message) noexcept -> void
{
    if (false == running_.get()) { return; }

    const auto body = message.Body();

    OT_ASSERT(0 < body.size());

    switch (body.at(0).as<Work>()) {
        case Work::Disconnect: {
            OT_ASSERT(1 < body.size());

            peers_.Disconnect(body.at(1).as<int>());
            do_work();
        } break;
        case Work::AddPeer: {
            OT_ASSERT(2 < body.size());

            auto* address_p = reinterpret_cast<const p2p::Address*>(
                body.at(1).as<std::uintptr_t>());
            auto* promise_p = reinterpret_cast<std::promise<bool>*>(
                body.at(2).as<std::uintptr_t>());

            OT_ASSERT(nullptr != address_p);
            OT_ASSERT(nullptr != promise_p);

            const auto& address = *address_p;
            auto& promise = *promise_p;

            peers_.AddPeer(address, promise);
            do_work();
        } break;
        case Work::StateMachine: {
            do_work();
        } break;
        case Work::Shutdown: {
            shutdown(shutdown_promise_);
        } break;
        default: {
            OT_FAIL;
        }
    }
}

auto PeerManager::RequestBlock(const block::Hash& block) const noexcept -> bool
{
    return RequestBlocks({block.Bytes()});
}

auto PeerManager::RequestBlocks(
    const std::vector<ReadView>& hashes) const noexcept -> bool
{
    if (false == running_.get()) { return false; }

    if (0 == peers_.Count()) { return false; }

    auto work = jobs_.Work(Task::Getblock);

    for (const auto& block : hashes) {
        work->AddFrame(block.data(), block.size());
    }

    jobs_.Dispatch(work);

    return true;
}

auto PeerManager::RequestFilterHeaders(
    const filter::Type type,
    const block::Height start,
    const block::Hash& stop) const noexcept -> bool
{
    if (false == running_.get()) { return false; }

    if (0 == peers_.Count()) { return false; }

    auto work = jobs_.Work(Task::Getcfheaders);
    work->AddFrame(type);
    work->AddFrame(start);
    work->AddFrame(stop);
    jobs_.Dispatch(work);

    return true;
}

auto PeerManager::RequestFilters(
    const filter::Type type,
    const block::Height start,
    const block::Hash& stop) const noexcept -> bool
{
    if (false == running_.get()) { return false; }

    if (0 == peers_.Count()) { return false; }

    auto work = jobs_.Work(Task::Getcfilters);
    work->AddFrame(type);
    work->AddFrame(start);
    work->AddFrame(stop);
    jobs_.Dispatch(work);

    return true;
}

auto PeerManager::RequestHeaders() const noexcept -> bool
{
    if (false == running_.get()) { return false; }

    if (0 == peers_.Count()) { return false; }

    jobs_.Dispatch(Task::Getheaders);

    return true;
}

auto PeerManager::shutdown(std::promise<void>& promise) noexcept -> void
{
    init_.get();

    if (running_->Off()) {
        jobs_.Shutdown();
        peers_.Shutdown();

        try {
            promise.set_value();
        } catch (...) {
        }
    }
}

auto PeerManager::state_machine() noexcept -> bool
{
    LogTrace(OT_METHOD)(__FUNCTION__).Flush();

    if (false == running_.get()) { return false; }

    return peers_.Run();
}

PeerManager::~PeerManager() { Shutdown().get(); }
}  // namespace opentxs::blockchain::client::implementation
