// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "0_stdafx.hpp"                    // IWYU pragma: associated
#include "1_Internal.hpp"                  // IWYU pragma: associated
#include "api/network/blockchain/Imp.hpp"  // IWYU pragma: associated

#include <algorithm>
#include <future>
#include <iterator>
#include <type_traits>
#include <utility>

#include "api/network/blockchain/BlockchainHandle.hpp"
#include "blockchain/database/common/Database.hpp"
#include "internal/api/network/OTDHT.hpp"
#include "internal/api/session/Endpoints.hpp"
#include "internal/blockchain/Params.hpp"
#include "internal/blockchain/node/Factory.hpp"
#include "internal/blockchain/node/Manager.hpp"
#include "internal/network/zeromq/Batch.hpp"
#include "internal/network/zeromq/Context.hpp"
#include "internal/network/zeromq/socket/Raw.hpp"
#include "internal/util/LogMacros.hpp"
#include "opentxs/api/network/Network.hpp"
#include "opentxs/api/network/OTDHT.hpp"
#include "opentxs/api/session/Endpoints.hpp"
#include "opentxs/api/session/Session.hpp"
#include "opentxs/blockchain/Blockchain.hpp"
#include "opentxs/blockchain/Types.hpp"
#include "opentxs/blockchain/node/FilterOracle.hpp"
#include "opentxs/blockchain/node/Manager.hpp"
#include "opentxs/blockchain/p2p/Types.hpp"
#include "opentxs/network/zeromq/Context.hpp"
#include "opentxs/network/zeromq/ZeroMQ.hpp"
#include "opentxs/network/zeromq/message/Message.hpp"
#include "opentxs/network/zeromq/message/Message.tpp"
#include "opentxs/network/zeromq/socket/Push.hpp"
#include "opentxs/network/zeromq/socket/SocketType.hpp"
#include "opentxs/network/zeromq/socket/Types.hpp"
#include "opentxs/util/Log.hpp"
#include "opentxs/util/Options.hpp"
#include "opentxs/util/Pimpl.hpp"
#include "opentxs/util/WorkType.hpp"
#include "util/Work.hpp"

namespace opentxs::api::network::implementation
{
BlockchainImp::BlockchainImp(
    const api::Session& api,
    const api::session::Endpoints& endpoints,
    const opentxs::network::zeromq::Context& zmq) noexcept
    : api_(api)
    , crypto_(nullptr)
    , block_available_endpoint_(opentxs::network::zeromq::MakeArbitraryInproc())
    , block_queue_endpoint_(opentxs::network::zeromq::MakeArbitraryInproc())
    , reorg_endpoint_(opentxs::network::zeromq::MakeArbitraryInproc())
    , handle_(zmq.Internal().MakeBatch(
          [&] {
              using Type = opentxs::network::zeromq::socket::Type;
              auto out = Vector<Type>{};
              out.emplace_back(Type::Publish);  // NOTE block_available_out_
              out.emplace_back(Type::Publish);  // NOTE block_queue_out_
              out.emplace_back(Type::Publish);  // NOTE reorg_out_
              out.emplace_back(Type::Pull);     // NOTE block_available_in_
              out.emplace_back(Type::Pull);     // NOTE block_queue_in_
              out.emplace_back(Type::Pull);     // NOTE reorg_in_

              return out;
          }(),
          "api::network::Blockchain"))
    , batch_(handle_.batch_)
    , block_available_out_([&]() -> auto& {
        auto& socket = batch_.sockets_.at(0);
        const auto rc =
            socket.Bind(endpoints.BlockchainBlockAvailable().data());

        OT_ASSERT(rc);

        return socket;
    }())
    , block_queue_out_([&]() -> auto& {
        auto& socket = batch_.sockets_.at(1);
        const auto rc =
            socket.Bind(endpoints.BlockchainBlockDownloadQueue().data());

        OT_ASSERT(rc);

        return socket;
    }())
    , reorg_out_([&]() -> auto& {
        auto& socket = batch_.sockets_.at(2);
        const auto rc = socket.Bind(endpoints.BlockchainReorg().data());

        OT_ASSERT(rc);

        return socket;
    }())
    , block_available_in_([&]() -> auto& {
        auto& socket = batch_.sockets_.at(3);
        const auto rc = socket.Bind(block_available_endpoint_.c_str());

        OT_ASSERT(rc);

        return socket;
    }())
    , block_queue_in_([&]() -> auto& {
        auto& socket = batch_.sockets_.at(4);
        const auto rc = socket.Bind(block_queue_endpoint_.c_str());

        OT_ASSERT(rc);

        return socket;
    }())
    , reorg_in_([&]() -> auto& {
        auto& socket = batch_.sockets_.at(5);
        const auto rc = socket.Bind(reorg_endpoint_.c_str());

        OT_ASSERT(rc);

        return socket;
    }())
    , thread_(zmq.Internal().Start(
          batch_.id_,
          {
              {block_available_in_.ID(),
               &block_available_in_,
               [socket = &block_available_out_](auto&& m) {
                   socket->SendDeferred(std::move(m), __FILE__, __LINE__);
               }},
              {block_queue_in_.ID(),
               &block_queue_in_,
               [socket = &block_queue_out_](auto&& m) {
                   socket->SendDeferred(std::move(m), __FILE__, __LINE__);
               }},
              {reorg_in_.ID(),
               &reorg_in_,
               [socket = &reorg_out_](auto&& m) {
                   socket->SendDeferred(std::move(m), __FILE__, __LINE__);
               }},
          }))
    , active_peer_updates_([&] {
        auto out = zmq.PublishSocket();
        const auto listen = out->Start(endpoints.BlockchainPeer().data());

        OT_ASSERT(listen);

        return out;
    }())
    , chain_state_publisher_([&] {
        auto out = zmq.PublishSocket();
        auto rc = out->Start(endpoints.BlockchainStateChange().data());

        OT_ASSERT(rc);

        return out;
    }())
    , connected_peer_updates_([&] {
        auto out = zmq.PublishSocket();
        const auto listen =
            out->Start(endpoints.BlockchainPeerConnection().data());

        OT_ASSERT(listen);

        return out;
    }())
    , new_filters_([&] {
        auto out = zmq.PublishSocket();
        const auto listen = out->Start(endpoints.BlockchainNewFilter().data());

        OT_ASSERT(listen);

        return out;
    }())
    , sync_updates_([&] {
        auto out = zmq.PublishSocket();
        const auto listen =
            out->Start(endpoints.BlockchainSyncProgress().data());

        OT_ASSERT(listen);

        return out;
    }())
    , mempool_([&] {
        auto out = zmq.PublishSocket();
        const auto listen = out->Start(endpoints.BlockchainMempool().data());

        OT_ASSERT(listen);

        return out;
    }())
    , startup_publisher_(endpoints, zmq)
    , base_config_()
    , db_()
    , lock_()
    , config_()
    , networks_()
    , running_(true)
{
    OT_ASSERT(nullptr != thread_);
}

auto BlockchainImp::AddSyncServer(
    const std::string_view endpoint) const noexcept -> bool
{
    return db_.get().AddSyncServer(endpoint);
}

auto BlockchainImp::ConnectedSyncServers() const noexcept -> Endpoints
{
    return {};  // TODO
}

auto BlockchainImp::DeleteSyncServer(
    const std::string_view endpoint) const noexcept -> bool
{
    return db_.get().DeleteSyncServer(endpoint);
}

auto BlockchainImp::Disable(const Chain type) const noexcept -> bool
{
    auto lock = Lock{lock_};

    return disable(lock, type);
}

auto BlockchainImp::disable(const Lock& lock, const Chain type) const noexcept
    -> bool
{
    if (0 == opentxs::blockchain::SupportedChains().count(type)) {
        LogError()(OT_PRETTY_CLASS())("Unsupported chain").Flush();

        return false;
    }

    stop(lock, type);

    if (db_.get().Disable(type)) { return true; }

    LogError()(OT_PRETTY_CLASS())("Database update failure").Flush();

    return false;
}

auto BlockchainImp::Enable(const Chain type, const std::string_view seednode)
    const noexcept -> bool
{
    auto lock = Lock{lock_};

    return enable(lock, type, seednode);
}

auto BlockchainImp::enable(
    const Lock& lock,
    const Chain type,
    const std::string_view seednode) const noexcept -> bool
{
    if (0 == opentxs::blockchain::SupportedChains().count(type)) {
        LogError()(OT_PRETTY_CLASS())("Unsupported chain").Flush();

        return false;
    }

    if (false == db_.get().Enable(type, seednode)) {
        LogError()(OT_PRETTY_CLASS())("Database error").Flush();

        return false;
    }

    return start(lock, type, seednode);
}

auto BlockchainImp::EnabledChains(alloc::Default alloc) const noexcept
    -> Set<Chain>
{
    auto out = Set<Chain>{alloc};
    const auto data = [&] {
        auto lock = Lock{lock_};

        return db_.get().LoadEnabledChains();
    }();
    std::transform(
        data.begin(),
        data.end(),
        std::inserter(out, out.begin()),
        [](const auto value) { return value.first; });

    return out;
}

auto BlockchainImp::GetChain(const Chain type) const noexcept(false)
    -> BlockchainHandle
{
    auto lock = Lock{lock_};

    return std::make_unique<BlockchainHandle::Imp>(networks_.at(type))
        .release();
}

auto BlockchainImp::GetSyncServers(alloc::Default alloc) const noexcept
    -> Endpoints
{
    return db_.get().GetSyncServers(alloc);
}

auto BlockchainImp::Hello(alloc::Default alloc) const noexcept
    -> opentxs::network::otdht::StateData
{
    auto lock = Lock{lock_};
    auto chains = [&] {
        auto output = Chains{};

        for (const auto& [chain, network] : networks_) {
            output.emplace_back(chain);
        }

        return output;
    }();

    return hello(lock, chains, alloc);
}

auto BlockchainImp::hello(
    const Lock&,
    const Chains& chains,
    alloc::Default alloc) const noexcept -> opentxs::network::otdht::StateData
{
    auto output = opentxs::network::otdht::StateData{alloc};

    for (const auto chain : chains) {
        const auto& network = networks_.at(chain);
        const auto& filter = network->FilterOracle();
        const auto type = filter.DefaultType();
        output.emplace_back(chain, filter.FilterTip(type));
    }

    return output;
}

auto BlockchainImp::Init(
    const api::crypto::Blockchain& crypto,
    const api::Legacy& legacy,
    const std::filesystem::path& dataFolder,
    const Options& options) noexcept -> void
{
    crypto_ = &crypto;
    base_config_.set_value([&] {
        auto output = Config{};
        output.profile_ = options.BlockchainProfile();

        switch (output.profile_) {
            case BlockchainProfile::mobile:
            case BlockchainProfile::desktop:
            case BlockchainProfile::desktop_native: {
                output.disable_wallet_ = !options.BlockchainWalletEnabled();
            } break;
            case BlockchainProfile::server: {
                if (options.ProvideBlockchainSyncServer()) {
                    output.provide_sync_server_ = true;
                    output.disable_wallet_ = true;
                } else {
                    output.disable_wallet_ = !options.BlockchainWalletEnabled();
                }
            } break;
            default: {
                LogAbort()(OT_PRETTY_CLASS())("invalid profile").Abort();
            }
        }

        return output;
    }());
    db_.set_value(DB{api_, crypto, legacy, dataFolder, options});
}

auto BlockchainImp::IsEnabled(
    const opentxs::blockchain::Type chain) const noexcept -> bool
{
    auto lock = Lock{lock_};

    for (const auto& [enabled, peer] : db_.get().LoadEnabledChains()) {
        if (chain == enabled) { return true; }
    }

    return false;
}

auto BlockchainImp::Profile() const noexcept -> BlockchainProfile
{
    return base_config_.get().profile_;
}

auto BlockchainImp::publish_chain_state(Chain type, bool state) const -> void
{
    chain_state_publisher_->Send([&] {
        auto work = opentxs::network::zeromq::tagged_message(
            WorkType::BlockchainStateChange);
        work.AddFrame(type);
        work.AddFrame(state);

        return work;
    }());
}

auto BlockchainImp::PublishStartup(
    const opentxs::blockchain::Type chain,
    OTZMQWorkType type) const noexcept -> bool
{
    using Dir = opentxs::network::zeromq::socket::Direction;
    auto push = api_.Network().ZeroMQ().PushSocket(Dir::Connect);
    auto out =
        push->Start(api_.Endpoints().Internal().BlockchainStartupPull().data());
    out &= push->Send([&] {
        auto out = MakeWork(type);
        out.AddFrame(chain);

        return out;
    }());

    return out;
}

auto BlockchainImp::ReportProgress(
    const Chain chain,
    const opentxs::blockchain::block::Height current,
    const opentxs::blockchain::block::Height target) const noexcept -> void
{
    sync_updates_->Send([&] {
        auto work = opentxs::network::zeromq::tagged_message(
            WorkType::BlockchainSyncProgress);
        work.AddFrame(chain);
        work.AddFrame(current);
        work.AddFrame(target);

        return work;
    }());
}

auto BlockchainImp::RestoreNetworks() const noexcept -> void
{
    auto lock = Lock{lock_};

    for (const auto& [chain, peer] : db_.get().LoadEnabledChains()) {
        start(lock, chain, peer, false);
    }

    for (auto& [chain, pNode] : networks_) { pNode->Internal().StartWallet(); }
}

auto BlockchainImp::Shutdown() noexcept -> void
{
    if (running_.exchange(false)) {
        LogVerbose()("Shutting down ")(networks_.size())(" blockchain clients")
            .Flush();

        for (auto& [chain, network] : networks_) {
            network->Internal().Shutdown().get();
        }

        networks_.clear();
    }

    Imp::Shutdown();
}

auto BlockchainImp::Start(const Chain type, const std::string_view seednode)
    const noexcept -> bool
{
    auto lock = Lock{lock_};

    return start(lock, type, seednode);
}

auto BlockchainImp::start(
    const Lock& lock,
    const Chain type,
    const std::string_view seednode,
    const bool startWallet) const noexcept -> bool
{
    if (Chain::UnitTest != type) {
        if (0 == opentxs::blockchain::SupportedChains().count(type)) {
            LogError()(OT_PRETTY_CLASS())("Unsupported chain").Flush();

            return false;
        }
    }

    if (0 != networks_.count(type)) {
        LogVerbose()(OT_PRETTY_CLASS())("Chain already running").Flush();

        return true;
    } else {
        LogConsole()("Starting ")(print(type))(" client").Flush();
    }

    namespace p2p = opentxs::blockchain::p2p;

    switch (opentxs::blockchain::params::Chains().at(type).p2p_protocol_) {
        case p2p::Protocol::bitcoin: {
            auto endpoint = UnallocatedCString{};

            if (base_config_.get().provide_sync_server_) {
                const auto& dht = api_.Network().OTDHT().Internal();
                dht.Enable(type);
                endpoint = dht.Endpoint(type);
            }

            const auto& config = [&]() -> const Config& {
                {
                    auto it = config_.find(type);

                    if (config_.end() != it) { return it->second; }
                }

                auto [it, added] = config_.emplace(type, base_config_);

                OT_ASSERT(added);

                if (false == api_.GetOptions().TestMode()) {
                    switch (type) {
                        case Chain::UnitTest: {
                        } break;
                        default: {
                            auto& profile = it->second.profile_;

                            if (BlockchainProfile::desktop_native == profile) {
                                profile = BlockchainProfile::desktop;
                            }
                        }
                    }
                }

                return it->second;
            }();
            auto [it, added] = networks_.emplace(
                type,
                factory::BlockchainNetworkBitcoin(
                    api_, type, config, seednode, endpoint));
            LogConsole()(print(type))(" client is running").Flush();
            publish_chain_state(type, true);
            auto& pNode = it->second;
            auto& node = *pNode;
            node.Internal().Start(pNode);

            if (startWallet) { node.Internal().StartWallet(); }

            return node.Connect();
        }
        case p2p::Protocol::opentxs:
        case p2p::Protocol::ethereum:
        default: {
        }
    }

    return false;
}

auto BlockchainImp::Stop(const Chain type) const noexcept -> bool
{
    auto lock = Lock{lock_};

    return stop(lock, type);
}

auto BlockchainImp::stop(const Lock& lock, const Chain type) const noexcept
    -> bool
{
    auto it = networks_.find(type);

    if (networks_.end() == it) { return true; }

    OT_ASSERT(it->second);

    api_.Network().OTDHT().Internal().Disable(type);
    it->second->Internal().Shutdown().get();
    networks_.erase(it);
    LogVerbose()(OT_PRETTY_CLASS())("stopped chain ")(print(type)).Flush();
    publish_chain_state(type, false);

    return true;
}

auto BlockchainImp::UpdatePeer(
    const opentxs::blockchain::Type chain,
    const std::string_view address) const noexcept -> void
{
    active_peer_updates_->Send([&] {
        auto work = MakeWork(WorkType::BlockchainPeerAdded);
        work.AddFrame(chain);
        work.AddFrame(address.data(), address.size());

        return work;
    }());
}

BlockchainImp::~BlockchainImp() { batch_.ClearCallbacks(); }
}  // namespace opentxs::api::network::implementation
