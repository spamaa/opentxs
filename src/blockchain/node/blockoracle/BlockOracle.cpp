// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// IWYU pragma: no_include <boost/smart_ptr/detail/operator_bool.hpp>

#include "0_stdafx.hpp"    // IWYU pragma: associated
#include "1_Internal.hpp"  // IWYU pragma: associated
#include "blockchain/node/blockoracle/BlockOracle.hpp"  // IWYU pragma: associated

#include <boost/smart_ptr/make_shared.hpp>
#include <boost/smart_ptr/shared_ptr.hpp>
#include <chrono>
#include <cstddef>
#include <exception>
#include <memory>
#include <utility>

#include "blockchain/node/blockoracle/BlockBatch.hpp"
#include "internal/api/network/Asio.hpp"
#include "internal/api/session/Session.hpp"
#include "internal/blockchain/database/Database.hpp"
#include "internal/blockchain/node/Config.hpp"
#include "internal/blockchain/node/Endpoints.hpp"
#include "internal/blockchain/node/Manager.hpp"
#include "internal/network/zeromq/Context.hpp"
#include "internal/util/LogMacros.hpp"
#include "opentxs/api/network/Asio.hpp"
#include "opentxs/api/network/Network.hpp"
#include "opentxs/api/session/Session.hpp"
#include "opentxs/blockchain/Types.hpp"
#include "opentxs/blockchain/node/Manager.hpp"
#include "opentxs/network/zeromq/Context.hpp"
#include "opentxs/network/zeromq/ZeroMQ.hpp"
#include "opentxs/network/zeromq/message/FrameSection.hpp"
#include "opentxs/network/zeromq/message/Message.hpp"
#include "opentxs/network/zeromq/socket/SocketType.hpp"
#include "opentxs/util/Allocator.hpp"
#include "opentxs/util/BlockchainProfile.hpp"
#include "opentxs/util/Container.hpp"
#include "opentxs/util/Log.hpp"
#include "opentxs/util/WorkType.hpp"
#include "util/ScopeGuard.hpp"
#include "util/Work.hpp"

namespace opentxs::blockchain::node
{
auto print(BlockOracleJobs state) noexcept -> std::string_view
{
    using namespace std::literals;

    try {
        static const auto map = Map<BlockOracleJobs, std::string_view>{
            {BlockOracleJobs::shutdown, "shutdown"sv},
            {BlockOracleJobs::request_blocks, "request_blocks"sv},
            {BlockOracleJobs::process_block, "process_block"sv},
            {BlockOracleJobs::init, "init"sv},
            {BlockOracleJobs::statemachine, "statemachine"sv},
        };

        return map.at(state);
    } catch (...) {
        LogError()(__FUNCTION__)(": invalid BlockOracleJobs: ")(
            static_cast<OTZMQWorkType>(state))
            .Flush();

        OT_FAIL;
    }
}
}  // namespace opentxs::blockchain::node

namespace opentxs::blockchain::node::internal
{
BlockOracle::Shared::Shared(
    std::shared_ptr<const api::Session> api,
    std::shared_ptr<const node::Manager> node,
    allocator_type alloc) noexcept
    : api_p_(std::move(api))
    , node_p_(std::move(node))
    , submit_endpoint_(network::zeromq::MakeArbitraryInproc(alloc.resource()))
    , cache_(
          *api_p_,
          *node_p_,
          node_p_->Internal().GetConfig(),
          node_p_->Internal().DB(),
          node_p_->Internal().Chain(),
          alloc)
    , to_actor_([&] {
        using Type = network::zeromq::socket::Type;
        auto out = api_p_->Network().ZeroMQ().Internal().RawSocket(Type::Push);
        const auto rc = out.Connect(submit_endpoint_.c_str());

        OT_ASSERT(rc);

        return out;
    }())
    , db_(node_p_->Internal().DB())
    , validator_(
          get_validator(node_p_->Internal().Chain(), node_p_->HeaderOracle()))
    , block_fetcher_([&]() -> OptionalFetcher {
        switch (node_p_->Internal().GetConfig().profile_) {
            case BlockchainProfile::mobile:
            case BlockchainProfile::desktop:
            case BlockchainProfile::desktop_native: {

                return std::nullopt;
            }
            case BlockchainProfile::server: {

                return blockoracle::BlockFetcher{api_p_, node_p_};
            }
            default: {
                OT_FAIL;
            }
        }
    }())
{
    OT_ASSERT(validator_);
}

auto BlockOracle::Shared::GetBlockBatch(
    boost::shared_ptr<Shared> me) const noexcept -> BlockBatch
{
    auto alloc = alloc::PMR<BlockBatch::Imp>{get_allocator()};
    auto [id, hashes] = cache_.lock()->GetBatch(alloc);
    const auto batchID{id};  // TODO c++20 lambda capture structured binding
    auto* imp = alloc.allocate(1);
    alloc.construct(
        imp,
        id,
        std::move(hashes),
        [me](const auto bytes) { me->cache_.lock()->ReceiveBlock(bytes); },
        std::make_shared<ScopeGuard>(
            [me, batchID] { me->cache_.lock()->FinishBatch(batchID); }));

    return imp;
}

auto BlockOracle::Shared::GetBlockJob() const noexcept -> BlockBatch
{
    auto handle = block_fetcher_.lock();
    auto& fetcher = *handle;

    if (fetcher.has_value()) {

        return fetcher->GetJob({});  // TODO allocator
    } else {

        return {};
    }
}

auto BlockOracle::Shared::get_allocator() const noexcept -> allocator_type
{
    return cache_.lock()->get_allocator();
}

auto BlockOracle::Shared::LoadBitcoin(const block::Hash& block) const noexcept
    -> BitcoinBlockResult
{
    auto output = cache_.lock()->Request(block);
    trigger();

    return output;
}

auto BlockOracle::Shared::LoadBitcoin(
    const Vector<block::Hash>& hashes) const noexcept -> BitcoinBlockResults
{
    auto output = cache_.lock()->Request(hashes);
    trigger();

    OT_ASSERT(hashes.size() == output.size());

    return output;
}

auto BlockOracle::Shared::Shutdown() noexcept -> void
{
    block_fetcher_.lock()->reset();
    node_p_.reset();
    api_p_.reset();
}

auto BlockOracle::Shared::StartDownloader() noexcept -> void
{
    auto handle = block_fetcher_.lock();
    auto& fetcher = *handle;

    if (fetcher.has_value()) { fetcher->Init(); }
}

auto BlockOracle::Shared::SubmitBlock(const ReadView in) const noexcept -> void
{
    to_actor_.lock()->SendDeferred([&] {
        auto out = MakeWork(Actor::Work::process_block);
        out.AddFrame(in.data(), in.size());

        return out;
    }());
}

auto BlockOracle::Shared::trigger() const noexcept -> void
{
    to_actor_.lock()->SendDeferred(MakeWork(OT_ZMQ_STATE_MACHINE_SIGNAL));
}
}  // namespace opentxs::blockchain::node::internal

namespace opentxs::blockchain::node::internal
{
BlockOracle::Actor::Actor(
    std::shared_ptr<const api::Session> api,
    std::shared_ptr<const node::Manager> node,
    boost::shared_ptr<Shared> shared,
    network::zeromq::BatchID batch,
    allocator_type alloc) noexcept
    : opentxs::Actor<BlockOracle::Actor, BlockOracleJobs>(
          *api,
          LogTrace(),
          [&] {
              using namespace std::literals;
              auto out = CString{alloc};
              out.append(print(node->Internal().Chain()));
              out.append(" block oracle"sv);

              return out;
          }(),
          50ms,
          std::move(batch),
          alloc,
          [&] {
              auto subscribe = network::zeromq::EndpointArgs{alloc};
              subscribe.emplace_back(
                  node->Internal().Endpoints().shutdown_publish_,
                  Direction::Connect);

              return subscribe;
          }(),
          [&] {
              auto pull = network::zeromq::EndpointArgs{alloc};
              pull.emplace_back(shared->submit_endpoint_, Direction::Bind);

              return pull;
          }())
    , api_p_(std::move(api))
    , node_p_(std::move(node))
    , shared_(std::move(shared))
    , api_(*api_p_)
    , node_(*node_p_)
    , cache_(shared_->cache_)
    , heartbeat_(api_.Network().Asio().Internal().GetTimer())
{
}

auto BlockOracle::Actor::do_shutdown() noexcept -> void
{
    heartbeat_.Cancel();
    cache_.lock()->Shutdown();
    shared_->Shutdown();
    shared_.reset();
    node_p_.reset();
    api_p_.reset();
}

auto BlockOracle::Actor::do_startup() noexcept -> void
{
    if ((api_.Internal().ShuttingDown()) || (node_.Internal().ShuttingDown())) {
        shutdown_actor();
    } else {
        reset_timer(heartbeat_interval_, heartbeat_, Work::statemachine);
    }
}

auto BlockOracle::Actor::Init(boost::shared_ptr<Actor> me) noexcept -> void
{
    signal_startup(me);
}

auto BlockOracle::Actor::pipeline(const Work work, Message&& msg) noexcept
    -> void
{
    switch (work) {
        case Work::shutdown: {
            shutdown_actor();
        } break;
        case Work::request_blocks: {
            cache_.lock()->ProcessBlockRequests(std::move(msg));
        } break;
        case Work::process_block: {
            const auto body = msg.Body();

            if (1 >= body.size()) {
                LogError()(OT_PRETTY_CLASS())("No block").Flush();

                OT_FAIL;
            }

            cache_.lock()->ReceiveBlock(body.at(1));
            do_work();
        } break;
        case Work::init: {
            do_init();
        } break;
        case Work::statemachine: {
            do_work();
            reset_timer(heartbeat_interval_, heartbeat_, Work::statemachine);
        } break;
        default: {
            LogError()(OT_PRETTY_CLASS())(name_)(" unhandled message type ")(
                static_cast<OTZMQWorkType>(work))
                .Flush();

            OT_FAIL;
        }
    }
}

auto BlockOracle::Actor::work() noexcept -> bool
{
    return cache_.lock()->StateMachine();
}

BlockOracle::Actor::~Actor() = default;
}  // namespace opentxs::blockchain::node::internal

namespace opentxs::blockchain::node::internal
{
BlockOracle::BlockOracle() noexcept
    : shared_()
    , actor_()
{
}

auto BlockOracle::DownloadQueue() const noexcept -> std::size_t
{
    return shared_->cache_.lock_shared()->DownloadQueue();
}

auto BlockOracle::Endpoint() const noexcept -> std::string_view
{
    return shared_->submit_endpoint_;
}

auto BlockOracle::GetBlockBatch() const noexcept -> BlockBatch
{
    return shared_->GetBlockBatch(shared_);
}

auto BlockOracle::GetBlockJob() const noexcept -> BlockBatch
{
    return shared_->GetBlockJob();
}

auto BlockOracle::Init() noexcept -> void { shared_->StartDownloader(); }

auto BlockOracle::LoadBitcoin(const block::Hash& block) const noexcept
    -> BitcoinBlockResult
{
    return shared_->LoadBitcoin(block);
}

auto BlockOracle::LoadBitcoin(const Vector<block::Hash>& hashes) const noexcept
    -> BitcoinBlockResults
{
    return shared_->LoadBitcoin(hashes);
}

auto BlockOracle::Shutdown() noexcept -> void
{
    shared_->to_actor_.lock()->SendDeferred(MakeWork(WorkType::Shutdown));
}

auto BlockOracle::Start(
    std::shared_ptr<const api::Session> api,
    std::shared_ptr<const node::Manager> node) noexcept -> void
{
    OT_ASSERT(api);
    OT_ASSERT(node);

    const auto& zmq = api->Network().ZeroMQ().Internal();
    const auto batchID = zmq.PreallocateBatch();
    auto* alloc = zmq.Alloc(batchID);
    // TODO the version of libc++ present in android ndk 23.0.7599858
    // has a broken std::allocate_shared function so we're using
    // boost::shared_ptr instead of std::shared_ptr
    shared_ = boost::allocate_shared<BlockOracle::Shared>(
        alloc::PMR<BlockOracle::Shared>{alloc}, api, node);

    OT_ASSERT(shared_);

    actor_ = boost::allocate_shared<BlockOracle::Actor>(
        alloc::PMR<BlockOracle::Actor>{alloc}, api, node, shared_, batchID);

    OT_ASSERT(actor_);

    actor_->Init(actor_);
    actor_.reset();
}

auto BlockOracle::SubmitBlock(const ReadView in) const noexcept -> void
{
    return shared_->SubmitBlock(in);
}

auto BlockOracle::Tip() const noexcept -> block::Position
{
    return shared_->Tip();
}

auto BlockOracle::Validate(const bitcoin::block::Block& block) const noexcept
    -> bool
{
    return shared_->Validate(block);
}

BlockOracle::~BlockOracle() = default;
}  // namespace opentxs::blockchain::node::internal
