// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// IWYU pragma: no_include <boost/smart_ptr/detail/operator_bool.hpp>

#include "0_stdafx.hpp"    // IWYU pragma: associated
#include "1_Internal.hpp"  // IWYU pragma: associated
#include "blockchain/node/filteroracle/BlockIndexer.hpp"  // IWYU pragma: associated

#include <boost/smart_ptr/make_shared.hpp>
#include <chrono>
#include <exception>
#include <future>
#include <memory>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>

#include "blockchain/node/filteroracle/Shared.hpp"
#include "internal/api/session/Endpoints.hpp"
#include "internal/api/session/Session.hpp"
#include "internal/blockchain/database/Cfilter.hpp"
#include "internal/blockchain/node/Endpoints.hpp"
#include "internal/blockchain/node/Manager.hpp"
#include "internal/blockchain/node/filteroracle/Types.hpp"
#include "internal/network/zeromq/Context.hpp"
#include "internal/network/zeromq/Types.hpp"
#include "internal/util/Future.hpp"
#include "internal/util/LogMacros.hpp"
#include "internal/util/Timer.hpp"
#include "opentxs/api/network/Network.hpp"
#include "opentxs/api/session/Endpoints.hpp"
#include "opentxs/api/session/Session.hpp"
#include "opentxs/blockchain/Types.hpp"
#include "opentxs/blockchain/bitcoin/block/Block.hpp"
#include "opentxs/blockchain/bitcoin/cfilter/GCS.hpp"
#include "opentxs/blockchain/bitcoin/cfilter/Hash.hpp"  // IWYU pragma: keep
#include "opentxs/blockchain/bitcoin/cfilter/Header.hpp"
#include "opentxs/blockchain/block/Hash.hpp"
#include "opentxs/blockchain/block/Header.hpp"
#include "opentxs/blockchain/block/Position.hpp"
#include "opentxs/blockchain/block/Types.hpp"
#include "opentxs/blockchain/node/BlockOracle.hpp"
#include "opentxs/blockchain/node/HeaderOracle.hpp"
#include "opentxs/blockchain/node/Manager.hpp"
#include "opentxs/blockchain/node/Types.hpp"
#include "opentxs/core/FixedByteArray.hpp"
#include "opentxs/network/zeromq/Context.hpp"
#include "opentxs/network/zeromq/message/Frame.hpp"
#include "opentxs/network/zeromq/message/FrameSection.hpp"
#include "opentxs/network/zeromq/message/Message.hpp"
#include "opentxs/network/zeromq/socket/Types.hpp"
#include "opentxs/util/Allocator.hpp"
#include "opentxs/util/Container.hpp"
#include "opentxs/util/Log.hpp"
#include "opentxs/util/WorkType.hpp"

namespace opentxs::blockchain::node::filteroracle
{
auto print(BlockIndexerJob job) noexcept -> std::string_view
{
    try {
        using Job = BlockIndexerJob;
        using namespace std::literals;
        static const auto map = Map<Job, std::string_view>{
            {Job::shutdown, "shutdown"sv},
            {Job::header, "header"sv},
            {Job::reindex, "reindex"sv},
            {Job::reorg, "reorg"sv},
            {Job::full_block, "full_block"sv},
            {Job::init, "init"sv},
            {Job::statemachine, "statemachine"sv},
        };

        return map.at(job);
    } catch (...) {
        LogError()(__FUNCTION__)("invalid BlockIndexerJob: ")(
            static_cast<OTZMQWorkType>(job))
            .Flush();

        OT_FAIL;
    }
}
}  // namespace opentxs::blockchain::node::filteroracle

namespace opentxs::blockchain::node::filteroracle
{
BlockIndexer::Imp::Imp(
    std::shared_ptr<const api::Session> api,
    std::shared_ptr<const node::Manager> node,
    std::shared_ptr<Shared> shared,
    const network::zeromq::BatchID batch,
    allocator_type alloc) noexcept
    : Actor(
          shared->api_,
          LogTrace(),
          [&] {
              auto out = CString{print(shared->chain_), alloc};
              out.append(" filter oracle block indexer");

              return out;
          }(),
          0ms,
          batch,
          alloc,
          {
              {CString{
                   shared->node_.Internal().Endpoints().shutdown_publish_,
                   alloc},
               Direction::Connect},
              {CString{
                   shared->node_.Internal()
                       .Endpoints()
                       .filter_oracle_reindex_publish_,
                   alloc},
               Direction::Connect},
              {CString{shared->api_.Endpoints().Shutdown(), alloc},
               Direction::Connect},
              {CString{
                   shared->api_.Endpoints().Internal().BlockchainBlockUpdated(
                       shared->chain_),
                   alloc},
               Direction::Connect},
              {CString{shared->api_.Endpoints().BlockchainReorg(), alloc},
               Direction::Connect},
          })
    , api_p_(std::move(api))
    , node_p_(std::move(node))
    , shared_p_(std::move(shared))
    , api_(*api_p_)
    , node_(*node_p_)
    , shared_(*shared_p_)
    , state_(State::normal)
    , previous_header_()
    , current_header_()
    , best_position_(block::Position{})
    , current_position_(block::Position{})
{
}

auto BlockIndexer::Imp::calculate_next_block() noexcept -> bool
{
    OT_ASSERT(0 <= current_position_.height_);

    const auto& blockOracle = node_.BlockOracle();
    const auto& headerOracle = node_.HeaderOracle();
    auto position = headerOracle.GetPosition(current_position_.height_ + 1);
    const auto& [height, hash] = position;

    if (hash.empty()) {
        log_(OT_PRETTY_CLASS())(name_)(": block hash not found for height ")(
            height)
            .Flush();

        return true;
    }

    auto future = blockOracle.LoadBitcoin(hash);

    if (false == IsReady(future)) {
        log_(OT_PRETTY_CLASS())(name_)(": block ")
            .asHex(hash)(" not yet downloaded")
            .Flush();

        return true;
    }

    const auto pBlock = future.get();

    if (false == bool(pBlock)) {
        // NOTE the only time the future should contain an uninitialized pointer
        // is if the block oracle is shutting down
        log_(OT_PRETTY_CLASS())(name_)(": block ")
            .asHex(hash)(" unavailable")
            .Flush();

        return false;
    }

    const auto& block = *pBlock;

    OT_ASSERT(block.ID() == hash);

    if (block.Header().ParentHash() != current_position_.hash_) {
        log_(OT_PRETTY_CLASS())(name_)(": block ")
            .asHex(hash)(" is not connected to current tip")
            .Flush();
        process_reorg(headerOracle.CommonParent(position).first);

        return true;
    }

    auto alloc = get_allocator();
    auto filters = Vector<database::Cfilter::CFilterParams>{alloc};
    auto headers = Vector<database::Cfilter::CFHeaderParams>{alloc};
    const auto& [ignore1, cfilter] = filters.emplace_back(
        hash, shared_.ProcessBlock(shared_.default_type_, block, alloc));

    if (false == cfilter.IsValid()) {
        LogAbort()(OT_PRETTY_CLASS())(name_)(": failed to calculate gcs for ")(
            position)
            .Abort();
    }

    auto& [ignore2, cfheader, cfhash] = headers.emplace_back(
        hash, cfilter.Header(current_header_), cfilter.Hash());
    const auto rc = shared_.StoreCfilters(
        shared_.default_type_,
        position,
        std::move(headers),
        std::move(filters));

    if (false == rc) {
        LogAbort()(OT_PRETTY_CLASS())(name_)(": failed to update database")
            .Abort();
    }

    previous_header_ = std::move(current_header_);
    current_header_ = std::move(cfheader);
    update_current_position(std::move(position));

    return current_position_ != best_position_;
}

auto BlockIndexer::Imp::do_shutdown() noexcept -> void
{
    shared_p_.reset();
    node_p_.reset();
    api_p_.reset();
}

auto BlockIndexer::Imp::do_startup() noexcept -> bool
{
    if ((api_.Internal().ShuttingDown()) || (node_.Internal().ShuttingDown())) {
        return true;
    }

    update_best_position(node_.BlockOracle().Tip());
    const auto& type = shared_.default_type_;
    auto [cfheaderTip, cfilterTip] = shared_.Tips();

    if (cfheaderTip.height_ > cfilterTip.height_) {
        LogError()(OT_PRETTY_CLASS())(name_)(": cfilter tip (")(
            cfilterTip)(") is behind cfheader tip (")(cfheaderTip)(")")
            .Flush();
        cfheaderTip = cfilterTip;
        const auto rc = shared_.SetCfheaderTip(type, cfheaderTip);

        OT_ASSERT(rc);
    }

    current_position_ = cfilterTip;
    current_header_ = shared_.LoadCfheader(type, cfheaderTip.hash_);

    if (0 < cfheaderTip.height_) {
        previous_header_ = shared_.LoadCfheader(
            type, shared_.header_.BestHash(cfheaderTip.height_ - 1));
    }

    do_work();

    return false;
}

auto BlockIndexer::Imp::Init(boost::shared_ptr<Imp> me) noexcept -> void
{
    signal_startup(me);
}

auto BlockIndexer::Imp::pipeline(
    const Work work,
    network::zeromq::Message&& msg) noexcept -> void
{
    switch (state_) {
        case State::normal: {
            state_normal(work, std::move(msg));
        } break;
        case State::shutdown: {
            shutdown_actor();
        } break;
        default: {
            LogAbort()(OT_PRETTY_CLASS())(name_)(": invalid state").Abort();
        }
    }
}

auto BlockIndexer::Imp::process_block(network::zeromq::Message&& in) noexcept
    -> void
{
    const auto body = in.Body();

    OT_ASSERT(body.size() > 2);

    process_block(
        block::Position{body.at(1).as<block::Height>(), body.at(2).Bytes()});
}

auto BlockIndexer::Imp::process_block(block::Position&& position) noexcept
    -> void
{
    if (node_.HeaderOracle().IsInBestChain(position)) {
        update_best_position(std::move(position));
    }
}

auto BlockIndexer::Imp::process_reindex(network::zeromq::Message&&) noexcept
    -> void
{
    reset(node_.HeaderOracle().GetPosition(0));
}

auto BlockIndexer::Imp::process_reorg(network::zeromq::Message&& in) noexcept
    -> void
{
    const auto body = in.Body();

    if (1 >= body.size()) {
        LogAbort()(OT_PRETTY_CLASS())(name_)(": invalid message").Abort();
    }

    const auto chain = body.at(1).as<blockchain::Type>();

    if (shared_.chain_ != chain) { return; }

    process_reorg(node_.HeaderOracle().CommonParent(current_position_).first);
}

auto BlockIndexer::Imp::process_reorg(block::Position&& commonParent) noexcept
    -> void
{
    if (best_position_ > commonParent) {
        update_best_position(block::Position{commonParent});
    }

    if (current_position_ > commonParent) { reset(std::move(commonParent)); }
}

auto BlockIndexer::Imp::reset(block::Position&& to) noexcept -> void
{
    auto best = block::Position{};
    std::tie(current_header_, previous_header_, best) =
        shared_.FindBestPosition(to);
    update_current_position(std::move(best));
}

auto BlockIndexer::Imp::state_normal(const Work work, Message&& msg) noexcept
    -> void
{
    switch (work) {
        case Work::shutdown: {
            transition_state_shutdown();
        } break;
        case Work::header: {
            // NOTE no action necessary
        } break;
        case Work::reorg: {
            process_reorg(std::move(msg));
            do_work();
        } break;
        case Work::reindex: {
            process_reindex(std::move(msg));
            do_work();
        } break;
        case Work::full_block: {
            process_block(std::move(msg));
            do_work();
        } break;
        case Work::init: {
            do_init();
        } break;
        case Work::statemachine: {
            do_work();
        } break;
        default: {
            LogAbort()(OT_PRETTY_CLASS())(name_)(": unhandled message type ")(
                static_cast<OTZMQWorkType>(work))
                .Abort();
        }
    }
}

auto BlockIndexer::Imp::transition_state_shutdown() noexcept -> void
{
    state_ = State::shutdown;
    log_(OT_PRETTY_CLASS())(name_)(": transitioned to shutdown state").Flush();
    shutdown_actor();
}

auto BlockIndexer::Imp::update_best_position(
    block::Position&& position) noexcept -> void
{
    best_position_ = std::move(position);
    log_(OT_PRETTY_CLASS())(name_)(": best position updated to ")(
        best_position_)
        .Flush();
}

auto BlockIndexer::Imp::update_current_position(
    block::Position&& position) noexcept -> void
{
    if (current_position_ != position) {
        current_position_ = std::move(position);
        log_(OT_PRETTY_CLASS())(name_)(": current position updated to ")(
            current_position_)
            .Flush();
        const auto rc = shared_.SetTips(current_position_);

        OT_ASSERT(rc);
    }
}

auto BlockIndexer::Imp::work() noexcept -> bool
{
    if (current_position_ == best_position_) {
        log_(OT_PRETTY_CLASS())(name_)(
            ": current position matches best position ")(best_position_)
            .Flush();

        return false;
    }

    return calculate_next_block();
}

BlockIndexer::Imp::~Imp() = default;
}  // namespace opentxs::blockchain::node::filteroracle

namespace opentxs::blockchain::node::filteroracle
{
BlockIndexer::BlockIndexer(
    std::shared_ptr<const api::Session> api,
    std::shared_ptr<const node::Manager> node,
    std::shared_ptr<Shared> shared) noexcept
    : imp_([&] {
        OT_ASSERT(api);
        OT_ASSERT(node);
        OT_ASSERT(shared);

        const auto& zmq = shared->api_.Network().ZeroMQ().Internal();
        const auto batchID = zmq.PreallocateBatch();
        // TODO the version of libc++ present in android ndk 23.0.7599858
        // has a broken std::allocate_shared function so we're using
        // boost::shared_ptr instead of std::shared_ptr

        return boost::allocate_shared<Imp>(
            alloc::PMR<Imp>{zmq.Alloc(batchID)}, api, node, shared, batchID);
    }())
{
    OT_ASSERT(imp_);
}

auto BlockIndexer::Start() noexcept -> void { imp_->Init(imp_); }

BlockIndexer::~BlockIndexer() = default;
}  // namespace opentxs::blockchain::node::filteroracle
