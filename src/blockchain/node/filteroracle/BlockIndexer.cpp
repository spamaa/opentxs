// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// IWYU pragma: no_include <boost/smart_ptr/detail/operator_bool.hpp>

#include "0_stdafx.hpp"    // IWYU pragma: associated
#include "1_Internal.hpp"  // IWYU pragma: associated
#include "blockchain/node/filteroracle/BlockIndexer.hpp"  // IWYU pragma: associated

#include <boost/smart_ptr/make_shared.hpp>
#include <algorithm>
#include <chrono>
#include <exception>
#include <future>
#include <memory>
#include <string_view>
#include <type_traits>
#include <utility>

#include "internal/api/session/Endpoints.hpp"
#include "internal/api/session/Session.hpp"
#include "internal/blockchain/database/Cfilter.hpp"
#include "internal/blockchain/node/Endpoints.hpp"
#include "internal/blockchain/node/Manager.hpp"
#include "internal/blockchain/node/filteroracle/FilterOracle.hpp"
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
#include "opentxs/blockchain/bitcoin/cfilter/FilterType.hpp"
#include "opentxs/blockchain/bitcoin/cfilter/GCS.hpp"
#include "opentxs/blockchain/bitcoin/cfilter/Hash.hpp"  // IWYU pragma: keep
#include "opentxs/blockchain/bitcoin/cfilter/Header.hpp"
#include "opentxs/blockchain/block/Hash.hpp"
#include "opentxs/blockchain/block/Header.hpp"
#include "opentxs/blockchain/block/Position.hpp"
#include "opentxs/blockchain/block/Types.hpp"
#include "opentxs/blockchain/node/BlockOracle.hpp"
#include "opentxs/blockchain/node/FilterOracle.hpp"
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
    const api::Session& api,
    const node::Manager& node,
    const node::FilterOracle& parent,
    database::Cfilter& db,
    NotifyCallback&& notify,
    blockchain::Type chain,
    cfilter::Type type,
    const node::Endpoints& endpoints,
    const network::zeromq::BatchID batch,
    allocator_type alloc) noexcept
    : Actor(
          api,
          LogTrace(),
          [&] {
              auto out = CString{print(chain), alloc};
              out.append(" filter oracle block indexer");

              return out;
          }(),
          0ms,
          batch,
          alloc,
          {
              {CString{endpoints.shutdown_publish_, alloc}, Direction::Connect},
              {CString{endpoints.filter_oracle_reindex_publish_, alloc},
               Direction::Connect},
              {CString{api.Endpoints().Shutdown(), alloc}, Direction::Connect},
              {CString{
                   api.Endpoints().Internal().BlockchainBlockUpdated(chain),
                   alloc},
               Direction::Connect},
              {CString{api.Endpoints().BlockchainReorg(), alloc},
               Direction::Connect},
          })
    , api_(api)
    , node_(node)
    , parent_(parent)
    , db_(db)
    , chain_(chain)
    , filter_type_(type)
    , notify_(std::move(notify))
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
        hash, parent_.Internal().ProcessBlock(filter_type_, block, alloc));

    if (false == cfilter.IsValid()) {
        log_(OT_PRETTY_CLASS())(name_)(": failed to calculate gcs for ")(
            position)
            .Flush();

        OT_FAIL;
    }

    auto& [ignore2, cfheader, cfhash] = headers.emplace_back(
        hash, cfilter.Header(current_header_), cfilter.Hash());
    const auto rc = db_.StoreFilters(filter_type_, headers, filters, position);

    if (false == rc) {
        log_(OT_PRETTY_CLASS())(name_)(": failed to update database").Flush();

        OT_FAIL;
    }

    previous_header_ = std::move(current_header_);
    current_header_ = std::move(cfheader);
    update_current_position(std::move(position));

    return current_position_ != best_position_;
}

auto BlockIndexer::Imp::do_shutdown() noexcept -> void
{
    current_header_ = {};
    previous_header_ = {};
    update_best_position({});
    update_current_position({});
}

auto BlockIndexer::Imp::do_startup() noexcept -> bool
{
    if ((api_.Internal().ShuttingDown()) || (node_.Internal().ShuttingDown())) {
        return true;
    }

    update_best_position(node_.BlockOracle().Tip());
    const auto headerTip = db_.FilterHeaderTip(filter_type_);
    const auto cfilterTip = db_.FilterTip(filter_type_);
    find_best_position(std::min(headerTip, cfilterTip));
    update_position(headerTip, cfilterTip, current_position_);

    return false;
}

auto BlockIndexer::Imp::find_best_position(block::Position candidate) noexcept
    -> void
{
    static const auto blank = block::Height{-1};
    const auto& headerOracle = node_.HeaderOracle();

    if (blank == candidate.height_) {
        candidate = headerOracle.GetPosition(0);

        OT_ASSERT(db_.HaveFilterHeader(filter_type_, candidate.hash_));
        OT_ASSERT(db_.HaveFilter(filter_type_, candidate.hash_));
    }

    if (0 == candidate.height_) {
        current_header_ =
            db_.LoadFilterHeader(filter_type_, candidate.hash_.Bytes());
        previous_header_ = {};
        update_current_position(std::move(candidate));

        return;
    } else {
        // NOTE this procedure allows for recovery from certain types of
        // database corruption. If the expected data are not present for the
        // cfilter tip and cfheader tip recorded in the database then the tips
        // will be rewound to the point at which consistent data is found, or
        // the genesis position is reached, whichever comes first.
        const auto have_data = [&](const auto& prev, const auto& cur) -> bool {
            return db_.HaveFilterHeader(filter_type_, cur) &&
                   db_.HaveFilterHeader(filter_type_, prev) &&
                   db_.HaveFilter(filter_type_, cur) &&
                   db_.HaveFilter(filter_type_, prev);
        };

        while (0 <= candidate.height_) {
            if (0 == candidate.height_) {
                current_header_ =
                    db_.LoadFilterHeader(filter_type_, candidate.hash_.Bytes());
                previous_header_ = {};
                update_current_position(std::move(candidate));

                return;
            } else {
                auto prior = candidate.height_ - 1;
                auto previous = headerOracle.BestHash(prior);

                if (have_data(previous, candidate.hash_)) {
                    current_header_ = db_.LoadFilterHeader(
                        filter_type_, candidate.hash_.Bytes());
                    previous_header_ =
                        db_.LoadFilterHeader(filter_type_, previous.Bytes());
                    update_current_position(std::move(candidate));

                    return;
                } else {
                    candidate = {std::move(prior), std::move(previous)};
                }
            }
        }

        OT_FAIL;  // it should be impossible to reach this line
    }
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
            OT_FAIL;
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

    if (1 > body.size()) {
        LogError()(OT_PRETTY_CLASS())(name_)(": invalid message").Flush();

        OT_FAIL;
    }

    const auto chain = body.at(1).as<blockchain::Type>();

    if (chain_ != chain) { return; }

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
    const auto before = current_position_;
    find_best_position(std::move(to));
    update_position(before, before, current_position_);
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
            LogError()(OT_PRETTY_CLASS())(name_)(": unhandled message type ")(
                static_cast<OTZMQWorkType>(work))
                .Flush();

            OT_FAIL;
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
    update_position(current_position_, current_position_, std::move(position));
}

auto BlockIndexer::Imp::update_position(
    const block::Position& previousCfheader,
    const block::Position& previousCfilter,
    const block::Position& newTip) noexcept -> void
{
    update_position(previousCfheader, previousCfilter, block::Position{newTip});
}

auto BlockIndexer::Imp::update_position(
    const block::Position& previousCfheader,
    const block::Position& previousCfilter,
    block::Position&& newTip) noexcept -> void
{
    auto changed{false};

    if (newTip != previousCfheader) {
        changed = true;
        const auto rc = db_.SetFilterHeaderTip(filter_type_, newTip);

        OT_ASSERT(rc);
    }

    if (newTip != previousCfilter) {
        changed = true;
        const auto rc = db_.SetFilterTip(filter_type_, newTip);

        OT_ASSERT(rc);
    }

    if (changed) {
        current_position_ = std::move(newTip);
        log_(OT_PRETTY_CLASS())(name_)(": current position updated to ")(
            current_position_)
            .Flush();
        notify_(filter_type_, current_position_);
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
    const api::Session& api,
    const node::Manager& node,
    const node::FilterOracle& parent,
    database::Cfilter& db,
    NotifyCallback&& notify,
    blockchain::Type chain,
    cfilter::Type type,
    const node::Endpoints& endpoints) noexcept
    : imp_([&] {
        const auto& zmq = api.Network().ZeroMQ().Internal();
        const auto batchID = zmq.PreallocateBatch();
        // TODO the version of libc++ present in android ndk 23.0.7599858
        // has a broken std::allocate_shared function so we're using
        // boost::shared_ptr instead of std::shared_ptr

        return boost::allocate_shared<Imp>(
            alloc::PMR<Imp>{zmq.Alloc(batchID)},
            api,
            node,
            parent,
            db,
            std::move(notify),
            chain,
            type,
            endpoints,
            batchID);
    }())
{
    OT_ASSERT(imp_);
}

auto BlockIndexer::Start() noexcept -> void { imp_->Init(imp_); }

BlockIndexer::~BlockIndexer() = default;
}  // namespace opentxs::blockchain::node::filteroracle
