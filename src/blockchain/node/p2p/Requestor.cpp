// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// IWYU pragma: no_include <boost/smart_ptr/detail/operator_bool.hpp>

#include "0_stdafx.hpp"                       // IWYU pragma: associated
#include "1_Internal.hpp"                     // IWYU pragma: associated
#include "blockchain/node/p2p/Requestor.hpp"  // IWYU pragma: associated

#include <P2PBlockchainChainState.pb.h>
#include <boost/smart_ptr/make_shared.hpp>
#include <chrono>
#include <memory>
#include <queue>
#include <ratio>
#include <string_view>
#include <utility>

#include "internal/api/network/Asio.hpp"
#include "internal/api/network/OTDHT.hpp"
#include "internal/api/session/Session.hpp"
#include "internal/blockchain/Params.hpp"
#include "internal/blockchain/node/Endpoints.hpp"
#include "internal/blockchain/node/Manager.hpp"
#include "internal/network/zeromq/Context.hpp"
#include "internal/network/zeromq/Types.hpp"
#include "internal/network/zeromq/message/Message.hpp"
#include "internal/network/zeromq/socket/Pipeline.hpp"
#include "internal/network/zeromq/socket/Raw.hpp"
#include "internal/util/LogMacros.hpp"
#include "internal/util/P0330.hpp"
#include "opentxs/api/network/Asio.hpp"
#include "opentxs/api/network/Network.hpp"
#include "opentxs/api/network/OTDHT.hpp"
#include "opentxs/api/session/Endpoints.hpp"
#include "opentxs/api/session/Factory.hpp"
#include "opentxs/api/session/Session.hpp"
#include "opentxs/blockchain/BlockchainType.hpp"
#include "opentxs/blockchain/Types.hpp"
#include "opentxs/blockchain/block/Hash.hpp"
#include "opentxs/blockchain/block/Types.hpp"
#include "opentxs/blockchain/node/FilterOracle.hpp"
#include "opentxs/blockchain/node/HeaderOracle.hpp"
#include "opentxs/blockchain/node/Manager.hpp"
#include "opentxs/network/otdht/Acknowledgement.hpp"
#include "opentxs/network/otdht/Base.hpp"
#include "opentxs/network/otdht/Data.hpp"
#include "opentxs/network/otdht/State.hpp"
#include "opentxs/network/zeromq/Context.hpp"
#include "opentxs/network/zeromq/Pipeline.hpp"
#include "opentxs/network/zeromq/message/Frame.hpp"
#include "opentxs/network/zeromq/message/FrameSection.hpp"
#include "opentxs/network/zeromq/message/Message.hpp"
#include "opentxs/network/zeromq/socket/SocketType.hpp"
#include "opentxs/network/zeromq/socket/Types.hpp"
#include "opentxs/util/Allocator.hpp"
#include "opentxs/util/Container.hpp"
#include "opentxs/util/Log.hpp"
#include "opentxs/util/Time.hpp"
#include "opentxs/util/WorkType.hpp"
#include "util/Work.hpp"

namespace opentxs::blockchain::node::p2p
{
Requestor::Imp::Imp(
    std::shared_ptr<const api::Session> api,
    std::shared_ptr<const node::Manager> node,
    const network::zeromq::BatchID batch,
    allocator_type alloc) noexcept
    : Actor(
          *api,
          LogTrace(),
          [&] {
              auto out = CString(print(node->Internal().Chain()), alloc);
              out.push_back(' ');
              out.append("dht requestor");

              return out;
          }(),
          0ms,
          batch,
          alloc,
          {
              {CString{api->Endpoints().Shutdown()}, Direction::Connect},
              {node->Internal().Endpoints().shutdown_publish_,
               Direction::Connect},
              {node->Internal().Endpoints().new_filter_publish_,
               Direction::Connect},
              {node->Internal().Endpoints().new_header_publish_,
               Direction::Connect},
          },
          {},
          {
              {CString{api->Network().OTDHT().Internal().Endpoint()},
               Direction::Connect},
          },
          {
              {SocketType::Pair,
               {
                   {node->Internal().Endpoints().p2p_requestor_pair_,
                    Direction::Bind},
               }},
          })
    , api_p_(std::move(api))
    , node_p_(std::move(node))
    , api_(*api_p_)
    , node_(*node_p_)
    , chain_(node_.Internal().Chain())
    , cfilter_(node_.FilterOracle().DefaultType())
    , to_parent_(pipeline_.Internal().ExtraSocket(0))
    , state_(State::init)
    , request_timer_(api_.Network().Asio().Internal().GetTimer())
    , activity_timer_(api_.Network().Asio().Internal().GetTimer())
    , stale_position_timer_(api_.Network().Asio().Internal().GetTimer())
    , sync_start_time_()
    , last_dht_position_()
    , last_incoming_(std::nullopt)
    , last_outgoing_(std::nullopt)
    , genesis_position_(0, HeaderOracle::GenesisBlockHash(chain_))
    , checkpoint_position_([&] {
        const auto& cp = params::Chains().at(chain_).checkpoint_;
        auto out = block::Position{};
        out.height_ = 0;
        const auto rc = out.hash_.DecodeHex(cp.block_hash_);

        OT_ASSERT(rc);

        return out;
    }())
    , header_position_(genesis_position_)
    , cfilter_position_(genesis_position_)
    , dht_position_()
    , queue_position_()
    , processed_position_()
    , queued_bytes_()
    , processed_bytes_()
    , queue_()
    , processing_(false)
{
}

auto Requestor::Imp::add_to_queue(
    const network::otdht::Data& data,
    Message&& msg) noexcept -> void
{
    const auto& blocks = data.Blocks();

    if (blocks.empty()) { return; }

    const auto bytes = msg.Total();
    log_(OT_PRETTY_CLASS())(name_)(": buffering ")(
        bytes)(" bytes of sync data for blocks ")(blocks.front().Height())(
        " to ")(blocks.back().Height())
        .Flush();
    queued_bytes_ += bytes;
    processed_bytes_ += bytes;
    queue_.emplace(std::move(msg));
    update_queue_position(data);
}

auto Requestor::Imp::check_request_timeout() noexcept -> void
{
    if (have_pending_request()) {
        const auto interval =
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                Clock::now() - *last_outgoing_);

        if (interval > request_timeout_) {
            log_(OT_PRETTY_CLASS())(name_)(
                ": last request has timed out after ")(interval)
                .Flush();
            finish_request();
        } else {
            const auto remaining = request_timeout_ - interval;
            log_(OT_PRETTY_CLASS())(name_)(
                ": last request still considered active for ")(remaining)
                .Flush();
        }
    }
}

auto Requestor::Imp::check_stale_dht() noexcept -> void
{
    const auto interval = std::chrono::duration_cast<std::chrono::nanoseconds>(
        Clock::now() - last_dht_position_);

    if (interval > dht_position_timeout_) {
        log_(OT_PRETTY_CLASS())(name_)(
            ": last dht position considered stale after ")(interval)
            .Flush();
        dht_position_ = genesis_position_;
    } else {
        const auto remaining =
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                dht_position_timeout_ - interval);
        log_(OT_PRETTY_CLASS())(name_)(": last dht position still valid for ")(
            remaining)
            .Flush();
    }
}

auto Requestor::Imp::do_shutdown() noexcept -> void
{
    request_timer_.Cancel();
    activity_timer_.Cancel();
    stale_position_timer_.Cancel();
    node_p_.reset();
    api_p_.reset();
}

auto Requestor::Imp::do_startup() noexcept -> bool
{
    if (api_.Internal().ShuttingDown() || node_p_->Internal().ShuttingDown()) {
        return true;
    }

    do_work();

    return false;
}

auto Requestor::Imp::do_state_common() noexcept -> void
{
    flush_queue();
    check_request_timeout();
    check_stale_dht();
    const auto& position = effective_position();
    const auto& target = target_position();

    if (need_data(position, target)) {
        request(position);
    } else if (position == target) {
        log_(OT_PRETTY_CLASS())(name_)(
            ": effective position is caught up to target position ")(target)
            .Flush();
    } else {
        log_(OT_PRETTY_CLASS())(name_)(
            ": refraining from requesting data until dht position ")(
            dht_position_)(" catches up to ")(target)(" or times out")
            .Flush();
    }
}

auto Requestor::Imp::do_state_init() noexcept -> void { register_chain(); }

auto Requestor::Imp::do_state_run() noexcept -> void { do_state_common(); }

auto Requestor::Imp::do_state_sync() noexcept -> void
{
    do_state_common();
    transition_state_run();
}

auto Requestor::Imp::effective_position() const noexcept
    -> const block::Position&
{
    const auto* out = std::addressof(genesis_position_);

    auto check = [&](const auto& test) mutable {
        if (test > *out) { out = std::addressof(test); }
    };
    check(queue_position_);
    check(processed_position_);
    log_(OT_PRETTY_CLASS())(name_)(": ")(*out).Flush();

    return *out;
}

auto Requestor::Imp::finish_request() noexcept -> void
{
    request_timer_.Cancel();
    last_outgoing_.reset();
}

auto Requestor::Imp::flush_queue() noexcept -> void
{
    if (processing_) {
        log_(OT_PRETTY_CLASS())(name_)(": waiting for existing job to finish")
            .Flush();

        return;
    }

    if (queue_.empty()) {
        log_(OT_PRETTY_CLASS())(name_)(": no queued data to process").Flush();

        return;
    }

    auto& msg = queue_.front();
    const auto bytes = msg.Total();
    log_(OT_PRETTY_CLASS())(name_)(": processing ")(bytes)(" bytes").Flush();
    to_parent_.Send(std::move(msg), __FILE__, __LINE__);
    processing_ = true;
    queued_bytes_ -= bytes;
    queue_.pop();
    update_queue_position();
}

auto Requestor::Imp::have_pending_request() const noexcept -> bool
{
    return last_outgoing_.has_value();
}

auto Requestor::Imp::need_data(
    const block::Position& current,
    const block::Position& target) const noexcept -> bool
{
    const auto localValid = target == current;
    const auto dhtValid = target == dht_position_;

    if (localValid && dhtValid) { return false; }

    if (have_pending_request()) {
        log_(OT_PRETTY_CLASS())(name_)(
            ": waiting for existing request to arrive or timeout")
            .Flush();

        return false;
    }

    if (queue_is_full()) {
        log_(OT_PRETTY_CLASS())(name_)(": data queue full").Flush();

        return false;
    }

    if (current == dht_position_) {
        log_(OT_PRETTY_CLASS())(name_)(": dht position ")(
            dht_position_)(" is not yet updated for newest known block ")(
            target)
            .Flush();
    }

    return true;
}

auto Requestor::Imp::pipeline(const Work work, Message&& msg) noexcept -> void
{
    switch (state_) {
        case State::init: {
            state_init(work, std::move(msg));
        } break;
        case State::sync: {
            state_sync(work, std::move(msg));
        } break;
        case State::run: {
            state_run(work, std::move(msg));
        } break;
        default: {
            LogAbort()(OT_PRETTY_CLASS())(name_)(": invalid state").Abort();
        }
    }
}

auto Requestor::Imp::process_cfilter(Message&& in) noexcept -> void
{
    try {
        const auto body = in.Body();
        network::zeromq::check_frame_count(body, 3_uz, get_allocator());
        const auto type = body.at(1).as<cfilter::Type>();

        if (type != cfilter_) { return; }

        cfilter_position_ = {
            body.at(2).as<block::Height>(), body.at(3).Bytes()};
    } catch (const std::exception& e) {
        LogAbort()(OT_PRETTY_CLASS())(name_)(": ")(e.what()).Abort();
    }
}

auto Requestor::Imp::process_header(Message&& in) noexcept -> void
{
    try {
        const auto body = in.Body();
        network::zeromq::check_frame_count(body, 2_uz, get_allocator());
        process_header_tip(
            {body.at(2).as<block::Height>(), body.at(1).Bytes()});
    } catch (const std::exception& e) {
        LogAbort()(OT_PRETTY_CLASS())(name_)(": ")(e.what()).Abort();
    }
}

auto Requestor::Imp::process_header_tip(block::Position&& tip) noexcept -> void
{
    header_position_ = std::move(tip);
}

auto Requestor::Imp::process_push_tx(Message&& in) noexcept -> void
{
    log_(OT_PRETTY_CLASS())(name_)(": forwarding outgoing transaction").Flush();
    transmit_push(std::move(in));
}

auto Requestor::Imp::process_register(Message&&) noexcept -> void
{
    log_(OT_PRETTY_CLASS())(name_)(": response received from high level api")
        .Flush();
    transition_state_sync();
}

auto Requestor::Imp::process_reorg(Message&& in) noexcept -> void
{
    try {
        const auto body = in.Body();
        network::zeromq::check_frame_count(body, 4_uz, get_allocator());
        auto ancestor =
            block::Position{body.at(2).as<block::Height>(), body.at(1).Bytes()};

        if (ancestor.height_ <= processed_position_.height_) {
            processed_position_ = std::move(ancestor);
        }

        process_header_tip(
            {body.at(4).as<block::Height>(), body.at(3).Bytes()});
    } catch (const std::exception& e) {
        LogAbort()(OT_PRETTY_CLASS())(name_)(": ")(e.what()).Abort();
    }
}

auto Requestor::Imp::process_sync_ack(Message&& in) noexcept -> void
{
    const auto base = api_.Factory().BlockchainSyncMessage(in);
    const auto& ack = base->asAcknowledgement();
    update_dht_position(ack.State(chain_));
    log_(OT_PRETTY_CLASS())(name_)(
        ": best chain tip according to sync peer is ")(dht_position_)
        .Flush();
}

auto Requestor::Imp::process_sync_processed(Message&& in) noexcept -> void
{
    try {
        const auto body = in.Body();
        network::zeromq::check_frame_count(body, 2_uz, get_allocator());
        auto pos = block::Position{
            body.at(1).as<block::Height>(), block::Hash{body.at(2).Bytes()}};

        if (node_.HeaderOracle().IsInBestChain(pos)) {
            processed_position_ = std::move(pos);
        }

        processing_ = false;
    } catch (const std::exception& e) {
        LogAbort()(OT_PRETTY_CLASS())(name_)(": ")(e.what()).Abort();
    }
}

auto Requestor::Imp::process_sync_push(Message&& in) noexcept -> void
{
    const auto base = api_.Factory().BlockchainSyncMessage(in);
    const auto& data = base->asData();
    update_dht_position(data);
    add_to_queue(data, std::move(in));
}

auto Requestor::Imp::process_sync_reply(Message&& in) noexcept -> void
{
    const auto base = api_.Factory().BlockchainSyncMessage(in);
    const auto& data = base->asData();
    update_dht_position(data);
    add_to_queue(data, std::move(in));
}

auto Requestor::Imp::queue_is_full() const noexcept -> bool
{
    return queued_bytes_ >= limit_;
}

auto Requestor::Imp::register_chain() noexcept -> void
{
    log_(OT_PRETTY_CLASS())(name_)(": registering with high level api").Flush();
    transmit_request([&] {
        auto out = MakeWork(Work::Register);
        out.AddFrame(chain_);

        return out;
    }());
}

auto Requestor::Imp::request(const block::Position& position) noexcept -> void
{
    log_(OT_PRETTY_CLASS())(name_)(
        ": requesting sync data starting from block ")(position.height_)
        .Flush();
    transmit_request([&] {
        auto msg = MakeWork(Work::Request);
        msg.AddFrame(chain_);
        msg.Internal().AddFrame([&] {
            auto proto = proto::P2PBlockchainChainState{};
            const auto state = network::otdht::State{chain_, position};
            state.Serialize(proto);

            return proto;
        }());

        return msg;
    }());
}

auto Requestor::Imp::request_timeout() const noexcept -> std::chrono::seconds
{
    switch (state_) {
        case State::init: {

            return init_timeout_;
        }
        default: {

            return request_timeout_;
        }
    }
}

auto Requestor::Imp::reset_activity_timer() noexcept -> void
{
    reset_timer(activity_timeout_, activity_timer_, Work::StateMachine);
}

auto Requestor::Imp::reset_request_timer() noexcept -> void
{
    reset_timer(request_timeout(), request_timer_, Work::StateMachine);
}

auto Requestor::Imp::reset_stale_position_timer() noexcept -> void
{
    reset_timer(
        dht_position_timeout_, stale_position_timer_, Work::StateMachine);
}

auto Requestor::Imp::state_init(const Work work, Message&& msg) noexcept -> void
{
    switch (work) {
        case Work::Shutdown: {
            shutdown_actor();
        } break;
        case Work::PushTransaction: {
            defer(std::move(msg));
        } break;
        case Work::Register: {
            update_incoming();
            process_register(std::move(msg));
        } break;
        case Work::ReorgInternal: {
            process_reorg(std::move(msg));
        } break;
        case Work::NewHeaderTip: {
            process_header(std::move(msg));
        } break;
        case Work::Init: {
            do_init();
        } break;
        case Work::NewCFilterTip: {
            process_cfilter(std::move(msg));
        } break;
        case Work::StateMachine: {
            do_work();
        } break;
        case Work::SyncAck:
        case Work::SyncReply:
        case Work::SyncPush:
        case Work::Processed: {
            LogAbort()(OT_PRETTY_CLASS())(name_)(": wrong state for ")(
                print(work))
                .Abort();
        }
        case Work::BlockHeader:
        case Work::Reorg:
        case Work::SyncServerUpdated:
        case Work::Response:
        case Work::PublishContract:
        case Work::QueryContract:
        case Work::Request:
        default: {
            LogAbort()(OT_PRETTY_CLASS())(name_)(": unhandled message type ")(
                static_cast<OTZMQWorkType>(work))
                .Abort();
        }
    }
}

auto Requestor::Imp::state_run(const Work work, Message&& msg) noexcept -> void
{
    switch (work) {
        case Work::Shutdown: {
            shutdown_actor();
        } break;
        case Work::SyncAck: {
            update_incoming();
            process_sync_ack(std::move(msg));
        } break;
        case Work::SyncReply: {
            update_incoming();
            process_sync_reply(std::move(msg));
        } break;
        case Work::SyncPush: {
            update_incoming();
            process_sync_push(std::move(msg));
        } break;
        case Work::PushTransaction: {
            process_push_tx(std::move(msg));
        } break;
        case Work::Register: {
            // NOTE ignore duplicate Register messages
        } break;
        case Work::Processed: {
            process_sync_processed(std::move(msg));
        } break;
        case Work::ReorgInternal: {
            process_reorg(std::move(msg));
        } break;
        case Work::NewHeaderTip: {
            process_header(std::move(msg));
        } break;
        case Work::NewCFilterTip: {
            process_cfilter(std::move(msg));
        } break;
        case Work::StateMachine: {
        } break;
        case Work::Init: {
            LogAbort()(OT_PRETTY_CLASS())(name_)(": wrong state for ")(
                print(work))
                .Abort();
        }
        case Work::BlockHeader:
        case Work::Reorg:
        case Work::SyncServerUpdated:
        case Work::Response:
        case Work::PublishContract:
        case Work::QueryContract:
        case Work::Request:
        default: {
            LogAbort()(OT_PRETTY_CLASS())(name_)(": unhandled message type ")(
                static_cast<OTZMQWorkType>(work))
                .Abort();
        }
    }

    do_work();
}

auto Requestor::Imp::state_sync(const Work work, Message&& msg) noexcept -> void
{
    state_run(work, std::move(msg));
}

auto Requestor::Imp::target_position() const noexcept -> const block::Position&
{
    const auto* out = std::addressof(genesis_position_);

    auto check = [&](const auto& test) mutable {
        if (test > *out) { out = std::addressof(test); }
    };
    check(checkpoint_position_);
    check(header_position_);
    check(cfilter_position_);
    check(dht_position_);
    log_(OT_PRETTY_CLASS())(name_)(": ")(*out).Flush();

    return *out;
}

auto Requestor::Imp::transition_state_run() noexcept -> void
{
    if (processing_) { return; }

    if (have_pending_request()) { return; }

    if (false == queue_.empty()) { return; }

    if (effective_position() != target_position()) { return; }

    const auto interval = std::chrono::duration_cast<std::chrono::nanoseconds>(
        Clock::now() - sync_start_time_.get());
    const auto ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(interval).count();
    const auto kb = processed_bytes_ / 1024_uz;
    const auto mb = kb / 1024_uz;
    const auto& log = LogConsole();
    log(print(chain_))(" sync complete. Processed ")(mb)(" MiB in ")(interval);

    if (0 < ms) { log(" (")(1000 * kb / ms)(" KiB/sec)"); }

    log.Flush();
    state_ = State::run;
}

auto Requestor::Imp::transition_state_sync() noexcept -> void
{
    sync_start_time_.set_value(Clock::now());
    state_ = State::sync;
    trigger();
}

auto Requestor::Imp::transmit(Message&& msg, bool request) noexcept -> void
{
    pipeline_.Internal().SendFromThread(std::move(msg));

    if (request) {
        last_outgoing_ = Clock::now();
        reset_request_timer();
    }
}

auto Requestor::Imp::transmit_push(Message&& msg) noexcept -> void
{
    transmit(std::move(msg), false);
}

auto Requestor::Imp::transmit_request(Message&& msg) noexcept -> void
{
    transmit(std::move(msg), true);
}

auto Requestor::Imp::update_dht_position(
    const network::otdht::Data& data) noexcept -> void
{
    update_dht_position(data.State());
}
auto Requestor::Imp::update_dht_position(
    const network::otdht::State& state) noexcept -> void
{
    dht_position_ = state.Position();
    last_dht_position_ = Clock::now();
    reset_stale_position_timer();
}

auto Requestor::Imp::update_incoming() noexcept -> void
{
    last_incoming_ = Clock::now();

    if (have_pending_request()) { finish_request(); }

    reset_activity_timer();
}

auto Requestor::Imp::update_queue_position() noexcept -> void
{
    if (queue_.empty()) {
        queue_position_ = genesis_position_;

        return;
    }

    if (genesis_position_ == queue_position_) {
        const auto base = api_.Factory().BlockchainSyncMessage(queue_.back());
        update_queue_position(base->asData());
    }
}

auto Requestor::Imp::update_queue_position(
    const network::otdht::Data& data) noexcept -> void
{
    const auto& blocks = data.Blocks();

    if (blocks.empty()) { return; }

    queue_position_ = data.LastPosition(api_);
}

auto Requestor::Imp::work() noexcept -> bool
{
    switch (state_) {
        case State::init: {
            do_state_init();
        } break;
        case State::sync: {
            do_state_sync();
        } break;
        case State::run: {
            do_state_run();
        } break;
        default: {
            LogAbort()(OT_PRETTY_CLASS())(name_)(": invalid state").Abort();
        }
    }

    return false;
}

Requestor::Imp::~Imp() = default;
}  // namespace opentxs::blockchain::node::p2p

namespace opentxs::blockchain::node::p2p
{
Requestor::Requestor(
    std::shared_ptr<const api::Session> api,
    std::shared_ptr<const node::Manager> node) noexcept
    : imp_([&] {
        const auto& asio = api->Network().ZeroMQ().Internal();
        const auto batchID = asio.PreallocateBatch();
        // TODO the version of libc++ present in android ndk 23.0.7599858
        // has a broken std::allocate_shared function so we're using
        // boost::shared_ptr instead of std::shared_ptr

        OT_ASSERT(api);
        OT_ASSERT(node);

        return boost::allocate_shared<Imp>(
            alloc::PMR<Imp>{asio.Alloc(batchID)},
            std::move(api),
            std::move(node),
            batchID);
    }())
{
}

auto Requestor::Init() noexcept -> void { imp_->Init(imp_); }

Requestor::~Requestor() = default;
}  // namespace opentxs::blockchain::node::p2p
