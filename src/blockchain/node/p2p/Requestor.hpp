// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// IWYU pragma: no_include "opentxs/blockchain/BlockchainType.hpp"

#pragma once

#include <boost/smart_ptr/shared_ptr.hpp>
#include <zmq.h>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <exception>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <thread>

#include "internal/blockchain/node/p2p/Requestor.hpp"
#include "internal/network/p2p/Types.hpp"
#include "internal/network/zeromq/Types.hpp"
#include "internal/util/AsyncConst.hpp"
#include "internal/util/Timer.hpp"
#include "opentxs/blockchain/bitcoin/cfilter/Types.hpp"
#include "opentxs/blockchain/block/Position.hpp"
#include "opentxs/blockchain/block/Types.hpp"
#include "opentxs/util/Allocated.hpp"
#include "opentxs/util/Container.hpp"
#include "opentxs/util/Time.hpp"
#include "util/Actor.hpp"
#include "util/Backoff.hpp"
#include "util/ByteLiterals.hpp"

// NOLINTBEGIN(modernize-concat-nested-namespaces)
namespace opentxs  // NOLINT
{
// inline namespace v1
// {
namespace api
{
class Session;
}  // namespace api

namespace blockchain
{
namespace block
{
class Position;
}  // namespace block

namespace node
{
class Manager;
}  // namespace node
}  // namespace blockchain

namespace network
{
namespace p2p
{
class Data;
class State;
}  // namespace p2p

namespace zeromq
{
namespace socket
{
class Raw;
}  // namespace socket

class Message;
}  // namespace zeromq
}  // namespace network
// }  // namespace v1
}  // namespace opentxs
// NOLINTEND(modernize-concat-nested-namespaces)

namespace opentxs::blockchain::node::p2p
{
class Requestor::Imp final : public Actor<Imp, network::p2p::Job>
{
public:
    auto Init(boost::shared_ptr<Imp> me) noexcept -> void
    {
        signal_startup(me);
    }

    Imp(std::shared_ptr<const api::Session> api,
        std::shared_ptr<const node::Manager> node,
        const network::zeromq::BatchID batch,
        allocator_type alloc) noexcept;
    Imp() = delete;
    Imp(const Imp&) = delete;
    Imp(Imp&&) = delete;
    auto operator=(const Imp&) -> Imp& = delete;
    auto operator=(Imp&&) -> Imp& = delete;

    ~Imp() final;

private:
    friend Actor<Imp, network::p2p::Job>;

    enum class State { init, sync, run };

    static constexpr std::size_t limit_{32_mib};
    static constexpr auto init_timeout_{5s};
    static constexpr auto request_timeout_{45s};
    static constexpr auto dht_position_timeout_{5 * 60s};
    static constexpr auto activity_timeout_{2 * 60s};

    std::shared_ptr<const api::Session> api_p_;
    std::shared_ptr<const node::Manager> node_p_;
    const api::Session& api_;
    const node::Manager& node_;
    const Type chain_;
    const cfilter::Type cfilter_;
    network::zeromq::socket::Raw& to_parent_;
    State state_;
    Timer request_timer_;
    Timer activity_timer_;
    Timer stale_position_timer_;
    AsyncConst<Time> sync_start_time_;
    Time last_dht_position_;
    std::optional<Time> last_incoming_;
    std::optional<Time> last_outgoing_;
    const block::Position genesis_position_;
    const block::Position checkpoint_position_;
    block::Position header_position_;
    block::Position cfilter_position_;
    block::Position dht_position_;
    block::Position queue_position_;
    block::Position processed_position_;
    std::size_t queued_bytes_;
    std::size_t processed_bytes_;
    std::queue<Message> queue_;
    bool processing_;

    auto effective_position() const noexcept -> const block::Position&;
    auto have_pending_request() const noexcept -> bool;
    auto need_data(
        const block::Position& current,
        const block::Position& target) const noexcept -> bool;
    auto queue_is_full() const noexcept -> bool;
    auto request_timeout() const noexcept -> std::chrono::seconds;
    auto target_position() const noexcept -> const block::Position&;

    auto add_to_queue(const network::p2p::Data& data, Message&& msg) noexcept
        -> void;
    auto check_request_timeout() noexcept -> void;
    auto check_stale_dht() noexcept -> void;
    auto do_shutdown() noexcept -> void;
    auto do_startup() noexcept -> bool;
    auto do_state_common() noexcept -> void;
    auto do_state_init() noexcept -> void;
    auto do_state_run() noexcept -> void;
    auto do_state_sync() noexcept -> void;
    auto finish_request() noexcept -> void;
    auto flush_queue() noexcept -> void;
    auto pipeline(const Work work, Message&& msg) noexcept -> void;
    auto process_cfilter(Message&& in) noexcept -> void;
    auto process_header(Message&& in) noexcept -> void;
    auto process_header_tip(block::Position&& tip) noexcept -> void;
    auto process_push_tx(Message&& in) noexcept -> void;
    auto process_register(Message&& in) noexcept -> void;
    auto process_reorg(Message&& in) noexcept -> void;
    auto process_sync_ack(Message&& in) noexcept -> void;
    auto process_sync_processed(Message&& in) noexcept -> void;
    auto process_sync_push(Message&& in) noexcept -> void;
    auto process_sync_reply(Message&& in) noexcept -> void;
    auto register_chain() noexcept -> void;
    auto request(const block::Position& position) noexcept -> void;
    auto reset_activity_timer() noexcept -> void;
    auto reset_request_timer() noexcept -> void;
    auto reset_stale_position_timer() noexcept -> void;
    auto state_init(const Work work, Message&& msg) noexcept -> void;
    auto state_run(const Work work, Message&& msg) noexcept -> void;
    auto state_sync(const Work work, Message&& msg) noexcept -> void;
    auto transition_state_run() noexcept -> void;
    auto transition_state_sync() noexcept -> void;
    auto transmit(Message&& msg, bool request) noexcept -> void;
    auto transmit_push(Message&& msg) noexcept -> void;
    auto transmit_request(Message&& msg) noexcept -> void;
    auto update_dht_position(const network::p2p::Data& data) noexcept -> void;
    auto update_dht_position(const network::p2p::State& state) noexcept -> void;
    auto update_incoming() noexcept -> void;
    auto update_queue_position() noexcept -> void;
    auto update_queue_position(const network::p2p::Data& data) noexcept -> void;
    auto work() noexcept -> bool;
};
}  // namespace opentxs::blockchain::node::p2p
