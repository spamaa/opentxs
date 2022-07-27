// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <boost/smart_ptr/shared_ptr.hpp>
#include <cs_plain_guarded.h>
#include <cstddef>
#include <memory>
#include <optional>
#include <tuple>
#include <vector>

#include "internal/blockchain/node/Job.hpp"
#include "internal/blockchain/node/blockoracle/BlockFetcher.hpp"
#include "internal/blockchain/node/blockoracle/Types.hpp"
#include "internal/network/zeromq/Types.hpp"
#include "opentxs/blockchain/Types.hpp"
#include "opentxs/blockchain/block/Position.hpp"
#include "opentxs/blockchain/block/Types.hpp"
#include "opentxs/util/Allocated.hpp"
#include "opentxs/util/Allocator.hpp"
#include "opentxs/util/Bytes.hpp"
#include "opentxs/util/Container.hpp"
#include "opentxs/util/Time.hpp"
#include "util/Actor.hpp"

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
class Hash;
class Position;
}  // namespace block

namespace database
{
class Block;
}  // namespace database

namespace node
{
namespace internal
{
class BlockBatch;
}  // namespace internal

class HeaderOracle;
class Manager;
struct Endpoints;
}  // namespace node
}  // namespace blockchain

namespace network
{
namespace zeromq
{
namespace socket
{
class Raw;
}  // namespace socket
}  // namespace zeromq
}  // namespace network
// }  // namespace v1
}  // namespace opentxs
// NOLINTEND(modernize-concat-nested-namespaces)

namespace opentxs::blockchain::node::blockoracle
{
class BlockFetcher::Shared : public Allocated
{
public:
    enum class Status { pending, downloading, success };
    using Index =
        Map<block::Height,
            std::tuple<block::Hash, std::optional<download::JobID>, Status>>;

    struct Data : public Allocated {
        block::Position tip_;
        std::size_t queue_;
        Index blocks_;
        Map<download::JobID, Map<block::Hash, Index::iterator>> job_index_;

        auto get_allocator() const noexcept -> allocator_type final;

        Data(allocator_type alloc) noexcept;
        Data() = delete;
        Data(const Data&) = delete;
        Data(Data&&) = delete;
        auto operator=(const Data&) -> Data& = delete;
        auto operator=(Data&&) -> Data& = delete;
    };

    using Guarded = libguarded::plain_guarded<Data>;

    mutable Guarded data_;

    auto get_allocator() const noexcept -> allocator_type final;

    Shared(allocator_type alloc) noexcept;
};
}  // namespace opentxs::blockchain::node::blockoracle

namespace opentxs::blockchain::node::blockoracle
{
class BlockFetcher::Imp final : public Actor<Imp, BlockFetcherJob>
{
public:
    auto GetJob(allocator_type alloc) const noexcept -> internal::BlockBatch;

    auto Init(boost::shared_ptr<Imp> self) noexcept -> void;

    Imp(std::shared_ptr<const api::Session> api,
        std::shared_ptr<const node::Manager> node,
        boost::shared_ptr<Shared> shared,
        network::zeromq::BatchID batchID,
        allocator_type alloc) noexcept;
    Imp() = delete;
    Imp(const Imp&) = delete;
    Imp(Imp&&) = delete;
    auto operator=(const Imp&) -> Imp& = delete;
    auto operator=(Imp&&) -> Imp& = delete;

    ~Imp() final;

private:
    friend Actor<Imp, BlockFetcherJob>;

    using Status = Shared::Status;

    std::shared_ptr<const api::Session> api_p_;
    std::shared_ptr<const node::Manager> node_p_;
    boost::shared_ptr<Shared> shared_;
    const api::Session& api_;
    const node::Manager& node_;
    const HeaderOracle& header_oracle_;
    database::Block& db_;
    network::zeromq::socket::Raw& job_ready_;
    network::zeromq::socket::Raw& tip_updated_;
    const blockchain::Type chain_;
    const std::size_t peer_target_;
    Shared::Guarded& data_;
    boost::shared_ptr<Imp> self_;

    auto broadcast_tip(const block::Position& tip) noexcept -> void;
    auto do_shutdown() noexcept -> void;
    auto do_startup() noexcept -> void;
    auto erase_obsolete(
        const block::Position& after,
        Shared::Data& data) noexcept -> void;
    auto pipeline(const Work work, Message&& msg) noexcept -> void;
    auto process_batch_finished(Message&& msg) noexcept -> void;
    auto process_block_received(Message&& msg) noexcept -> void;
    auto process_reorg(Message&& msg) noexcept -> void;
    auto update_tip(Shared::Data& data) noexcept -> void;
    auto work() noexcept -> bool;
};
}  // namespace opentxs::blockchain::node::blockoracle
