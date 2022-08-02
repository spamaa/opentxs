// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <boost/container/flat_map.hpp>
#include <boost/container/vector.hpp>
#include <boost/smart_ptr/shared_ptr.hpp>
#include <cs_plain_guarded.h>
#include <cs_shared_guarded.h>
#include <chrono>
#include <cstddef>
#include <exception>
#include <functional>
#include <future>
#include <iosfwd>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string_view>
#include <tuple>
#include <utility>

#include "blockchain/node/blockoracle/BlockFetcher.hpp"
#include "blockchain/node/blockoracle/Cache.hpp"
#include "core/Worker.hpp"
#include "internal/blockchain/block/Validator.hpp"
#include "internal/blockchain/database/Block.hpp"
#include "internal/blockchain/node/Types.hpp"
#include "internal/blockchain/node/blockoracle/BlockBatch.hpp"
#include "internal/blockchain/node/blockoracle/BlockFetcher.hpp"
#include "internal/blockchain/node/blockoracle/BlockOracle.hpp"
#include "internal/network/zeromq/Types.hpp"
#include "internal/network/zeromq/socket/Raw.hpp"
#include "internal/util/Timer.hpp"
#include "opentxs/blockchain/BlockchainType.hpp"
#include "opentxs/blockchain/Types.hpp"
#include "opentxs/blockchain/block/Hash.hpp"
#include "opentxs/blockchain/block/Position.hpp"
#include "opentxs/blockchain/block/Types.hpp"
#include "opentxs/blockchain/node/BlockOracle.hpp"
#include "opentxs/blockchain/node/Types.hpp"
#include "opentxs/util/Allocated.hpp"
#include "opentxs/util/Bytes.hpp"
#include "opentxs/util/Container.hpp"
#include "opentxs/util/Time.hpp"
#include "opentxs/util/WorkType.hpp"
#include "util/Actor.hpp"
#include "util/Work.hpp"

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
namespace bitcoin
{
namespace block
{
class Block;
}  // namespace block
}  // namespace bitcoin

namespace block
{
class Position;
}  // namespace block

namespace node
{
namespace blockoracle
{
class BlockBatch;
class BlockDownloader;
}  // namespace blockoracle

namespace internal
{
class BlockBatch;
struct Config;
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
class Publish;
}  // namespace socket

class Frame;
class Message;
}  // namespace zeromq
}  // namespace network
// }  // namespace v1
}  // namespace opentxs
// NOLINTEND(modernize-concat-nested-namespaces)

namespace opentxs::blockchain::node::internal
{
using namespace std::literals;

class BlockOracle::Shared : public Allocated
{
private:
    std::shared_ptr<const api::Session> api_p_;
    std::shared_ptr<const node::Manager> node_p_;

public:
    using Cache =
        libguarded::shared_guarded<blockoracle::Cache, std::shared_mutex>;
    using GuardedSocket =
        libguarded::plain_guarded<network::zeromq::socket::Raw>;

    const CString submit_endpoint_;
    mutable Cache cache_;
    mutable GuardedSocket to_actor_;

    auto GetBlockBatch(boost::shared_ptr<Shared> me) const noexcept
        -> BlockBatch;
    auto GetBlockJob() const noexcept -> BlockBatch;
    auto get_allocator() const noexcept -> allocator_type final;
    auto LoadBitcoin(const block::Hash& block) const noexcept
        -> BitcoinBlockResult;
    auto LoadBitcoin(const Vector<block::Hash>& hashes) const noexcept
        -> BitcoinBlockResults;
    auto SubmitBlock(const ReadView in) const noexcept -> void;
    auto Tip() const noexcept -> block::Position { return db_.BlockTip(); }
    auto Validate(const bitcoin::block::Block& block) const noexcept -> bool
    {
        return validator_->Validate(block);
    }

    auto Shutdown() noexcept -> void;
    auto StartDownloader() noexcept -> void;

    Shared(
        std::shared_ptr<const api::Session> api,
        std::shared_ptr<const node::Manager> node,
        allocator_type alloc) noexcept;
    Shared() = delete;
    Shared(const Shared&) = delete;
    Shared(Shared&&) = delete;
    auto operator=(const Shared&) -> Shared& = delete;
    auto operator=(Shared&&) -> Shared& = delete;

private:
    using OptionalFetcher = std::optional<blockoracle::BlockFetcher>;
    using GuardedFetcher = libguarded::plain_guarded<OptionalFetcher>;

    const database::Block& db_;
    const std::unique_ptr<const block::Validator> validator_;
    mutable GuardedFetcher block_fetcher_;

    static auto get_validator(
        const blockchain::Type chain,
        const node::HeaderOracle& headers) noexcept
        -> std::unique_ptr<const block::Validator>;

    auto trigger() const noexcept -> void;
};
}  // namespace opentxs::blockchain::node::internal

namespace opentxs::blockchain::node::internal
{
class BlockOracle::Actor final
    : public opentxs::Actor<BlockOracle::Actor, BlockOracleJobs>
{
public:
    auto Init(boost::shared_ptr<Actor> me) noexcept -> void;

    Actor(
        std::shared_ptr<const api::Session> api,
        std::shared_ptr<const node::Manager> node,
        boost::shared_ptr<Shared> shared,
        network::zeromq::BatchID batch,
        allocator_type alloc) noexcept;
    Actor() = delete;
    Actor(const Actor&) = delete;
    Actor(Actor&&) = delete;
    auto operator=(const Actor&) -> Actor& = delete;
    auto operator=(Actor&&) -> Actor& = delete;

    ~Actor() final;

private:
    friend opentxs::Actor<BlockOracle::Actor, BlockOracleJobs>;

    static constexpr auto heartbeat_interval_ = 1s;

    std::shared_ptr<const api::Session> api_p_;
    std::shared_ptr<const node::Manager> node_p_;
    boost::shared_ptr<Shared> shared_;
    const api::Session& api_;
    const node::Manager& node_;
    Shared::Cache& cache_;
    Timer heartbeat_;

    auto do_shutdown() noexcept -> void;
    auto do_startup() noexcept -> void;
    auto pipeline(const Work work, Message&& msg) noexcept -> void;
    auto work() noexcept -> bool;
};
}  // namespace opentxs::blockchain::node::internal
