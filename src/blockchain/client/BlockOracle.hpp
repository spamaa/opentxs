// Copyright (c) 2010-2020 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <boost/container/flat_map.hpp>
#include <chrono>
#include <deque>
#include <functional>
#include <future>
#include <iosfwd>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <tuple>
#include <utility>

#include "core/Worker.hpp"
#include "internal/blockchain/client/Client.hpp"
#include "opentxs/Bytes.hpp"
#include "opentxs/Types.hpp"
#include "opentxs/blockchain/Blockchain.hpp"
#include "opentxs/blockchain/BlockchainType.hpp"
#include "opentxs/blockchain/Types.hpp"
#include "opentxs/blockchain/client/BlockOracle.hpp"
#include "opentxs/core/Data.hpp"
#include "opentxs/util/WorkType.hpp"
#include "util/Work.hpp"

namespace opentxs
{
namespace api
{
namespace client
{
class Blockchain;
}  // namespace client

class Core;
}  // namespace api

namespace network
{
namespace zeromq
{
class Frame;
class Message;
}  // namespace zeromq
}  // namespace network
}  // namespace opentxs

namespace opentxs::blockchain::client::implementation
{
class BlockOracle final : public internal::BlockOracle,
                          public Worker<BlockOracle, api::Core>
{
public:
    class BlockDownloader;

    enum class Work : OTZMQWorkType {
        block = value(WorkType::BlockchainNewHeader),
        reorg = value(WorkType::BlockchainReorg),
        statemachine = OT_ZMQ_STATE_MACHINE_SIGNAL,
        shutdown = value(WorkType::Shutdown),
    };

    auto GetBlockJob() const noexcept -> BlockJob final;
    auto Heartbeat() const noexcept -> void final;
    auto LoadBitcoin(const block::Hash& block) const noexcept
        -> BitcoinBlockFuture final;
    auto LoadBitcoin(const BlockHashes& hashes) const noexcept
        -> BitcoinBlockFutures final;
    auto SubmitBlock(const ReadView in) const noexcept -> void final;
    auto Tip() const noexcept -> block::Position final
    {
        return db_.BlockTip();
    }

    auto Init() noexcept -> void final;
    auto Shutdown() noexcept -> std::shared_future<void> final
    {
        return stop_worker();
    }

    BlockOracle(
        const api::Core& api,
        const internal::Network& network,
        const internal::HeaderOracle& header,
        const internal::BlockDatabase& db,
        const blockchain::Type chain,
        const std::string& shutdown) noexcept;

    ~BlockOracle() final;

private:
    friend Worker<BlockOracle, api::Core>;

    using Promise = std::promise<BitcoinBlock_p>;
    using PendingData = std::tuple<Time, Promise, BitcoinBlockFuture, bool>;
    using Pending = std::map<block::pHash, PendingData>;

    struct Cache {
        auto ReceiveBlock(const zmq::Frame& in) const noexcept -> void;
        auto ReceiveBlock(BitcoinBlock_p in) const noexcept -> void;
        auto Request(const block::Hash& block) const noexcept
            -> BitcoinBlockFuture;
        auto Request(const BlockHashes& hashes) const noexcept
            -> BitcoinBlockFutures;
        auto StateMachine() const noexcept -> bool;

        auto Shutdown() noexcept -> void;

        Cache(
            const api::Core& api_,
            const internal::Network& network,
            const internal::BlockDatabase& db,
            const blockchain::Type chain) noexcept;
        ~Cache() { Shutdown(); }

    private:
        static const std::size_t cache_limit_;
        static const std::chrono::seconds download_timeout_;

        struct Mem {
            auto find(const ReadView& id) const noexcept -> BitcoinBlockFuture;

            auto clear() noexcept -> void;
            auto push(block::pHash&& id, BitcoinBlockFuture&& future) noexcept
                -> void;

            Mem(const std::size_t limit) noexcept;

        private:
            using Completed =
                std::deque<std::pair<block::pHash, BitcoinBlockFuture>>;
            using Index = boost::container::
                flat_map<ReadView, Completed::const_reverse_iterator>;

            const std::size_t limit_;
            Completed queue_;
            Index index_;
        };

        const api::Core& api_;
        const internal::Network& network_;
        const internal::BlockDatabase& db_;
        const blockchain::Type chain_;
        mutable std::mutex lock_;
        mutable Pending pending_;
        mutable Mem mem_;
        bool running_;

        auto download(const block::Hash& block) const noexcept -> bool;
    };

    const internal::Network& network_;
    const internal::BlockDatabase& db_;
    std::promise<void> init_promise_;
    std::shared_future<void> init_;
    Cache cache_;
    mutable std::mutex lock_;
    std::unique_ptr<BlockDownloader> block_downloader_;

    auto pipeline(const zmq::Message& in) noexcept -> void;
    auto shutdown(std::promise<void>& promise) noexcept -> void;
    auto state_machine() noexcept -> bool;

    BlockOracle() = delete;
    BlockOracle(const BlockOracle&) = delete;
    BlockOracle(BlockOracle&&) = delete;
    auto operator=(const BlockOracle&) -> BlockOracle& = delete;
    auto operator=(BlockOracle &&) -> BlockOracle& = delete;
};
}  // namespace opentxs::blockchain::client::implementation
