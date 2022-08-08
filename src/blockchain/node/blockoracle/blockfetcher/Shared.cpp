// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// IWYU pragma: no_include <boost/smart_ptr/detail/operator_bool.hpp>

#include "0_stdafx.hpp"    // IWYU pragma: associated
#include "1_Internal.hpp"  // IWYU pragma: associated
#include "blockchain/node/blockoracle/blockfetcher/Shared.hpp"  // IWYU pragma: associated

#include <boost/smart_ptr/shared_ptr.hpp>
#include <memory>
#include <utility>

#include "blockchain/node/blockoracle/BlockBatch.hpp"
#include "internal/blockchain/node/Config.hpp"
#include "internal/blockchain/node/Endpoints.hpp"
#include "internal/blockchain/node/Manager.hpp"
#include "internal/blockchain/node/blockoracle/BlockBatch.hpp"
#include "internal/blockchain/node/blockoracle/Types.hpp"
#include "internal/network/zeromq/Context.hpp"
#include "internal/network/zeromq/socket/Raw.hpp"
#include "internal/util/LogMacros.hpp"
#include "internal/util/P0330.hpp"
#include "opentxs/api/network/Network.hpp"
#include "opentxs/api/session/Session.hpp"
#include "opentxs/blockchain/node/Manager.hpp"
#include "opentxs/network/zeromq/Context.hpp"
#include "opentxs/network/zeromq/message/Message.hpp"
#include "opentxs/network/zeromq/socket/SocketType.hpp"
#include "opentxs/util/Allocator.hpp"
#include "util/ScopeGuard.hpp"
#include "util/Work.hpp"

namespace opentxs::blockchain::node::blockoracle
{
BlockFetcher::Shared::Data::Data(allocator_type alloc) noexcept
    : tip_()
    , queue_()
    , blocks_(alloc)
    , job_index_(alloc)
{
}

auto BlockFetcher::Shared::Data::get_allocator() const noexcept
    -> allocator_type
{
    return job_index_.get_allocator();
}
}  // namespace opentxs::blockchain::node::blockoracle

namespace opentxs::blockchain::node::blockoracle
{
BlockFetcher::Shared::Shared(
    const api::Session& api,
    const node::Manager& node,
    network::zeromq::BatchID batchID,
    allocator_type alloc) noexcept
    : batch_id_(std::move(batchID))
    , peer_target_(
          node.Internal().GetConfig().PeerTarget(node.Internal().Chain()))
    , data_(std::move(alloc))
    , to_actor_([&] {
        using Type = network::zeromq::socket::Type;
        auto out = api.Network().ZeroMQ().Internal().RawSocket(Type::Push);
        const auto rc = out.Connect(
            node.Internal().Endpoints().block_fetcher_pull_.c_str());

        OT_ASSERT(rc);

        return out;
    }())
{
}

auto BlockFetcher::Shared::GetJob(
    boost::shared_ptr<Shared> self,
    allocator_type pmr) const noexcept -> internal::BlockBatch
{
    OT_ASSERT(self);

    auto alloc = alloc::PMR<internal::BlockBatch::Imp>{pmr};
    auto* imp = alloc.allocate(1_uz);
    const auto id = download::next_job();
    auto hashes = [&] {
        // TODO define max in Params
        static constexpr auto max = 50000_uz;
        static constexpr auto min = 10_uz;
        auto handle = data_.lock();
        auto& data = *handle;
        auto& queue = data.queue_;
        auto& blocks = data.blocks_;
        const auto count = download::batch_size(queue, peer_target_, max, min);

        OT_ASSERT(blocks.size() >= count);
        OT_ASSERT(count <= queue);

        auto& index = data.job_index_[id];
        auto out = Vector<block::Hash>{pmr};
        out.reserve(count);
        auto i = blocks.begin();

        while (out.size() < count) {
            auto cur = i++;
            auto& [height, val] = *cur;
            auto& [hash, job, status] = val;

            if (Status::pending == status) {
                --queue;
                job = id;
                status = Status::downloading;
                --data.queue_;
                out.emplace_back(hash);
                index.emplace(hash, cur);
            }
        }

        return out;
    }();

    if (hashes.empty()) {

        return {};
    } else {
        auto download = [me = self, id](const auto bytes) {
            me->to_actor_.lock()->SendDeferred(
                [bytes, id] {
                    auto msg = MakeWork(BlockFetcherJob::block_received);
                    msg.AddFrame(id);
                    msg.AddFrame(bytes.data(), bytes.size());

                    return msg;
                }(),
                __FILE__,
                __LINE__);
        };
        auto finished = [me = self, id] {
            me->to_actor_.lock()->SendDeferred(
                [id] {
                    auto msg = MakeWork(BlockFetcherJob::batch_finished);
                    msg.AddFrame(id);

                    return msg;
                }(),
                __FILE__,
                __LINE__);
        };
        alloc.construct(
            imp,
            id,
            std::move(hashes),
            download,
            std::make_shared<ScopeGuard>(finished));

        return imp;
    }
}

auto BlockFetcher::Shared::get_allocator() const noexcept -> allocator_type
{
    return data_.lock()->get_allocator();
}

BlockFetcher::Shared::~Shared() = default;
}  // namespace opentxs::blockchain::node::blockoracle
