// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <boost/smart_ptr/shared_ptr.hpp>
#include <string_view>

#include "internal/blockchain/node/Types.hpp"
#include "opentxs/blockchain/node/BlockOracle.hpp"
#include "opentxs/util/Container.hpp"
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
namespace node
{
namespace internal
{
class BlockBatch;
}  // namespace internal

class Manager;
}  // namespace node
}  // namespace blockchain
// }  // namespace v1
}  // namespace opentxs
// NOLINTEND(modernize-concat-nested-namespaces)

namespace opentxs::blockchain::node::internal
{
class BlockOracle final : public node::BlockOracle
{
public:
    class Actor;
    class Shared;

    auto DownloadQueue() const noexcept -> std::size_t final;
    auto Endpoint() const noexcept -> std::string_view;
    auto GetBlockBatch() const noexcept -> BlockBatch;
    auto GetBlockJob() const noexcept -> BlockBatch;
    auto Internal() const noexcept -> const BlockOracle& final { return *this; }
    auto LoadBitcoin(const block::Hash& block) const noexcept
        -> BitcoinBlockResult final;
    auto LoadBitcoin(const Vector<block::Hash>& hashes) const noexcept
        -> BitcoinBlockResults final;
    auto SubmitBlock(const ReadView in) const noexcept -> void;
    auto Tip() const noexcept -> block::Position final;
    auto Validate(const bitcoin::block::Block& block) const noexcept
        -> bool final;

    auto Init() noexcept -> void;
    auto Internal() noexcept -> BlockOracle& final { return *this; }
    auto Start(
        std::shared_ptr<const api::Session> api,
        std::shared_ptr<const node::Manager> node) noexcept -> void;
    auto Shutdown() noexcept -> void;

    BlockOracle() noexcept;
    BlockOracle(const BlockOracle&) = delete;
    BlockOracle(BlockOracle&& rhs) noexcept;
    auto operator=(const BlockOracle&) -> BlockOracle& = delete;
    auto operator=(BlockOracle&&) -> BlockOracle& = delete;

    ~BlockOracle() final;

private:
    // TODO switch to std::shared_ptr once the android ndk ships a version of
    // libc++ with unfucked pmr / allocate_shared support
    boost::shared_ptr<Shared> shared_;
    boost::shared_ptr<Actor> actor_;
};
}  // namespace opentxs::blockchain::node::internal
