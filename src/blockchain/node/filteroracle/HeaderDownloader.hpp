// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// IWYU pragma: no_forward_declare opentxs::blockchain::node::implementation::FilterOracle::HeaderDownloader
// IWYU pragma: no_include "opentxs/blockchain/BlockchainType.hpp"
// IWYU pragma: no_include "opentxs/blockchain/bitcoin/cfilter/FilterType.hpp"

#pragma once

#include <cstddef>
#include <exception>
#include <functional>
#include <future>

#include "blockchain/DownloadManager.hpp"
#include "blockchain/DownloadTask.hpp"
#include "blockchain/node/filteroracle/FilterOracle.hpp"
#include "core/Worker.hpp"
#include "opentxs/api/session/Session.hpp"
#include "opentxs/blockchain/Types.hpp"
#include "opentxs/blockchain/bitcoin/cfilter/Hash.hpp"
#include "opentxs/blockchain/bitcoin/cfilter/Header.hpp"
#include "opentxs/blockchain/bitcoin/cfilter/Types.hpp"
#include "opentxs/util/Container.hpp"
#include "opentxs/util/Time.hpp"

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

namespace cfilter
{
class Hash;
class Header;
}  // namespace cfilter

namespace database
{
class Cfilter;
}  // namespace database

namespace node
{
namespace internal
{
class Manager;
}  // namespace internal

class HeaderOracle;
}  // namespace node
}  // namespace blockchain

namespace network
{
namespace zeromq
{
class Message;
}  // namespace zeromq
}  // namespace network
// }  // namespace v1
}  // namespace opentxs
// NOLINTEND(modernize-concat-nested-namespaces)

namespace opentxs::blockchain::node::implementation
{
using HeaderDM = download::Manager<
    FilterOracle::HeaderDownloader,
    cfilter::Hash,
    cfilter::Header,
    cfilter::Type>;
using HeaderWorker = Worker<FilterOracle::HeaderDownloader, api::Session>;

class FilterOracle::HeaderDownloader : public HeaderDM, public HeaderWorker
{
public:
    using Callback =
        std::function<Position(const Position&, const cfilter::Header&)>;

    auto NextBatch() noexcept -> BatchType;

    HeaderDownloader(
        const api::Session& api,
        database::Cfilter& db,
        const HeaderOracle& header,
        const internal::Manager& node,
        FilterOracle::FilterDownloader& filter,
        const blockchain::Type chain,
        const cfilter::Type type,
        const UnallocatedCString& shutdown,
        Callback&& cb) noexcept;

    ~HeaderDownloader();

private:
    friend HeaderDM;
    friend HeaderWorker;

    database::Cfilter& db_;
    const HeaderOracle& header_;
    const internal::Manager& node_;
    FilterOracle::FilterDownloader& filter_;
    const blockchain::Type chain_;
    const cfilter::Type type_;
    const Callback checkpoint_;

    auto batch_ready() const noexcept -> void;
    auto batch_size(const std::size_t in) const noexcept -> std::size_t;
    auto check_task(TaskType&) const noexcept -> void;
    auto trigger_state_machine() const noexcept -> void;
    auto update_tip(const Position& position, const cfilter::Header&)
        const noexcept -> void;

    auto pipeline(const zmq::Message& in) noexcept -> void;
    auto process_position(const zmq::Message& in) noexcept -> void;
    auto process_position() noexcept -> void;
    auto process_reset(const zmq::Message& in) noexcept -> void;
    auto queue_processing(DownloadedData&& data) noexcept -> void;
    auto shutdown(std::promise<void>& promise) noexcept -> void;
};
}  // namespace opentxs::blockchain::node::implementation
