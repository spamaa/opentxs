// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// IWYU pragma: no_include "opentxs/blockchain/BlockchainType.hpp"
// IWYU pragma: no_include "opentxs/blockchain/bitcoin/cfilter/FilterType.hpp"

#pragma once

#include <zmq.h>
#include <atomic>
#include <cstddef>
#include <exception>
#include <future>
#include <memory>
#include <mutex>
#include <thread>

#include "blockchain/DownloadManager.hpp"
#include "blockchain/DownloadTask.hpp"
#include "blockchain/node/manager/Manager.hpp"
#include "core/Worker.hpp"
#include "internal/util/Mutex.hpp"
#include "network/zeromq/socket/Socket.hpp"
#include "opentxs/api/session/Session.hpp"
#include "opentxs/blockchain/Types.hpp"
#include "opentxs/blockchain/bitcoin/cfilter/GCS.hpp"
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

namespace database
{
class Sync;
}  // namespace database

namespace node
{
namespace base
{
namespace implementation
{
class Base;
}  // namespace implementation

class SyncServer;
}  // namespace base

namespace internal
{
class FilterOracle;
class Manager;
}  // namespace internal

class HeaderOracle;
}  // namespace node

class GCS;
}  // namespace blockchain

namespace network
{
namespace p2p
{
class Block;
}  // namespace p2p

namespace zeromq
{
class Message;
}  // namespace zeromq
}  // namespace network
// }  // namespace v1
}  // namespace opentxs
// NOLINTEND(modernize-concat-nested-namespaces)

namespace opentxs::blockchain::node::base
{
using SyncDM = download::Manager<SyncServer, GCS, int, cfilter::Type>;
using SyncWorker = Worker<SyncServer, api::Session>;

class SyncServer : public SyncDM, public SyncWorker
{
public:
    auto Tip() const noexcept -> block::Position;

    auto NextBatch() noexcept -> BatchType;
    auto Shutdown() noexcept -> std::shared_future<void>;

    SyncServer(
        const api::Session& api,
        database::Sync& db,
        const node::HeaderOracle& header,
        const node::internal::FilterOracle& filter,
        const node::internal::Manager& node,
        const blockchain::Type chain,
        const cfilter::Type type,
        const UnallocatedCString& shutdown,
        const UnallocatedCString& publishEndpoint) noexcept;

    ~SyncServer();

private:
    friend SyncDM;
    friend SyncWorker;

    using Socket = std::unique_ptr<void, decltype(&::zmq_close)>;
    using OTSocket = network::zeromq::socket::implementation::Socket;
    using Work = node::implementation::Base::Work;

    database::Sync& db_;
    const node::HeaderOracle& header_;
    const node::internal::FilterOracle& filter_;
    const node::internal::Manager& node_;
    const blockchain::Type chain_;
    const cfilter::Type type_;
    const int linger_;
    const UnallocatedCString endpoint_;
    Socket socket_;
    mutable std::mutex zmq_lock_;
    std::atomic_bool zmq_running_;
    std::thread zmq_thread_;

    auto batch_ready() const noexcept -> void;
    auto batch_size(const std::size_t in) const noexcept -> std::size_t;
    auto check_task(TaskType&) const noexcept -> void;
    auto hello(const Lock&, const block::Position& incoming) const noexcept;
    auto trigger_state_machine() const noexcept -> void;
    auto update_tip(const Position& position, const int&) const noexcept
        -> void;

    auto download() noexcept -> void;
    auto pipeline(const zmq::Message& in) noexcept -> void;
    auto process_position(const zmq::Message& in) noexcept -> void;
    auto process_position(const Position& pos) noexcept -> void;
    auto process_zmq(const Lock& lock) noexcept -> void;
    auto queue_processing(DownloadedData&& data) noexcept -> void;
    auto shutdown(std::promise<void>& promise) noexcept -> void;
    auto zmq_thread() noexcept -> void;
};
}  // namespace opentxs::blockchain::node::base