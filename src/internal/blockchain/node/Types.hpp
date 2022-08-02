// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// IWYU pragma: no_include "opentxs/blockchain/block/Hash.hpp"

#pragma once

#include <functional>
#include <memory>
#include <string_view>

#include "blockchain/DownloadTask.hpp"
#include "internal/util/Mutex.hpp"
#include "opentxs/blockchain/bitcoin/cfilter/Types.hpp"
#include "opentxs/util/WorkType.hpp"
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
class Hash;
}  // namespace block

namespace cfilter
{
class Hash;
class Header;
}  // namespace cfilter

namespace node
{
class HeaderOracle;
}  // namespace node

class GCS;
}  // namespace blockchain
// }  // namespace v1
}  // namespace opentxs
// NOLINTEND(modernize-concat-nested-namespaces)

namespace opentxs::blockchain::node
{
enum class ManagerJobs : OTZMQWorkType {
    Shutdown = value(WorkType::Shutdown),
    SyncReply = value(WorkType::P2PBlockchainSyncReply),
    SyncNewBlock = value(WorkType::P2PBlockchainNewBlock),
    SubmitBlockHeader = OT_ZMQ_INTERNAL_SIGNAL + 0,
    SubmitBlock = OT_ZMQ_INTERNAL_SIGNAL + 2,
    Heartbeat = OT_ZMQ_INTERNAL_SIGNAL + 3,
    SendToAddress = OT_ZMQ_INTERNAL_SIGNAL + 4,
    SendToPaymentCode = OT_ZMQ_INTERNAL_SIGNAL + 5,
    StartWallet = OT_ZMQ_INTERNAL_SIGNAL + 6,
    FilterUpdate = OT_ZMQ_NEW_FILTER_SIGNAL,
    StateMachine = OT_ZMQ_STATE_MACHINE_SIGNAL,
};

enum class PeerManagerJobs : OTZMQWorkType {
    Getheaders = OT_ZMQ_INTERNAL_SIGNAL + 0,
    BroadcastTransaction = OT_ZMQ_INTERNAL_SIGNAL + 2,
    JobAvailableCfheaders = OT_ZMQ_INTERNAL_SIGNAL + 4,
    JobAvailableCfilters = OT_ZMQ_INTERNAL_SIGNAL + 5,
    Heartbeat = OT_ZMQ_HEARTBEAT_SIGNAL,
};

using CfheaderJob =
    download::Batch<cfilter::Hash, cfilter::Header, cfilter::Type>;
using CfilterJob = download::Batch<GCS, cfilter::Header, cfilter::Type>;
using ReorgTask = std::function<bool(const node::HeaderOracle&, const Lock&)>;

constexpr auto value(PeerManagerJobs job) noexcept
{
    return static_cast<OTZMQWorkType>(job);
}
}  // namespace opentxs::blockchain::node
