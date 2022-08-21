// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <string_view>

#include "opentxs/util/WorkType.hpp"
#include "util/Work.hpp"

namespace opentxs::network::otdht
{
// WARNING update print function if new values are added or removed
enum class Job : OTZMQWorkType {
    Shutdown = value(WorkType::Shutdown),
    BlockHeader = value(WorkType::BlockchainNewHeader),
    Reorg = value(WorkType::BlockchainReorg),
    SyncServerUpdated = value(WorkType::SyncServerUpdated),
    SyncAck = value(WorkType::P2PBlockchainSyncAck),
    SyncReply = value(WorkType::P2PBlockchainSyncReply),
    SyncPush = value(WorkType::P2PBlockchainNewBlock),
    Response = value(WorkType::P2PResponse),
    PublishContract = value(WorkType::P2PPublishContract),
    QueryContract = value(WorkType::P2PQueryContract),
    PushTransaction = value(WorkType::P2PPushTransaction),
    Register = OT_ZMQ_INTERNAL_SIGNAL + 0,
    Request = OT_ZMQ_INTERNAL_SIGNAL + 1,
    Processed = OT_ZMQ_INTERNAL_SIGNAL + 2,
    ReorgInternal = OT_ZMQ_REORG_SIGNAL,
    NewHeaderTip = OT_ZMQ_NEW_BLOCK_HEADER_SIGNAL,
    Init = OT_ZMQ_INIT_SIGNAL,
    NewCFilterTip = OT_ZMQ_NEW_FILTER_SIGNAL,
    StateMachine = OT_ZMQ_STATE_MACHINE_SIGNAL,
};
// WARNING update print function if new values are added or removed
enum class NodeJob : OTZMQWorkType {
    shutdown = value(WorkType::Shutdown),
    chain_state = value(WorkType::BlockchainStateChange),
    new_cfilter = value(WorkType::BlockchainNewFilter),
    new_peer = value(WorkType::SyncServerUpdated),
    init = OT_ZMQ_INIT_SIGNAL,
    statemachine = OT_ZMQ_STATE_MACHINE_SIGNAL,
};
// WARNING update print function if new values are added or removed
enum class PeerJob : OTZMQWorkType {
    shutdown = value(WorkType::Shutdown),
    chain_state = value(WorkType::BlockchainStateChange),
    sync_request = value(WorkType::P2PBlockchainSyncRequest),
    sync_ack = value(WorkType::P2PBlockchainSyncAck),
    sync_reply = value(WorkType::P2PBlockchainSyncReply),
    sync_push = value(WorkType::P2PBlockchainNewBlock),
    response = value(WorkType::P2PResponse),
    push_tx = value(WorkType::P2PPushTransaction),
    registration = OT_ZMQ_REGISTER_SIGNAL,
    init = OT_ZMQ_INIT_SIGNAL,
    statemachine = OT_ZMQ_STATE_MACHINE_SIGNAL,
};

auto print(Job) noexcept -> std::string_view;
auto print(NodeJob) noexcept -> std::string_view;
auto print(PeerJob) noexcept -> std::string_view;
}  // namespace opentxs::network::otdht
