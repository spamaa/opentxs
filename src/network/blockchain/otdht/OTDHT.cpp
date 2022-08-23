// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// IWYU pragma: no_include <boost/smart_ptr/detail/operator_bool.hpp>

#include "0_stdafx.hpp"                           // IWYU pragma: associated
#include "1_Internal.hpp"                         // IWYU pragma: associated
#include "internal/network/blockchain/OTDHT.hpp"  // IWYU pragma: associated

#include <boost/smart_ptr/make_shared.hpp>
#include <boost/smart_ptr/shared_ptr.hpp>
#include <string_view>

#include "internal/network/blockchain/Types.hpp"
#include "internal/network/zeromq/Context.hpp"
#include "internal/util/LogMacros.hpp"
#include "network/blockchain/otdht/Actor.hpp"
#include "opentxs/api/network/Network.hpp"
#include "opentxs/api/session/Session.hpp"
#include "opentxs/network/zeromq/Context.hpp"
#include "opentxs/util/Allocator.hpp"
#include "opentxs/util/Container.hpp"
#include "opentxs/util/Log.hpp"
#include "opentxs/util/WorkType.hpp"

namespace opentxs::network::blockchain
{
using namespace std::literals;

auto print(DHTJob job) noexcept -> std::string_view
{
    try {
        using Job = DHTJob;
        static const auto map = Map<Job, std::string_view>{
            {Job::shutdown, "shutdown"sv},
            {Job::sync_ack, "sync_ack"sv},
            {Job::sync_reply, "sync_reply"sv},
            {Job::sync_push, "sync_push"sv},
            {Job::response, "response"sv},
            {Job::push_tx, "push_tx"sv},
            {Job::job_processed, "job_processed"sv},
            {Job::registration, "registration"sv},
            {Job::init, "init"sv},
            {Job::cfilter, "cfilter"sv},
            {Job::statemachine, "statemachine"sv},
        };

        return map.at(job);
    } catch (...) {
        LogAbort()(__FUNCTION__)("invalid DHTJob: ")(
            static_cast<OTZMQWorkType>(job))
            .Abort();
    }
}
}  // namespace opentxs::network::blockchain

namespace opentxs::network::blockchain
{
OTDHT::OTDHT(
    std::shared_ptr<const api::Session> api,
    std::shared_ptr<const opentxs::blockchain::node::Manager> node) noexcept
{
    OT_ASSERT(api);
    OT_ASSERT(node);

    const auto& zmq = api->Network().ZeroMQ().Internal();
    const auto batchID = zmq.PreallocateBatch();
    // TODO the version of libc++ present in android ndk 23.0.7599858 has a
    // broken std::allocate_shared function so we're using boost::shared_ptr
    // instead of std::shared_ptr
    auto actor = boost::allocate_shared<Actor>(
        alloc::PMR<Actor>{zmq.Alloc(batchID)}, api, node, batchID);

    OT_ASSERT(actor);

    actor->Init(actor);
}

auto OTDHT::Init() noexcept -> void
{
    // NOTE this function intentionally left blank
}

OTDHT::~OTDHT() = default;
}  // namespace opentxs::network::blockchain
