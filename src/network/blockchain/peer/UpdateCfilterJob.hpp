// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include "network/blockchain/peer/Imp.hpp"  // IWYU pragma: associated

namespace opentxs::network::blockchain::internal
{
class Peer::Imp::UpdateCfilterJob
{
public:
    auto operator()(std::monostate& job) noexcept -> JobUpdate;
    auto operator()(
        opentxs::blockchain::node::internal::HeaderJob& job) noexcept
        -> JobUpdate;
    auto operator()(
        opentxs::blockchain::node::internal::BlockBatch& job) noexcept
        -> JobUpdate;
    auto operator()(opentxs::blockchain::node::CfheaderJob& job) noexcept
        -> JobUpdate;
    auto operator()(opentxs::blockchain::node::CfilterJob& job) noexcept
        -> JobUpdate;

    UpdateCfilterJob(
        opentxs::blockchain::cfilter::Type type,
        opentxs::blockchain::block::Position&& block,
        opentxs::blockchain::GCS&& filter) noexcept;

private:
    opentxs::blockchain::block::Position block_;
    opentxs::blockchain::cfilter::Type type_;
    opentxs::blockchain::GCS filter_;
};
}  // namespace opentxs::network::blockchain::internal
