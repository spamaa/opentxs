// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// IWYU pragma: no_include <boost/smart_ptr/detail/operator_bool.hpp>

#include "0_stdafx.hpp"                   // IWYU pragma: associated
#include "1_Internal.hpp"                 // IWYU pragma: associated
#include "network/otdht/node/Shared.hpp"  // IWYU pragma: associated

#include <algorithm>
#include <iterator>
#include <utility>

#include "opentxs/blockchain/Blockchain.hpp"
#include "opentxs/blockchain/BlockchainType.hpp"
#include "opentxs/util/Container.hpp"

namespace opentxs::network::otdht
{
Node::Shared::Shared(zeromq::BatchID batchID, allocator_type alloc) noexcept
    : Allocated(std::move(alloc))
    , batch_id_(std::move(batchID))
    , data_(get_allocator())
{
}

auto Node::Shared::Chains() noexcept -> const Set<opentxs::blockchain::Type>&
{
    static const auto chains = [] {
        auto set = opentxs::blockchain::SupportedChains();
        set.emplace(opentxs::blockchain::Type::UnitTest);
        auto out = Set<opentxs::blockchain::Type>{};
        std::copy(set.begin(), set.end(), std::inserter(out, out.end()));

        return out;
    }();

    return chains;
}

Node::Shared::~Shared() = default;
}  // namespace opentxs::network::otdht
