// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <cs_deferred_guarded.h>
#include <optional>
#include <shared_mutex>

#include "internal/blockchain/node/wallet/FeeOracle.hpp"
#include "opentxs/core/Amount.hpp"

class opentxs::blockchain::node::wallet::FeeOracle::Shared
{
public:
    using Estimate =
        libguarded::deferred_guarded<std::optional<Amount>, std::shared_mutex>;

    Estimate data_{std::nullopt};
};
