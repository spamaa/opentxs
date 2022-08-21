// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "0_stdafx.hpp"                   // IWYU pragma: associated
#include "1_Internal.hpp"                 // IWYU pragma: associated
#include "api/network/otdht/Disable.hpp"  // IWYU pragma: associated

#include "internal/network/otdht/Server.hpp"

namespace opentxs::api::network::implementation
{
OTDHT::DisableChain::DisableChain(opentxs::blockchain::Type chain) noexcept
    : chain_(chain)
{
}

auto OTDHT::DisableChain::operator()(std::monostate& val) const noexcept -> void
{
}

auto OTDHT::DisableChain::operator()(
    opentxs::network::otdht::Server& val) const noexcept -> void
{
    val.Disable(chain_);
}
}  // namespace opentxs::api::network::implementation
