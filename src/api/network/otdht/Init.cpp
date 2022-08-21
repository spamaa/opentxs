// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "0_stdafx.hpp"                // IWYU pragma: associated
#include "1_Internal.hpp"              // IWYU pragma: associated
#include "api/network/otdht/Init.hpp"  // IWYU pragma: associated

#include "internal/network/otdht/Client.hpp"

namespace opentxs::api::network::implementation
{
OTDHT::Init::Init(const api::network::Blockchain& blockchain) noexcept
    : blockchain_(blockchain)
{
}

auto OTDHT::Init::operator()(std::monostate& val) const noexcept -> void {}

auto OTDHT::Init::operator()(
    opentxs::network::otdht::Client& val) const noexcept -> void
{
    val.Init(blockchain_);
}

auto OTDHT::Init::operator()(
    opentxs::network::otdht::Server& val) const noexcept -> void
{
}
}  // namespace opentxs::api::network::implementation
