// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "0_stdafx.hpp"                 // IWYU pragma: associated
#include "1_Internal.hpp"               // IWYU pragma: associated
#include "api/network/otdht/Start.hpp"  // IWYU pragma: associated

#include "internal/network/otdht/Server.hpp"

namespace opentxs::api::network::implementation
{
OTDHT::StartServer::StartServer(
    std::string_view bindInternal,
    std::string_view bindPublic,
    std::string_view publishInternal,
    std::string_view publishPublic) noexcept
    : bind_internal_(bindInternal)
    , bind_public_(bindPublic)
    , publish_internal_(publishInternal)
    , publish_public_(publishPublic)
{
}

auto OTDHT::StartServer::operator()(std::monostate& val) const noexcept -> bool
{
    return false;
}

auto OTDHT::StartServer::operator()(
    opentxs::network::otdht::Client& val) const noexcept -> bool
{
    return false;
}

auto OTDHT::StartServer::operator()(
    opentxs::network::otdht::Server& val) const noexcept -> bool
{
    return val.Start(
        bind_internal_, bind_public_, publish_internal_, publish_public_);
}
}  // namespace opentxs::api::network::implementation
