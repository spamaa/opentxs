// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "0_stdafx.hpp"                       // IWYU pragma: associated
#include "1_Internal.hpp"                     // IWYU pragma: associated
#include "api/network/otdht/GetEndpoint.hpp"  // IWYU pragma: associated

#include "internal/network/otdht/Client.hpp"
#include "opentxs/util/Container.hpp"

namespace opentxs::api::network::implementation
{
auto OTDHT::GetEndpoint::blank() noexcept -> std::string_view
{
    static const auto out = UnallocatedCString{};

    return out;
}

auto OTDHT::GetEndpoint::operator()(const std::monostate& val) const noexcept
    -> std::string_view
{
    return blank();
}

auto OTDHT::GetEndpoint::operator()(const opentxs::network::otdht::Client& val)
    const noexcept -> std::string_view
{
    return val.Endpoint();
}

auto OTDHT::GetEndpoint::operator()(const opentxs::network::otdht::Server& val)
    const noexcept -> std::string_view
{
    return blank();
}
}  // namespace opentxs::api::network::implementation
