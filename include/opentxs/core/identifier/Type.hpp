// Copyright (c) 2010-2021 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <cstdint>

namespace opentxs::identifier
{
enum class Type : std::uint16_t {
    invalid = 0,
    generic = 1,
    nym = 2,
    notary = 3,
    unitdefinition = 4,
};
}  // namespace opentxs::identifier