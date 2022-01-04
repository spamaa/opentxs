// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include "opentxs/Version.hpp"  // IWYU pragma: associated

#include <string>

namespace opentxs
{
class Secret;
}  // namespace opentxs

namespace opentxs
{
class OPENTXS_EXPORT PasswordCallback
{
public:
    // Asks for password once. (For authentication when using nym.)
    virtual void runOne(
        const char* szDisplay,
        Secret& theOutput,
        const std::string& key) const = 0;

    // Asks for password twice. (For confirmation when changing password or
    // creating nym.)
    virtual void runTwo(
        const char* szDisplay,
        Secret& theOutput,
        const std::string& key) const = 0;

    PasswordCallback() = default;
    virtual ~PasswordCallback() = default;
};
}  // namespace opentxs