// Copyright (c) 2010-2021 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <string>

namespace opentxs::internal
{
class Log
{
public:
    static auto SetVerbosity(const int level) noexcept -> void;
    static auto Shutdown() noexcept -> void;
    static auto StartLog(
        const opentxs::Log& source,
        const std::string& function) noexcept -> const opentxs::Log&;

    Log() = default;

    virtual ~Log() = default;

private:
    Log(const Log&) = delete;
    Log(Log&&) = delete;
    auto operator=(const Log&) -> Log& = delete;
    auto operator=(Log&&) -> Log& = delete;
};
}  // namespace opentxs::internal
