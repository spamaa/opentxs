// Copyright (c) 2010-2021 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "0_stdafx.hpp"     // IWYU pragma: associated
#include "1_Internal.hpp"   // IWYU pragma: associated
#include "util/Thread.hpp"  // IWYU pragma: associated

#include <errno.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>
#include <array>
#include <map>

#include "opentxs/core/Log.hpp"
#include "opentxs/core/LogSource.hpp"

namespace opentxs
{
auto SetThisThreadsPriority(ThreadPriority priority) noexcept -> void
{
    static const auto map = std::map<ThreadPriority, int>{
        {ThreadPriority::Idle, 20},
        {ThreadPriority::Lowest, 15},
        {ThreadPriority::BelowNormal, 10},
        {ThreadPriority::Normal, 0},
        {ThreadPriority::AboveNormal, -10},
        {ThreadPriority::Highest, -15},
        {ThreadPriority::TimeCritical, -20},
    };
    const auto nice = map.at(priority);
    const auto tid = ::gettid();
    const auto rc = ::setpriority(PRIO_PROCESS, tid, nice);
    const auto error = errno;

    if (-1 == rc) {
        auto buf = std::array<char, 1024>{};
        const auto* text = ::strerror_r(error, buf.data(), buf.size());
        LogDebug(__func__)(": failed to set thread priority to ")(
            opentxs::print(priority))(" due to: ")(text)
            .Flush();
    }
}
}  // namespace opentxs