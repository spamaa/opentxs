// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

namespace opentxs::blockchain::node::wallet
{
class Job
{
public:
    virtual auto Init() noexcept -> void = 0;

    Job(const Job&) = delete;
    Job(Job&&) = delete;
    auto operator=(const Job&) -> Job& = delete;
    auto operator=(Job&&) -> Job& = delete;

    virtual ~Job() = default;

protected:
    Job() = default;
};
}  // namespace opentxs::blockchain::node::wallet
