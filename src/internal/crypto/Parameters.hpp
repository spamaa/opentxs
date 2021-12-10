// Copyright (c) 2010-2021 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include "opentxs/core/Data.hpp"

namespace opentxs
{
namespace proto
{
class ContactData;
class VerificationSet;
}  // namespace proto
}  // namespace opentxs

namespace opentxs::crypto::internal
{
class Parameters
{
public:
    virtual auto operator<(const Parameters& rhs) const noexcept -> bool = 0;
    virtual auto operator==(const Parameters& rhs) const noexcept -> bool = 0;

    virtual auto GetContactData(proto::ContactData& serialized) const noexcept
        -> bool = 0;
    virtual auto GetVerificationSet(
        proto::VerificationSet& serialized) const noexcept -> bool = 0;
    virtual auto Hash() const noexcept -> OTData = 0;

    virtual auto SetContactData(const proto::ContactData& contactData) noexcept
        -> void = 0;
    virtual auto SetVerificationSet(
        const proto::VerificationSet& verificationSet) noexcept -> void = 0;

    virtual ~Parameters() = default;
};
}  // namespace opentxs::crypto::internal