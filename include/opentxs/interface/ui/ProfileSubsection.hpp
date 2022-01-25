// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include "opentxs/Version.hpp"  // IWYU pragma: associated

#include "opentxs/interface/ui/List.hpp"
#include "opentxs/interface/ui/ListRow.hpp"
#include "opentxs/util/Container.hpp"
#include "opentxs/util/SharedPimpl.hpp"

namespace opentxs
{
namespace ui
{
class ProfileSubsection;
}  // namespace ui

using OTUIProfileSubsection = SharedPimpl<ui::ProfileSubsection>;
}  // namespace opentxs

namespace opentxs::ui
{
class OPENTXS_EXPORT ProfileSubsection : virtual public List,
                                         virtual public ListRow
{
public:
    virtual auto AddItem(
        const UnallocatedCString& value,
        const bool primary,
        const bool active) const noexcept -> bool = 0;
    virtual auto Delete(const UnallocatedCString& claimID) const noexcept
        -> bool = 0;
    virtual auto First() const noexcept
        -> opentxs::SharedPimpl<opentxs::ui::ProfileItem> = 0;
    virtual auto Name(const UnallocatedCString& lang) const noexcept
        -> UnallocatedCString = 0;
    virtual auto Next() const noexcept
        -> opentxs::SharedPimpl<opentxs::ui::ProfileItem> = 0;
    virtual auto SetActive(const UnallocatedCString& claimID, const bool active)
        const noexcept -> bool = 0;
    virtual auto SetPrimary(
        const UnallocatedCString& claimID,
        const bool primary) const noexcept -> bool = 0;
    virtual auto SetValue(
        const UnallocatedCString& claimID,
        const UnallocatedCString& value) const noexcept -> bool = 0;
    virtual auto Type() const noexcept -> identity::wot::claim::ClaimType = 0;

    ~ProfileSubsection() override = default;

protected:
    ProfileSubsection() noexcept = default;

private:
    ProfileSubsection(const ProfileSubsection&) = delete;
    ProfileSubsection(ProfileSubsection&&) = delete;
    auto operator=(const ProfileSubsection&) -> ProfileSubsection& = delete;
    auto operator=(ProfileSubsection&&) -> ProfileSubsection& = delete;
};
}  // namespace opentxs::ui