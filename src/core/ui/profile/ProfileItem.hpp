// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <memory>
#include <string>

#include "1_Internal.hpp"
#include "core/ui/base/Row.hpp"
#include "internal/core/ui/UI.hpp"
#include "opentxs/Types.hpp"
#include "opentxs/core/identifier/Generic.hpp"
#include "opentxs/core/ui/ProfileItem.hpp"
#include "opentxs/identity/wot/claim/Item.hpp"
#include "opentxs/util/Pimpl.hpp"
#include "opentxs/util/SharedPimpl.hpp"

namespace opentxs
{
namespace api
{
namespace session
{
class Client;
}  // namespace session
}  // namespace api

namespace network
{
namespace zeromq
{
namespace socket
{
class Publish;
}  // namespace socket
}  // namespace zeromq
}  // namespace network

namespace ui
{
class ProfileItem;
}  // namespace ui
}  // namespace opentxs

template class opentxs::SharedPimpl<opentxs::ui::ProfileItem>;

namespace opentxs::ui::implementation
{
using ProfileItemRow =
    Row<ProfileSubsectionRowInternal,
        ProfileSubsectionInternalInterface,
        ProfileSubsectionRowID>;

class ProfileItem final : public ProfileItemRow
{
public:
    auto ClaimID() const noexcept -> std::string final
    {
        sLock lock(shared_lock_);

        return row_id_->str();
    }
    auto Delete() const noexcept -> bool final;
    auto IsActive() const noexcept -> bool final
    {
        sLock lock(shared_lock_);

        return item_->isActive();
    }
    auto IsPrimary() const noexcept -> bool final
    {
        sLock lock(shared_lock_);

        return item_->isPrimary();
    }
    auto SetActive(const bool& active) const noexcept -> bool final;
    auto SetPrimary(const bool& primary) const noexcept -> bool final;
    auto SetValue(const std::string& value) const noexcept -> bool final;
    auto Value() const noexcept -> std::string final
    {
        sLock lock(shared_lock_);

        return item_->Value();
    }

    ProfileItem(
        const ProfileSubsectionInternalInterface& parent,
        const api::session::Client& api,
        const ProfileSubsectionRowID& rowID,
        const ProfileSubsectionSortKey& sortKey,
        CustomData& custom) noexcept;
    ~ProfileItem() final = default;

private:
    std::unique_ptr<identity::wot::claim::Item> item_;

    auto add_claim(const Claim& claim) const noexcept -> bool;
    auto as_claim() const noexcept -> Claim;

    auto reindex(
        const ProfileSubsectionSortKey& key,
        CustomData& custom) noexcept -> bool final;

    ProfileItem() = delete;
    ProfileItem(const ProfileItem&) = delete;
    ProfileItem(ProfileItem&&) = delete;
    auto operator=(const ProfileItem&) -> ProfileItem& = delete;
    auto operator=(ProfileItem&&) -> ProfileItem& = delete;
};
}  // namespace opentxs::ui::implementation
