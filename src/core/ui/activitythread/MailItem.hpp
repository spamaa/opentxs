// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <memory>
#include <thread>

#include "1_Internal.hpp"
#include "core/ui/activitythread/ActivityThreadItem.hpp"
#include "internal/core/ui/UI.hpp"

namespace opentxs
{
namespace api
{
namespace session
{
class Client;
}  // namespace session
}  // namespace api

namespace identifier
{
class Nym;
}  // namespace identifier

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
}  // namespace opentxs

namespace opentxs::ui::implementation
{
class MailItem final : public ActivityThreadItem
{
public:
    MailItem(
        const ActivityThreadInternalInterface& parent,
        const api::session::Client& api,
        const identifier::Nym& nymID,
        const ActivityThreadRowID& rowID,
        const ActivityThreadSortKey& sortKey,
        CustomData& custom) noexcept;

    ~MailItem() final;

private:
    MailItem() = delete;
    MailItem(const MailItem&) = delete;
    MailItem(MailItem&&) = delete;
    auto operator=(const MailItem&) -> MailItem& = delete;
    auto operator=(MailItem&&) -> MailItem& = delete;
};
}  // namespace opentxs::ui::implementation
