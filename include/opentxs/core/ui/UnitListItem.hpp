// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include "opentxs/Version.hpp"  // IWYU pragma: associated

#include <string>

#include "ListRow.hpp"
#include "opentxs/util/SharedPimpl.hpp"

namespace opentxs
{
namespace ui
{
class UnitListItem;
}  // namespace ui

using OTUIUnitListItem = SharedPimpl<ui::UnitListItem>;
}  // namespace opentxs

namespace opentxs
{
namespace ui
{
class OPENTXS_EXPORT UnitListItem : virtual public ListRow
{
public:
    virtual auto Name() const noexcept -> std::string = 0;
    virtual auto Unit() const noexcept -> core::UnitType = 0;

    ~UnitListItem() override = default;

protected:
    UnitListItem() noexcept = default;

private:
    UnitListItem(const UnitListItem&) = delete;
    UnitListItem(UnitListItem&&) = delete;
    auto operator=(const UnitListItem&) -> UnitListItem& = delete;
    auto operator=(UnitListItem&&) -> UnitListItem& = delete;
};
}  // namespace ui
}  // namespace opentxs
