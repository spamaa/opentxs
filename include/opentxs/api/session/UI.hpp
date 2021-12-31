// Copyright (c) 2010-2021 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

// IWYU pragma: no_include "opentxs/blockchain/BlockchainType.hpp"
// IWYU pragma: no_include "opentxs/contact/ClaimType.hpp"
// IWYU pragma: no_include "opentxs/core/UnitType.hpp"
// IWYU pragma: no_include "opentxs/ui/Blockchains.hpp"

#include "opentxs/Version.hpp"  // IWYU pragma: associated

#include <cstddef>
#include <iosfwd>

#include "opentxs/Types.hpp"
#include "opentxs/blockchain/Types.hpp"
#include "opentxs/core/Types.hpp"
#include "opentxs/crypto/Types.hpp"
#include "opentxs/ui/Types.hpp"

class QAbstractItemModel;

namespace opentxs
{
namespace api
{
namespace session
{
namespace internal
{
class UI;
}  // namespace internal
}  // namespace session
}  // namespace api

namespace identifier
{
class Nym;
class Server;
class UnitDefinition;
}  // namespace identifier

namespace ui
{
class AccountActivity;
class AccountActivityQt;
class AccountList;
class AccountListQt;
class AccountSummary;
class AccountSummaryQt;
class ActivitySummary;
class ActivitySummaryQt;
class ActivityThread;
class ActivityThreadQt;
class BlockchainAccountStatus;
class BlockchainAccountStatusQt;
class BlockchainSelection;
class BlockchainSelectionQt;
class BlockchainStatistics;
class BlockchainStatisticsQt;
class Contact;
class ContactList;
class ContactListQt;
class ContactQt;
class MessagableList;
class MessagableListQt;
class PayableList;
class PayableListQt;
class Profile;
class ProfileQt;
class SeedValidator;
class UnitList;
class UnitListQt;
}  // namespace ui

class Identifier;
}  // namespace opentxs

namespace opentxs::api::session
{
class OPENTXS_EXPORT UI
{
public:
    virtual auto AccountActivity(
        const identifier::Nym& nymID,
        const Identifier& accountID,
        const SimpleCallback updateCB = {}) const noexcept
        -> const opentxs::ui::AccountActivity& = 0;
    /// Caller does not own this pointer
    virtual auto AccountActivityQt(
        const identifier::Nym& nymID,
        const Identifier& accountID,
        const SimpleCallback updateCB = {}) const noexcept
        -> opentxs::ui::AccountActivityQt* = 0;
    virtual auto AccountList(
        const identifier::Nym& nym,
        const SimpleCallback updateCB = {}) const noexcept
        -> const opentxs::ui::AccountList& = 0;
    /// Caller does not own this pointer
    virtual auto AccountListQt(
        const identifier::Nym& nym,
        const SimpleCallback updateCB = {}) const noexcept
        -> opentxs::ui::AccountListQt* = 0;
    virtual auto AccountSummary(
        const identifier::Nym& nymID,
        const core::UnitType currency,
        const SimpleCallback updateCB = {}) const noexcept
        -> const opentxs::ui::AccountSummary& = 0;
    /// Caller does not own this pointer
    virtual auto AccountSummaryQt(
        const identifier::Nym& nymID,
        const core::UnitType currency,
        const SimpleCallback updateCB = {}) const noexcept
        -> opentxs::ui::AccountSummaryQt* = 0;
    virtual auto ActivitySummary(
        const identifier::Nym& nymID,
        const SimpleCallback updateCB = {}) const noexcept
        -> const opentxs::ui::ActivitySummary& = 0;
    /// Caller does not own this pointer
    virtual auto ActivitySummaryQt(
        const identifier::Nym& nymID,
        const SimpleCallback updateCB = {}) const noexcept
        -> opentxs::ui::ActivitySummaryQt* = 0;
    virtual auto ActivityThread(
        const identifier::Nym& nymID,
        const Identifier& threadID,
        const SimpleCallback updateCB = {}) const noexcept
        -> const opentxs::ui::ActivityThread& = 0;
    /// Caller does not own this pointer
    virtual auto ActivityThreadQt(
        const identifier::Nym& nymID,
        const Identifier& threadID,
        const SimpleCallback updateCB = {}) const noexcept
        -> opentxs::ui::ActivityThreadQt* = 0;
    /// Caller does not own this pointer
    virtual auto BlankModel(const std::size_t columns) const noexcept
        -> QAbstractItemModel* = 0;
    virtual auto BlockchainAccountStatus(
        const identifier::Nym& nymID,
        const opentxs::blockchain::Type chain,
        const SimpleCallback updateCB = {}) const noexcept
        -> const opentxs::ui::BlockchainAccountStatus& = 0;
    /// Caller does not own this pointer
    virtual auto BlockchainAccountStatusQt(
        const identifier::Nym& nymID,
        const opentxs::blockchain::Type chain,
        const SimpleCallback updateCB = {}) const noexcept
        -> opentxs::ui::BlockchainAccountStatusQt* = 0;
    virtual auto BlockchainIssuerID(const opentxs::blockchain::Type chain)
        const noexcept -> const identifier::Nym& = 0;
    virtual auto BlockchainNotaryID(const opentxs::blockchain::Type chain)
        const noexcept -> const identifier::Server& = 0;
    virtual auto BlockchainSelection(
        const opentxs::ui::Blockchains type,
        const SimpleCallback updateCB = {}) const noexcept
        -> const opentxs::ui::BlockchainSelection& = 0;
    /// Caller does not own this pointer
    virtual auto BlockchainSelectionQt(
        const opentxs::ui::Blockchains type,
        const SimpleCallback updateCB = {}) const noexcept
        -> opentxs::ui::BlockchainSelectionQt* = 0;
    virtual auto BlockchainStatistics(const SimpleCallback updateCB = {})
        const noexcept -> const opentxs::ui::BlockchainStatistics& = 0;
    virtual auto BlockchainStatisticsQt(const SimpleCallback updateCB = {})
        const noexcept -> opentxs::ui::BlockchainStatisticsQt* = 0;
    virtual auto BlockchainUnitID(const opentxs::blockchain::Type chain)
        const noexcept -> const identifier::UnitDefinition& = 0;
    virtual auto Contact(
        const Identifier& contactID,
        const SimpleCallback updateCB = {}) const noexcept
        -> const opentxs::ui::Contact& = 0;
    virtual auto ContactQt(
        const Identifier& contactID,
        const SimpleCallback updateCB = {}) const noexcept
        -> opentxs::ui::ContactQt* = 0;
    virtual auto ContactList(
        const identifier::Nym& nymID,
        const SimpleCallback updateCB = {}) const noexcept
        -> const opentxs::ui::ContactList& = 0;
    /// Caller does not own this pointer
    virtual auto ContactListQt(
        const identifier::Nym& nymID,
        const SimpleCallback updateCB = {}) const noexcept
        -> opentxs::ui::ContactListQt* = 0;
    OPENTXS_NO_EXPORT virtual auto Internal() const noexcept
        -> const internal::UI& = 0;
    virtual auto MessagableList(
        const identifier::Nym& nymID,
        const SimpleCallback updateCB = {}) const noexcept
        -> const opentxs::ui::MessagableList& = 0;
    /// Caller does not own this pointer
    virtual auto MessagableListQt(
        const identifier::Nym& nymID,
        const SimpleCallback updateCB = {}) const noexcept
        -> opentxs::ui::MessagableListQt* = 0;
    virtual auto PayableList(
        const identifier::Nym& nymID,
        const core::UnitType currency,
        const SimpleCallback updateCB = {}) const noexcept
        -> const opentxs::ui::PayableList& = 0;
    /// Caller does not own this pointer
    virtual auto PayableListQt(
        const identifier::Nym& nymID,
        const core::UnitType currency,
        const SimpleCallback updateCB = {}) const noexcept
        -> opentxs::ui::PayableListQt* = 0;
    virtual auto Profile(
        const identifier::Nym& nymID,
        const SimpleCallback updateCB = {}) const noexcept
        -> const opentxs::ui::Profile& = 0;
    /// Caller does not own this pointer
    virtual auto ProfileQt(
        const identifier::Nym& nymID,
        const SimpleCallback updateCB = {}) const noexcept
        -> opentxs::ui::ProfileQt* = 0;
    /// Caller does not own this pointer
    virtual auto SeedValidator(
        const opentxs::crypto::SeedStyle type,
        const opentxs::crypto::Language lang) const noexcept
        -> const opentxs::ui::SeedValidator* = 0;
    virtual auto UnitList(
        const identifier::Nym& nym,
        const SimpleCallback updateCB = {}) const noexcept
        -> const opentxs::ui::UnitList& = 0;
    /// Caller does not own this pointer
    virtual auto UnitListQt(
        const identifier::Nym& nym,
        const SimpleCallback updateCB = {}) const noexcept
        -> opentxs::ui::UnitListQt* = 0;

    OPENTXS_NO_EXPORT virtual auto Internal() noexcept -> internal::UI& = 0;

    OPENTXS_NO_EXPORT virtual ~UI() = default;

protected:
    UI() = default;

private:
    UI(const UI&) = delete;
    UI(UI&&) = delete;
    auto operator=(const UI&) -> UI& = delete;
    auto operator=(UI&&) -> UI& = delete;
};
}  // namespace opentxs::api::session