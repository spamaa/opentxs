// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

// IWYU pragma: no_include "opentxs/identity/wot/claim/ClaimType.hpp"
// IWYU pragma: no_include "opentxs/identity/wot/claim/SectionType.hpp"
// IWYU pragma: no_include "opentxs/core/UnitType.hpp"

#include "opentxs/Version.hpp"  // IWYU pragma: associated

#include <map>
#include <memory>
#include <set>
#include <string>
#include <tuple>
#include <utility>

#include "opentxs/Types.hpp"
#include "opentxs/core/Types.hpp"
#include "opentxs/core/identifier/Generic.hpp"
#include "opentxs/core/identifier/Notary.hpp"
#include "opentxs/identity/wot/claim/Types.hpp"
#include "opentxs/util/Bytes.hpp"
#include "opentxs/util/Numbers.hpp"

namespace opentxs
{
namespace api
{
class Session;
}  // namespace api

namespace identity
{
namespace wot
{
namespace claim
{
class Group;
class Item;
class Section;
}  // namespace claim
}  // namespace wot
}  // namespace identity

namespace proto
{
class ContactData;
}  // namespace proto
}  // namespace opentxs

namespace opentxs::identity::wot::claim
{
class OPENTXS_EXPORT Data
{
public:
    using SectionMap =
        std::map<claim::SectionType, std::shared_ptr<claim::Section>>;

    OPENTXS_NO_EXPORT static auto PrintContactData(
        const proto::ContactData& data) -> std::string;

    Data(
        const api::Session& api,
        const std::string& nym,
        const VersionNumber version,
        const VersionNumber targetVersion,
        const SectionMap& sections);
    OPENTXS_NO_EXPORT Data(
        const api::Session& api,
        const std::string& nym,
        const VersionNumber targetVersion,
        const proto::ContactData& serialized);
    Data(
        const api::Session& api,
        const std::string& nym,
        const VersionNumber targetVersion,
        const ReadView& serialized);
    Data(const Data&);

    auto operator+(const Data& rhs) const -> Data;

    operator std::string() const;

    auto AddContract(
        const std::string& instrumentDefinitionID,
        const core::UnitType currency,
        const bool primary,
        const bool active) const -> Data;
    auto AddEmail(
        const std::string& value,
        const bool primary,
        const bool active) const -> Data;
    auto AddItem(const Claim& claim) const -> Data;
    auto AddItem(const std::shared_ptr<Item>& item) const -> Data;
    auto AddPaymentCode(
        const std::string& code,
        const core::UnitType currency,
        const bool primary,
        const bool active) const -> Data;
    auto AddPhoneNumber(
        const std::string& value,
        const bool primary,
        const bool active) const -> Data;
    auto AddPreferredOTServer(const Identifier& id, const bool primary) const
        -> Data;
    auto AddSocialMediaProfile(
        const std::string& value,
        const claim::ClaimType type,
        const bool primary,
        const bool active) const -> Data;
    auto begin() const -> SectionMap::const_iterator;
    auto BestEmail() const -> std::string;
    auto BestPhoneNumber() const -> std::string;
    auto BestSocialMediaProfile(const claim::ClaimType type) const
        -> std::string;
    auto Claim(const Identifier& item) const -> std::shared_ptr<Item>;
    auto Contracts(const core::UnitType currency, const bool onlyActive) const
        -> std::set<OTIdentifier>;
    auto Delete(const Identifier& id) const -> Data;
    auto EmailAddresses(bool active = true) const -> std::string;
    auto end() const -> SectionMap::const_iterator;
    auto Group(const claim::SectionType section, const claim::ClaimType type)
        const -> std::shared_ptr<Group>;
    auto HaveClaim(const Identifier& item) const -> bool;
    auto HaveClaim(
        const claim::SectionType section,
        const claim::ClaimType type,
        const std::string& value) const -> bool;
    auto Name() const -> std::string;
    auto PhoneNumbers(bool active = true) const -> std::string;
    auto PreferredOTServer() const -> OTNotaryID;
    auto Section(const claim::SectionType section) const
        -> std::shared_ptr<Section>;
    auto Serialize(AllocateOutput destination, const bool withID = false) const
        -> bool;
    OPENTXS_NO_EXPORT auto Serialize(
        proto::ContactData& out,
        const bool withID = false) const -> bool;
    auto SetCommonName(const std::string& name) const -> Data;
    auto SetName(const std::string& name, const bool primary = true) const
        -> Data;
    auto SetScope(const claim::ClaimType type, const std::string& name) const
        -> Data;
    auto SocialMediaProfiles(const claim::ClaimType type, bool active = true)
        const -> std::string;
    auto SocialMediaProfileTypes() const -> const std::set<claim::ClaimType>;
    auto Type() const -> claim::ClaimType;
    auto Version() const -> VersionNumber;

    ~Data();

private:
    struct Imp;

    std::unique_ptr<Imp> imp_;

    Data() = delete;
    Data(Data&&) = delete;
    auto operator=(const Data&) -> Data& = delete;
    auto operator=(Data&&) -> Data& = delete;
};
}  // namespace opentxs::identity::wot::claim