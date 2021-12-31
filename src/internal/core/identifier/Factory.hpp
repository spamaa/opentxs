// Copyright (c) 2010-2021 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <memory>

namespace opentxs
{
namespace identifier
{
class Nym;
class Server;
class UnitDefinition;
}  // namespace identifier

namespace proto
{
class Identifier;
}  // namespace proto

class Identifier;
}  // namespace opentxs

namespace opentxs::factory
{
auto IdentifierGeneric() noexcept -> std::unique_ptr<opentxs::Identifier>;
auto IdentifierGeneric(const proto::Identifier& in) noexcept
    -> std::unique_ptr<opentxs::Identifier>;
auto IdentifierNym() noexcept -> std::unique_ptr<opentxs::identifier::Nym>;
auto IdentifierNym(const proto::Identifier& in) noexcept
    -> std::unique_ptr<opentxs::identifier::Nym>;
auto IdentifierNotary() noexcept
    -> std::unique_ptr<opentxs::identifier::Server>;
auto IdentifierNotary(const proto::Identifier& in) noexcept
    -> std::unique_ptr<opentxs::identifier::Server>;
auto IdentifierUnit() noexcept
    -> std::unique_ptr<opentxs::identifier::UnitDefinition>;
auto IdentifierUnit(const proto::Identifier& in) noexcept
    -> std::unique_ptr<opentxs::identifier::UnitDefinition>;
}  // namespace opentxs::factory