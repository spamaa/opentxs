// Copyright (c) 2010-2021 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef OPENTXS_BLIND_PURSE_HPP
#define OPENTXS_BLIND_PURSE_HPP

#include "opentxs/Version.hpp"  // IWYU pragma: associated

#include <chrono>
#include <cstdint>

#if OT_CASH
#include "opentxs/Bytes.hpp"
#include "opentxs/Pimpl.hpp"
#include "opentxs/blind/Types.hpp"
#include "opentxs/iterator/Bidirectional.hpp"

namespace opentxs
{
namespace api
{
namespace server
{
namespace internal
{
struct Manager;
}  // namespace internal
}  // namespace server
}  // namespace api

namespace blind
{
class Mint;
class Purse;
class Token;
}  // namespace blind

namespace crypto
{
namespace key
{
class Symmetric;
}  // namespace key
}  // namespace crypto

namespace identifier
{
class Server;
class UnitDefinition;
}  // namespace identifier

namespace proto
{
class Purse;
}  // namespace proto

class PasswordPrompt;

using OTPurse = Pimpl<blind::Purse>;
}  // namespace opentxs

namespace opentxs
{
namespace blind
{
class OPENTXS_EXPORT Purse
{
public:
    using Clock = std::chrono::system_clock;
    using Time = Clock::time_point;
    using iterator = opentxs::iterator::Bidirectional<Purse, Token>;
    using const_iterator =
        opentxs::iterator::Bidirectional<const Purse, const Token>;

    virtual const Token& at(const std::size_t position) const = 0;
    virtual const_iterator begin() const noexcept = 0;
    virtual const_iterator cbegin() const noexcept = 0;
    virtual const_iterator cend() const noexcept = 0;
    virtual Time EarliestValidTo() const = 0;
    virtual const_iterator end() const noexcept = 0;
    virtual bool IsUnlocked() const = 0;
    virtual Time LatestValidFrom() const = 0;
    virtual const identifier::Server& Notary() const = 0;
    OPENTXS_NO_EXPORT virtual bool Serialize(
        proto::Purse& out) const noexcept = 0;
    virtual auto Serialize(AllocateOutput destination) const noexcept
        -> bool = 0;
    virtual std::size_t size() const noexcept = 0;
    virtual blind::PurseType State() const = 0;
    virtual blind::CashType Type() const = 0;
    virtual const identifier::UnitDefinition& Unit() const = 0;
    virtual bool Unlock(const identity::Nym& nym, const PasswordPrompt& reason)
        const = 0;
    virtual bool Verify(const api::server::internal::Manager& server) const = 0;
    virtual Amount Value() const = 0;

    virtual bool AddNym(
        const identity::Nym& nym,
        const PasswordPrompt& reason) = 0;
    virtual Token& at(const std::size_t position) = 0;
    virtual iterator begin() noexcept = 0;
    virtual iterator end() noexcept = 0;
    virtual crypto::key::Symmetric& PrimaryKey(
        PasswordPrompt& password) noexcept(false) = 0;
    virtual std::shared_ptr<Token> Pop() = 0;
    virtual bool Process(
        const identity::Nym& owner,
        const Mint& mint,
        const PasswordPrompt& reason) = 0;
    virtual bool Push(
        std::shared_ptr<Token> token,
        const PasswordPrompt& reason) = 0;
    virtual const crypto::key::Symmetric& SecondaryKey(
        const identity::Nym& owner,
        PasswordPrompt& password) = 0;

    virtual ~Purse() = default;

protected:
    Purse() noexcept = default;

private:
    friend OTPurse;

    virtual Purse* clone() const noexcept = 0;

    Purse(const Purse&) = delete;
    Purse(Purse&&) = delete;
    Purse& operator=(const Purse&) = delete;
    Purse& operator=(Purse&&) = delete;
};
}  // namespace blind
}  // namespace opentxs
#endif  // OT_CASH
#endif
