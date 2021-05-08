// Copyright (c) 2010-2021 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef OPENTXS_IDENTITY_CREDENTIAL_KEY_HPP
#define OPENTXS_IDENTITY_CREDENTIAL_KEY_HPP

#include "opentxs/Version.hpp"  // IWYU pragma: associated

#include <memory>

#include "opentxs/Types.hpp"
#include "opentxs/core/crypto/NymParameters.hpp"
#include "opentxs/crypto/HashType.hpp"
#include "opentxs/crypto/Types.hpp"
#include "opentxs/crypto/key/Keypair.hpp"
#include "opentxs/identity/credential/Base.hpp"

namespace opentxs
{
namespace proto
{
class Signature;
}  // namespace proto
}  // namespace opentxs

namespace opentxs
{
namespace identity
{
namespace credential
{
class OPENTXS_EXPORT Key : virtual public Base
{
public:
    virtual const crypto::key::Keypair& GetKeypair(
        const crypto::key::asymmetric::Algorithm type,
        const opentxs::crypto::key::asymmetric::Role role) const = 0;
    virtual const crypto::key::Keypair& GetKeypair(
        const opentxs::crypto::key::asymmetric::Role role) const = 0;
    virtual std::int32_t GetPublicKeysBySignature(
        crypto::key::Keypair::Keys& listOutput,
        const opentxs::Signature& theSignature,
        char cKeyType = '0') const = 0;
    OPENTXS_NO_EXPORT virtual bool Sign(
        const GetPreimage input,
        const crypto::SignatureRole role,
        proto::Signature& signature,
        const PasswordPrompt& reason,
        opentxs::crypto::key::asymmetric::Role key =
            opentxs::crypto::key::asymmetric::Role::Sign,
        const crypto::HashType hash = crypto::HashType::Error) const = 0;

    ~Key() override = default;

protected:
    Key() noexcept {}  // TODO Signable

private:
    Key(const Key&) = delete;
    Key(Key&&) = delete;
    Key& operator=(const Key&) = delete;
    Key& operator=(Key&&) = delete;
};
}  // namespace credential
}  // namespace identity
}  // namespace opentxs
#endif
