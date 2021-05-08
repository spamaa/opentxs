// Copyright (c) 2010-2021 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef OPENTXS_API_CRYPTO_ASYMMETRIC_HPP
#define OPENTXS_API_CRYPTO_ASYMMETRIC_HPP

#include "opentxs/Version.hpp"  // IWYU pragma: associated

#include <memory>

#include "opentxs/Types.hpp"
#include "opentxs/crypto/Bip32.hpp"
#include "opentxs/crypto/Types.hpp"
#include "opentxs/crypto/key/Asymmetric.hpp"
#include "opentxs/crypto/key/EllipticCurve.hpp"
#include "opentxs/crypto/key/Secp256k1.hpp"

namespace opentxs
{
namespace proto
{
class AsymmetricKey;
}  // namespace proto

class Secret;
}  // namespace opentxs

namespace opentxs
{
namespace api
{
namespace crypto
{
class OPENTXS_EXPORT Asymmetric
{
public:
    using ECKey = std::unique_ptr<opentxs::crypto::key::EllipticCurve>;
    using Key = std::unique_ptr<opentxs::crypto::key::Asymmetric>;
    using HDKey = std::unique_ptr<opentxs::crypto::key::HD>;
    using Secp256k1Key = std::unique_ptr<opentxs::crypto::key::Secp256k1>;

    OPENTXS_NO_EXPORT virtual ECKey InstantiateECKey(
        const proto::AsymmetricKey& serialized) const = 0;
    OPENTXS_NO_EXPORT virtual HDKey InstantiateHDKey(
        const proto::AsymmetricKey& serialized) const = 0;
    virtual HDKey InstantiateKey(
        const opentxs::crypto::key::asymmetric::Algorithm type,
        const std::string& seedID,
        const opentxs::crypto::Bip32::Key& serialized,
        const PasswordPrompt& reason,
        const opentxs::crypto::key::asymmetric::Role role =
            opentxs::crypto::key::asymmetric::Role::Sign,
        const VersionNumber version =
            opentxs::crypto::key::EllipticCurve::DefaultVersion) const = 0;
    OPENTXS_NO_EXPORT virtual Key InstantiateKey(
        const proto::AsymmetricKey& serialized) const = 0;
    virtual HDKey NewHDKey(
        const std::string& seedID,
        const Secret& seed,
        const EcdsaCurve& curve,
        const opentxs::crypto::Bip32::Path& path,
        const PasswordPrompt& reason,
        const opentxs::crypto::key::asymmetric::Role role =
            opentxs::crypto::key::asymmetric::Role::Sign,
        const VersionNumber version =
            opentxs::crypto::key::EllipticCurve::DefaultVersion) const = 0;
    virtual Secp256k1Key InstantiateSecp256k1Key(
        const ReadView publicKey,
        const PasswordPrompt& reason,
        const opentxs::crypto::key::asymmetric::Role role =
            opentxs::crypto::key::asymmetric::Role::Sign,
        const VersionNumber version =
            opentxs::crypto::key::Secp256k1::DefaultVersion) const noexcept = 0;
    virtual Secp256k1Key InstantiateSecp256k1Key(
        const Secret& privateKey,
        const PasswordPrompt& reason,
        const opentxs::crypto::key::asymmetric::Role role =
            opentxs::crypto::key::asymmetric::Role::Sign,
        const VersionNumber version =
            opentxs::crypto::key::Secp256k1::DefaultVersion) const noexcept = 0;
    virtual Secp256k1Key NewSecp256k1Key(
        const std::string& seedID,
        const Secret& seed,
        const opentxs::crypto::Bip32::Path& path,
        const PasswordPrompt& reason,
        const opentxs::crypto::key::asymmetric::Role role =
            opentxs::crypto::key::asymmetric::Role::Sign,
        const VersionNumber version =
            opentxs::crypto::key::Secp256k1::DefaultVersion) const = 0;
    virtual Key NewKey(
        const NymParameters& params,
        const PasswordPrompt& reason,
        const opentxs::crypto::key::asymmetric::Role role =
            opentxs::crypto::key::asymmetric::Role::Sign,
        const VersionNumber version =
            opentxs::crypto::key::Asymmetric::DefaultVersion) const = 0;

    OPENTXS_NO_EXPORT virtual ~Asymmetric() = default;

protected:
    Asymmetric() = default;

private:
    Asymmetric(const Asymmetric&) = delete;
    Asymmetric(Asymmetric&&) = delete;
    Asymmetric& operator=(const Asymmetric&) = delete;
    Asymmetric& operator=(Asymmetric&&) = delete;
};
}  // namespace crypto
}  // namespace api
}  // namespace opentxs
#endif
