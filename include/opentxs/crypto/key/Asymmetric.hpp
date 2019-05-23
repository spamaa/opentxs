// Copyright (c) 2018 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef OPENTXS_CRYPTO_KEY_ASYMMETRIC_HPP
#define OPENTXS_CRYPTO_KEY_ASYMMETRIC_HPP

#include "opentxs/Forward.hpp"

#include "opentxs/core/Data.hpp"
#include "opentxs/core/Log.hpp"
#include "opentxs/core/String.hpp"
#include "opentxs/crypto/library/AsymmetricProvider.hpp"
#include "opentxs/Proto.hpp"

#include <cstdint>
#include <list>
#include <memory>
#include <string>

namespace opentxs
{
namespace crypto
{
namespace key
{
typedef std::list<Asymmetric*> listOfAsymmetricKeys;

class Asymmetric
{
public:
    EXPORT static const VersionNumber DefaultVersion;
    EXPORT static const VersionNumber MaxVersion;

    EXPORT static OTAsymmetricKey Factory();

    EXPORT virtual OTData CalculateHash(
        const proto::HashType hashType,
        const OTPasswordData& password) const = 0;
    /** Only works for public keys. */
    EXPORT virtual bool CalculateID(Identifier& theOutput) const = 0;
    EXPORT virtual const opentxs::crypto::AsymmetricProvider& engine()
        const = 0;
    EXPORT virtual const OTSignatureMetadata* GetMetadata() const = 0;
    EXPORT virtual bool hasCapability(
        const NymCapability& capability) const = 0;
    EXPORT virtual bool HasPrivate() const = 0;
    EXPORT virtual bool HasPublic() const = 0;
    EXPORT virtual proto::AsymmetricKeyType keyType() const = 0;
    EXPORT virtual bool Open(
        crypto::key::Asymmetric& dhPublic,
        crypto::key::Symmetric& sessionKey,
        OTPasswordData& password) const = 0;
    EXPORT virtual const std::string Path() const = 0;
    EXPORT virtual bool Path(proto::HDPath& output) const = 0;
    EXPORT virtual const proto::KeyRole& Role() const = 0;
    EXPORT virtual bool Seal(
        const opentxs::api::Core& api,
        OTAsymmetricKey& dhPublic,
        crypto::key::Symmetric& key,
        OTPasswordData& password) const = 0;
    EXPORT virtual std::shared_ptr<proto::AsymmetricKey> Serialize() const = 0;
    EXPORT virtual OTData SerializeKeyToData(
        const proto::AsymmetricKey& rhs) const = 0;
    EXPORT virtual proto::HashType SigHashType() const = 0;
    EXPORT virtual bool Sign(
        const Data& plaintext,
        proto::Signature& sig,
        const OTPasswordData* pPWData = nullptr,
        const OTPassword* exportPassword = nullptr,
        const String& credID = String::Factory(""),
        const proto::SignatureRole role = proto::SIGROLE_ERROR) const = 0;
    EXPORT virtual bool Sign(
        const GetPreimage input,
        const proto::SignatureRole role,
        proto::Signature& signature,
        const Identifier& credential,
        proto::KeyRole key = proto::KEYROLE_SIGN,
        const OTPasswordData* pPWData = nullptr,
        const proto::HashType hash = proto::HASHTYPE_BLAKE2B256) const = 0;
    EXPORT virtual bool TransportKey(Data& publicKey, OTPassword& privateKey)
        const = 0;
    EXPORT virtual bool Verify(
        const Data& plaintext,
        const proto::Signature& sig) const = 0;

    // Only used for RSA keys
    EXPORT [[deprecated]] virtual void Release() = 0;
    EXPORT [[deprecated]] virtual void ReleaseKey() = 0;
    /** Don't use this, normally it's not necessary. */
    EXPORT virtual void SetAsPublic() = 0;
    /** (Only if you really know what you are doing.) */
    EXPORT virtual void SetAsPrivate() = 0;

    EXPORT virtual operator bool() const = 0;
    EXPORT virtual bool operator==(const proto::AsymmetricKey&) const = 0;

    EXPORT virtual ~Asymmetric() = default;

protected:
    Asymmetric() = default;

private:
    friend OTAsymmetricKey;

    virtual Asymmetric* clone() const = 0;

    Asymmetric(const Asymmetric&) = delete;
    Asymmetric(Asymmetric&&) = delete;
    Asymmetric& operator=(const Asymmetric&) = delete;
    Asymmetric& operator=(Asymmetric&&) = delete;
};
}  // namespace key
}  // namespace crypto
}  // namespace opentxs
#endif
