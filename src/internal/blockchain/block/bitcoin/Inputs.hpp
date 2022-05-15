// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <cstddef>
#include <memory>
#include <optional>

#include "opentxs/blockchain/bitcoin/cfilter/Types.hpp"
#include "opentxs/blockchain/block/bitcoin/Inputs.hpp"
#include "opentxs/core/identifier/Generic.hpp"
#include "opentxs/core/identifier/Nym.hpp"
#include "opentxs/util/Bytes.hpp"
#include "opentxs/util/Container.hpp"

// NOLINTBEGIN(modernize-concat-nested-namespaces)
namespace opentxs  // NOLINT
{
// inline namespace v1
// {
namespace blockchain
{
namespace block
{
namespace bitcoin
{
namespace internal
{
class Output;
}  // namespace internal
}  // namespace bitcoin
}  // namespace block
}  // namespace blockchain

namespace proto
{
class BlockchainTransaction;
}  // namespace proto

class Amount;
class Log;
// }  // namespace v1
}  // namespace opentxs
// NOLINTEND(modernize-concat-nested-namespaces)

namespace opentxs::blockchain::block::bitcoin::internal
{
class Inputs : virtual public bitcoin::Inputs
{
public:
    virtual auto AssociatedLocalNyms(
        UnallocatedVector<OTNymID>& output) const noexcept -> void = 0;
    virtual auto AssociatedRemoteContacts(
        UnallocatedVector<OTIdentifier>& output) const noexcept -> void = 0;
    virtual auto CalculateSize(const bool normalized = false) const noexcept
        -> std::size_t = 0;
    virtual auto clone() const noexcept -> std::unique_ptr<Inputs> = 0;
    virtual auto ExtractElements(const cfilter::Type style) const noexcept
        -> Vector<Vector<std::byte>> = 0;
    virtual auto FindMatches(
        const Txid& txid,
        const cfilter::Type type,
        const Patterns& txos,
        const ParsedPatterns& elements,
        const Log& log) const noexcept -> Matches = 0;
    virtual auto GetPatterns() const noexcept
        -> UnallocatedVector<PatternID> = 0;
    virtual auto NetBalanceChange(const identifier::Nym& nym, const Log& log)
        const noexcept -> opentxs::Amount = 0;
    virtual auto Serialize(
        proto::BlockchainTransaction& destination) const noexcept -> bool = 0;
    virtual auto Serialize(const AllocateOutput destination) const noexcept
        -> std::optional<std::size_t> = 0;
    virtual auto SerializeNormalized(const AllocateOutput destination)
        const noexcept -> std::optional<std::size_t> = 0;

    virtual auto AnyoneCanPay(const std::size_t index) noexcept -> bool = 0;
    virtual auto AssociatePreviousOutput(
        const std::size_t inputIndex,
        const Output& output) noexcept -> bool = 0;
    using bitcoin::Inputs::at;
    virtual auto at(const std::size_t position) noexcept(false)
        -> value_type& = 0;
    virtual auto MergeMetadata(const Inputs& rhs, const Log& log) noexcept
        -> bool = 0;
    virtual auto ReplaceScript(const std::size_t index) noexcept -> bool = 0;
    virtual auto SetKeyData(const KeyData& data) noexcept -> void = 0;

    ~Inputs() override = default;
};
}  // namespace opentxs::blockchain::block::bitcoin::internal
