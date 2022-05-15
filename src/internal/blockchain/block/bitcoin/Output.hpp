// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// IWYU pragma: no_include "opentxs/blockchain/node/TxoState.hpp"
// IWYU pragma: no_include "opentxs/blockchain/node/TxoTag.hpp"

#pragma once

#include <cstddef>
#include <memory>
#include <optional>

#include "internal/blockchain/block/Block.hpp"
#include "opentxs/blockchain/bitcoin/cfilter/Types.hpp"
#include "opentxs/blockchain/block/Position.hpp"
#include "opentxs/blockchain/block/bitcoin/Output.hpp"
#include "opentxs/blockchain/crypto/Types.hpp"
#include "opentxs/blockchain/node/Types.hpp"
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
class Script;
}  // namespace internal
}  // namespace bitcoin
}  // namespace block
}  // namespace blockchain

namespace proto
{
class BlockchainTransactionOutput;
}  // namespace proto

class Amount;
class Identifier;
class Log;
// }  // namespace v1
}  // namespace opentxs
// NOLINTEND(modernize-concat-nested-namespaces)

namespace opentxs::blockchain::block::bitcoin::internal
{
class Output : virtual public bitcoin::Output
{
public:
    using SerializeType = proto::BlockchainTransactionOutput;

    virtual auto AssociatedLocalNyms(
        UnallocatedVector<OTNymID>& output) const noexcept -> void = 0;
    virtual auto AssociatedRemoteContacts(
        UnallocatedVector<OTIdentifier>& output) const noexcept -> void = 0;
    virtual auto CalculateSize() const noexcept -> std::size_t = 0;
    virtual auto clone() const noexcept -> std::unique_ptr<Output> = 0;
    virtual auto ExtractElements(const cfilter::Type style) const noexcept
        -> Vector<Vector<std::byte>> = 0;
    virtual auto FindMatches(
        const Txid& txid,
        const cfilter::Type type,
        const ParsedPatterns& elements,
        const Log& log) const noexcept -> Matches = 0;
    virtual auto GetPatterns() const noexcept
        -> UnallocatedVector<PatternID> = 0;
    // WARNING do not call this function if another thread has a non-const
    // reference to this object
    virtual auto MinedPosition() const noexcept -> const block::Position& = 0;
    virtual auto NetBalanceChange(const identifier::Nym& nym, const Log& log)
        const noexcept -> opentxs::Amount = 0;
    virtual auto Serialize(const AllocateOutput destination) const noexcept
        -> std::optional<std::size_t> = 0;
    virtual auto Serialize(SerializeType& destination) const noexcept
        -> bool = 0;
    virtual auto SigningSubscript() const noexcept
        -> std::unique_ptr<internal::Script> = 0;
    virtual auto State() const noexcept -> node::TxoState = 0;
    virtual auto Tags() const noexcept
        -> const UnallocatedSet<node::TxoTag> = 0;

    virtual auto AddTag(node::TxoTag tag) noexcept -> void = 0;
    virtual auto ForTestingOnlyAddKey(const crypto::Key& key) noexcept
        -> void = 0;
    virtual auto MergeMetadata(const Output& rhs, const Log& log) noexcept
        -> bool = 0;
    virtual auto SetIndex(const std::uint32_t index) noexcept -> void = 0;
    virtual auto SetKeyData(const KeyData& data) noexcept -> void = 0;
    virtual auto SetMinedPosition(const block::Position& pos) noexcept
        -> void = 0;
    virtual auto SetPayee(const Identifier& contact) noexcept -> void = 0;
    virtual auto SetPayer(const Identifier& contact) noexcept -> void = 0;
    virtual auto SetState(node::TxoState state) noexcept -> void = 0;
    virtual auto SetValue(const blockchain::Amount& value) noexcept -> void = 0;

    ~Output() override = default;
};
}  // namespace opentxs::blockchain::block::bitcoin::internal
