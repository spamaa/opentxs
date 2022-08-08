// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "0_stdafx.hpp"    // IWYU pragma: associated
#include "1_Internal.hpp"  // IWYU pragma: associated
#include "blockchain/node/filteroracle/FilterOracle.hpp"  // IWYU pragma: associated

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <future>
#include <iterator>
#include <stdexcept>
#include <tuple>
#include <type_traits>
#include <utility>

#include "blockchain/node/filteroracle/FilterCheckpoints.hpp"
#include "blockchain/node/filteroracle/FilterDownloader.hpp"
#include "blockchain/node/filteroracle/HeaderDownloader.hpp"
#include "internal/api/network/Blockchain.hpp"
#include "internal/blockchain/Blockchain.hpp"
#include "internal/blockchain/block/Block.hpp"
#include "internal/blockchain/database/Cfilter.hpp"
#include "internal/blockchain/node/Config.hpp"
#include "internal/blockchain/node/Endpoints.hpp"
#include "internal/blockchain/node/Factory.hpp"
#include "internal/blockchain/node/Types.hpp"
#include "internal/blockchain/node/filteroracle/BlockIndexer.hpp"
#include "internal/util/LogMacros.hpp"
#include "internal/util/P0330.hpp"
#include "opentxs/api/network/Blockchain.hpp"
#include "opentxs/api/network/Network.hpp"
#include "opentxs/api/session/Factory.hpp"
#include "opentxs/api/session/Session.hpp"
#include "opentxs/blockchain/Types.hpp"
#include "opentxs/blockchain/bitcoin/block/Block.hpp"
#include "opentxs/blockchain/bitcoin/cfilter/FilterType.hpp"
#include "opentxs/blockchain/bitcoin/cfilter/GCS.hpp"
#include "opentxs/blockchain/bitcoin/cfilter/Hash.hpp"
#include "opentxs/blockchain/bitcoin/cfilter/Header.hpp"
#include "opentxs/blockchain/block/Header.hpp"
#include "opentxs/blockchain/node/HeaderOracle.hpp"
#include "opentxs/core/ByteArray.hpp"
#include "opentxs/core/FixedByteArray.hpp"
#include "opentxs/network/p2p/Block.hpp"
#include "opentxs/network/p2p/Data.hpp"
#include "opentxs/network/p2p/Types.hpp"
#include "opentxs/network/zeromq/Context.hpp"
#include "opentxs/network/zeromq/message/Message.hpp"
#include "opentxs/util/BlockchainProfile.hpp"
#include "opentxs/util/Bytes.hpp"
#include "opentxs/util/Container.hpp"
#include "opentxs/util/Log.hpp"
#include "opentxs/util/Pimpl.hpp"

namespace opentxs::factory
{
auto BlockchainFilterOracle(
    const api::Session& api,
    const blockchain::node::internal::Config& config,
    const blockchain::node::Manager& node,
    const blockchain::node::HeaderOracle& header,
    const blockchain::node::BlockOracle& block,
    blockchain::database::Cfilter& database,
    const blockchain::Type chain,
    const blockchain::cfilter::Type filter,
    const blockchain::node::Endpoints& endpoints) noexcept
    -> std::unique_ptr<blockchain::node::FilterOracle>
{
    using ReturnType = opentxs::blockchain::node::implementation::FilterOracle;

    return std::make_unique<ReturnType>(
        api, config, node, header, block, database, chain, filter, endpoints);
}
}  // namespace opentxs::factory

namespace opentxs::blockchain::node::implementation
{
struct FilterOracle::SyncClientFilterData {
    using Future = std::future<cfilter::Header>;
    using Promise = std::promise<cfilter::Header>;

    const block::Hash& block_hash_;
    const network::p2p::Block& incoming_data_;
    cfilter::Hash filter_hash_;
    database::Cfilter::CFilterParams& filter_data_;
    database::Cfilter::CFHeaderParams& header_data_;
    Outstanding& job_counter_;
    Future previous_header_;
    Promise calculated_header_;

    SyncClientFilterData(
        const block::Hash& block,
        const network::p2p::Block& data,
        database::Cfilter::CFilterParams& filter,
        database::Cfilter::CFHeaderParams& header,
        Outstanding& jobCounter,
        Future&& previous) noexcept
        : block_hash_(block)
        , incoming_data_(data)
        , filter_hash_()
        , filter_data_(filter)
        , header_data_(header)
        , job_counter_(jobCounter)
        , previous_header_(std::move(previous))
        , calculated_header_()
    {
    }
};

FilterOracle::FilterOracle(
    const api::Session& api,
    const internal::Config& config,
    const node::Manager& node,
    const HeaderOracle& header,
    const node::BlockOracle& block,
    database::Cfilter& database,
    const blockchain::Type chain,
    const blockchain::cfilter::Type filter,
    const node::Endpoints& endpoints) noexcept
    : internal::FilterOracle()
    , api_(api)
    , node_(node)
    , header_(header)
    , database_(database)
    , filter_notifier_(api_.Network().Blockchain().Internal().FilterUpdate())
    , chain_(chain)
    , default_type_(filter)
    , lock_()
    , new_filters_([&] {
        auto socket = api_.Network().ZeroMQ().PublishSocket();
        auto started = socket->Start(endpoints.new_filter_publish_);

        OT_ASSERT(started);

        return socket;
    }())
    , reindex_blocks_([&] {
        auto socket = api_.Network().ZeroMQ().PublishSocket();
        auto started = socket->Start(endpoints.filter_oracle_reindex_publish_);

        OT_ASSERT(started);

        return socket;
    }())
    , cb_([this](const auto type, const auto& pos) { update_tip(type, pos); })
    , filter_downloader_([&]() -> std::unique_ptr<FilterDownloader> {
        switch (config.profile_) {
            case BlockchainProfile::desktop_native: {

                return std::make_unique<FilterDownloader>(
                    api,
                    database_,
                    header_,
                    node_,
                    chain,
                    default_type_,
                    endpoints,
                    cb_);
            }
            case BlockchainProfile::mobile:
            case BlockchainProfile::desktop:
            case BlockchainProfile::server: {

                return {};
            }
            default: {
                OT_FAIL;
            }
        }
    }())
    , header_downloader_([&]() -> std::unique_ptr<HeaderDownloader> {
        switch (config.profile_) {
            case BlockchainProfile::desktop_native: {

                return std::make_unique<HeaderDownloader>(
                    api,
                    database_,
                    header_,
                    node_,
                    *filter_downloader_,
                    chain,
                    default_type_,
                    endpoints,
                    [&](const auto& position, const auto& header) {
                        return compare_header_to_checkpoint(position, header);
                    });
            }
            case BlockchainProfile::mobile:
            case BlockchainProfile::desktop:
            case BlockchainProfile::server: {

                return {};
            }
            default: {
                OT_FAIL;
            }
        }
    }())
    , block_indexer_()
    , have_block_indexer_([&] {
        switch (config.profile_) {
            case BlockchainProfile::server: {
                block_indexer_ = std::make_unique<filteroracle::BlockIndexer>(
                    api,
                    node_,
                    *this,
                    database_,
                    filteroracle::NotifyCallback{cb_},
                    chain,
                    default_type_,
                    endpoints);
            } break;
            case BlockchainProfile::mobile:
            case BlockchainProfile::desktop:
            case BlockchainProfile::desktop_native: {
            } break;
            default: {
                OT_FAIL;
            }
        }

        return block_indexer_.operator bool();
    }())
    , last_sync_progress_()
    , last_broadcast_()
    , outstanding_jobs_()
    , running_(true)
{
    OT_ASSERT(cb_);

    compare_tips_to_header_chain();
    compare_tips_to_checkpoint();
}

auto FilterOracle::compare_header_to_checkpoint(
    const block::Position& block,
    const cfilter::Header& receivedHeader) noexcept -> block::Position
{
    const auto& cp = filter_checkpoints_.at(chain_);
    const auto height = block.height_;

    if (auto it = cp.find(height); cp.end() != it) {
        const auto& bytes = it->second.at(default_type_);
        const auto expectedHeader =
            api_.Factory().DataFromBytes(ReadView{bytes.data(), bytes.size()});

        if (expectedHeader == receivedHeader) {
            LogConsole()(print(chain_))(" filter header at height ")(
                height)(" verified against checkpoint")
                .Flush();

            return block;
        } else {
            OT_ASSERT(cp.begin() != it);

            std::advance(it, -1);
            const auto rollback =
                block::Position{it->first, header_.BestHash(it->first)};
            LogConsole()(print(chain_))(" filter header at height ")(
                height)(" does not match checkpoint. Resetting to previous "
                        "checkpoint at height ")(rollback.height_)
                .Flush();

            return rollback;
        }
    }

    return block;
}

auto FilterOracle::compare_tips_to_checkpoint() noexcept -> void
{
    const auto& cp = filter_checkpoints_.at(chain_);
    const auto headerTip = database_.FilterHeaderTip(default_type_);
    auto checkPosition{headerTip};
    auto changed{false};

    for (auto i{cp.crbegin()}; i != cp.crend(); ++i) {
        const auto& cpHeight = i->first;

        if (cpHeight > checkPosition.height_) { continue; }

        checkPosition = block::Position{cpHeight, header_.BestHash(cpHeight)};
        const auto existingHeader = database_.LoadFilterHeader(
            default_type_, checkPosition.hash_.Bytes());

        try {
            const auto& cpHeader = i->second.at(default_type_);
            const auto cpBytes = api_.Factory().DataFromHex(cpHeader);

            if (existingHeader == cpBytes) { break; }

            changed = true;
        } catch (...) {
            break;
        }
    }

    if (changed) {
        LogConsole()(print(chain_))(
            " filter header chain did not match checkpoint. Resetting to last "
            "known good position")
            .Flush();
        reset_tips_to(default_type_, headerTip, checkPosition, changed);
    } else {
        LogVerbose()(print(chain_))(" filter header chain matched checkpoint")
            .Flush();
    }
}

auto FilterOracle::compare_tips_to_header_chain() noexcept -> bool
{
    const auto current = database_.FilterHeaderTip(default_type_);
    const auto [parent, best] = header_.CommonParent(current);

    if (parent == current) {
        LogVerbose()(print(chain_))(
            " filter header chain is following the best chain")
            .Flush();

        return false;
    }

    LogConsole()(print(chain_))(
        " filter header chain is following a sibling chain. Resetting to "
        "common ancestor at height ")(parent.height_)
        .Flush();
    reset_tips_to(default_type_, current, parent);

    return true;
}

auto FilterOracle::FilterTip(const cfilter::Type type) const noexcept
    -> block::Position
{
    return database_.FilterTip(type);
}

auto FilterOracle::GetFilterJob() const noexcept -> CfilterJob
{
    auto lock = rLock{lock_};

    if (filter_downloader_) {

        return filter_downloader_->NextBatch();
    } else {

        return {};
    }
}

auto FilterOracle::GetHeaderJob() const noexcept -> CfheaderJob
{
    auto lock = rLock{lock_};

    if (header_downloader_) {

        return header_downloader_->NextBatch();
    } else {

        return {};
    }
}

auto FilterOracle::Heartbeat() const noexcept -> void
{
    auto lock = rLock{lock_};

    if (filter_downloader_) { filter_downloader_->Heartbeat(); }
    if (header_downloader_) { header_downloader_->Heartbeat(); }

    constexpr auto limit = 5s;

    if ((Clock::now() - last_sync_progress_) > limit) {
        new_tip(lock, default_type_, database_.FilterTip(default_type_));
    }
}

auto FilterOracle::LoadFilter(
    const cfilter::Type type,
    const block::Hash& block,
    alloc::Default alloc) const noexcept -> GCS
{
    return database_.LoadFilter(type, block.Bytes(), alloc);
}

auto FilterOracle::LoadFilters(
    const cfilter::Type type,
    const Vector<block::Hash>& blocks) const noexcept -> Vector<GCS>
{
    return database_.LoadFilters(type, blocks);
}

auto FilterOracle::LoadFilterHeader(
    const cfilter::Type type,
    const block::Hash& block) const noexcept -> cfilter::Header
{
    return database_.LoadFilterHeader(type, block.Bytes());
}

auto FilterOracle::LoadFilterOrResetTip(
    const cfilter::Type type,
    const block::Position& position,
    alloc::Default alloc) const noexcept -> GCS
{
    auto output = LoadFilter(type, position.hash_, alloc);

    if (output.IsValid()) { return output; }

    const auto& height = position.height_;

    OT_ASSERT(0 < height);

    const auto parent = height - 1;
    const auto hash = header_.BestHash(parent);

    OT_ASSERT(false == hash.IsNull());

    reset_tips_to(type, block::Position{parent, hash}, false, true);

    return {};
}

auto FilterOracle::new_tip(
    const rLock&,
    const cfilter::Type type,
    const block::Position& tip) const noexcept -> void
{
    {
        auto& last = [&]() -> auto&
        {
            auto& map = last_broadcast_;

            if (auto it = map.find(type); map.end() == it) {

                return map
                    .try_emplace(type, 0, header_.GenesisBlockHash(chain_))
                    .first->second;
            } else {

                return it->second;
            }
        }
        ();

        if (tip == last) {

            return;
        } else {
            last = tip;
        }
    }

    LogTrace()(OT_PRETTY_CLASS())(print(chain_))(
        ": notifying peers of new filter tip ")(tip)
        .Flush();
    last_sync_progress_ = Clock::now();
    new_filters_->Send([&] {
        auto work = MakeWork(OT_ZMQ_NEW_FILTER_SIGNAL);
        work.AddFrame(type);
        work.AddFrame(tip.height_);
        work.AddFrame(tip.hash_);

        return work;
    }());
    filter_notifier_.Send([&] {
        auto work = MakeWork(WorkType::BlockchainNewFilter);
        work.AddFrame(chain_);
        work.AddFrame(type);
        work.AddFrame(tip.height_);
        work.AddFrame(tip.hash_);

        return work;
    }());
}

auto FilterOracle::ProcessBlock(
    const bitcoin::block::Block& block) const noexcept -> bool
{
    const auto& id = block.ID();
    const auto& header = block.Header();
    auto filters = Vector<database::Cfilter::CFilterParams>{};
    auto headers = Vector<database::Cfilter::CFHeaderParams>{};
    const auto& cfilter =
        filters.emplace_back(id, ProcessBlock(default_type_, block, {})).second;

    if (false == cfilter.IsValid()) {
        LogError()(OT_PRETTY_CLASS())("Failed to calculate ")(print(chain_))(
            " cfilter")
            .Flush();

        return false;
    }

    const auto previousCfheader =
        LoadFilterHeader(default_type_, header.ParentHash());

    if (previousCfheader.IsNull()) {
        LogError()(OT_PRETTY_CLASS())("failed to load previous")(print(chain_))(
            " cfheader")
            .Flush();

        return false;
    }

    const auto filterHash = cfilter.Hash();
    const auto& cfheader = std::get<1>(headers.emplace_back(
        id, cfilter.Header(previousCfheader.Bytes()), filterHash.Bytes()));

    if (cfheader.IsNull()) {
        LogError()(OT_PRETTY_CLASS())("failed to calculate ")(print(chain_))(
            " cfheader")
            .Flush();

        return false;
    }

    const auto position = block::Position{};
    const auto stored =
        database_.StoreFilters(default_type_, headers, filters, position);

    if (stored) {

        return true;
    } else {
        LogError()(OT_PRETTY_CLASS())("Database error ").Flush();

        return false;
    }
}

auto FilterOracle::ProcessBlock(
    const cfilter::Type filterType,
    const bitcoin::block::Block& block,
    alloc::Default alloc) const noexcept -> GCS
{
    const auto& id = block.ID();
    const auto params = blockchain::internal::GetFilterParams(filterType);
    const auto elements = [&] {
        const auto input = block.Internal().ExtractElements(filterType);
        auto output = Vector<ByteArray>{};
        std::transform(
            input.begin(),
            input.end(),
            std::back_inserter(output),
            [&](const auto& element) -> ByteArray {
                return api_.Factory().DataFromBytes(reader(element));
            });

        return output;
    }();

    return factory::GCS(
        api_,
        params.first,
        params.second,
        blockchain::internal::BlockHashToFilterKey(id.Bytes()),
        elements,
        alloc);
}

auto FilterOracle::ProcessSyncData(
    const block::Hash& prior,
    const Vector<block::Hash>& hashes,
    const network::p2p::Data& data) const noexcept -> void
{
    auto filters = Vector<database::Cfilter::CFilterParams>{};
    auto headers = Vector<database::Cfilter::CFHeaderParams>{};
    const auto& blocks = data.Blocks();
    const auto incoming = blocks.front().Height();
    const auto finalFilter = data.LastPosition(api_);
    const auto filterType = blocks.front().FilterType();
    const auto current = database_.FilterTip(filterType);
    const auto params = blockchain::internal::GetFilterParams(filterType);

    if ((1 == incoming) && (1000 < current.height_)) {
        const auto height = current.height_ - 1000;
        reset_tips_to(
            filterType, block::Position{height, header_.BestHash(height)});

        return;
    }

    LogVerbose()(OT_PRETTY_CLASS())("current ")(print(chain_))(
        " filter tip height is ")(current.height_)
        .Flush();
    LogVerbose()(OT_PRETTY_CLASS())("incoming ")(print(chain_))(
        " sync data provides heights ")(incoming)(" to ")(finalFilter.height_)
        .Flush();

    if (incoming > (current.height_ + 1)) {
        LogVerbose()(OT_PRETTY_CLASS())("cannot connect ")(print(chain_))(
            " sync data to current tip")
            .Flush();

        return;
    }

    const auto redundant = (finalFilter.height_ < current.height_) ||
                           (finalFilter.hash_ == current.hash_);

    if (redundant) {
        LogVerbose()(OT_PRETTY_CLASS())("ignoring redundant ")(print(chain_))(
            " sync data")
            .Flush();

        return;
    }

    const auto count{std::min<std::size_t>(hashes.size(), blocks.size())};
    filters.reserve(count);
    headers.reserve(count);

    try {
        OT_ASSERT(0 < count);

        const auto previous = [&] {
            if (prior.empty()) {

                return cfilter::Header{};
            } else {

                auto output = LoadFilterHeader(filterType, prior);

                if (output.IsNull()) {
                    LogError()(OT_PRETTY_CLASS())("cfheader for ")(
                        print(chain_))(" block ")(prior.asHex())(" not found")
                        .Flush();

                    throw std::runtime_error(
                        "Failed to load previous cfheader");
                }

                return output;
            }
        }();
        const auto* parent = &previous;
        auto b = hashes.cbegin();
        auto d = blocks.cbegin();

        for (auto i = 0_uz; i < count; ++i, ++b, ++d) {
            const auto& blockHash = *b;
            const auto& syncData = *d;
            const auto height = syncData.Height();
            auto& [fBlockHash, cfilter] = filters.emplace_back(
                blockHash,
                factory::GCS(
                    api_,
                    params.first,
                    params.second,
                    blockchain::internal::BlockHashToFilterKey(
                        blockHash.Bytes()),
                    syncData.FilterElements(),
                    syncData.Filter(),
                    {}));  // TODO allocator

            if (false == cfilter.IsValid()) {
                LogError()(OT_PRETTY_CLASS())("Failed to instantiate ")(
                    print(chain_))(" cfilter #")(height)
                    .Flush();

                throw std::runtime_error("Failed to instantiate gcs");
            }

            auto& [hBlockHash, cfheader, cfhash] = headers.emplace_back(
                blockHash, cfilter.Header(*parent), cfilter.Hash());
            parent = &cfheader;
        }

        const auto tip = [&] {
            const auto last = count - 1u;

            return block::Position{blocks.at(last).Height(), hashes.at(last)};
        }();
        const auto stored =
            database_.StoreFilters(filterType, headers, filters, tip);

        if (stored) {
            LogDetail()(print(chain_))(
                " cfheader and cfilter chain updated to height ")(tip.height_)
                .Flush();
            cb_(filterType, tip);
        } else {
            throw std::runtime_error{"database error"};
        }
    } catch (const std::exception& e) {
        LogError()(OT_PRETTY_CLASS())(e.what()).Flush();
    }
}

auto FilterOracle::reset_tips_to(
    const cfilter::Type type,
    const block::Position& position,
    const std::optional<bool> resetHeader,
    const std::optional<bool> resetfilter) const noexcept -> bool
{
    return reset_tips_to(
        type,
        database_.FilterHeaderTip(default_type_),
        database_.FilterTip(default_type_),
        position,
        resetHeader,
        resetfilter);
}

auto FilterOracle::reset_tips_to(
    const cfilter::Type type,
    const block::Position& headerTip,
    const block::Position& position,
    const std::optional<bool> resetHeader) const noexcept -> bool
{
    return reset_tips_to(
        type,
        headerTip,
        database_.FilterTip(default_type_),
        position,
        resetHeader);
}

auto FilterOracle::reset_tips_to(
    const cfilter::Type type,
    const block::Position& headerTip,
    const block::Position& filterTip,
    const block::Position& position,
    std::optional<bool> resetHeader,
    std::optional<bool> resetfilter) const noexcept -> bool
{
    auto counter{0};

    if (false == resetHeader.has_value()) {
        resetHeader = headerTip > position;
    }

    if (false == resetfilter.has_value()) {
        resetfilter = filterTip > position;
    }

    OT_ASSERT(resetHeader.has_value());
    OT_ASSERT(resetfilter.has_value());

    auto lock = rLock{lock_};
    using Future = std::shared_future<cfilter::Header>;
    auto previous = [&]() -> Future {
        const auto& block = header_.LoadHeader(position.hash_);

        OT_ASSERT(block);

        auto promise = std::promise<cfilter::Header>{};
        promise.set_value(database_.LoadFilterHeader(
            default_type_, block->ParentHash().Bytes()));

        return promise.get_future();
    }();
    auto resetBlock{false};
    auto headerTipHasBeenReset{false};
    auto filterTipHasBeenReset{false};

    if (resetHeader.value()) {
        if (header_downloader_) {
            header_downloader_->Reset(position, Future{previous});
            headerTipHasBeenReset = true;
        }

        resetBlock = true;
        ++counter;
    }

    if (resetfilter.value()) {
        if (filter_downloader_) {
            filter_downloader_->Reset(position, Future{previous});
            filterTipHasBeenReset = true;
        }

        resetBlock = true;
        ++counter;
    }

    if (resetBlock && have_block_indexer_) {
        reindex_blocks_->Send(MakeWork(filteroracle::BlockIndexerJob::reindex));
        headerTipHasBeenReset = true;
        filterTipHasBeenReset = true;
    }

    if (resetHeader.value() && (false == headerTipHasBeenReset)) {
        database_.SetFilterHeaderTip(default_type_, position);
    }

    if (resetfilter.value() && (false == filterTipHasBeenReset)) {
        database_.SetFilterTip(default_type_, position);
    }

    return 0 < counter;
}

auto FilterOracle::Shutdown() noexcept -> void
{
    running_ = false;

    auto lock = rLock{lock_};

    if (header_downloader_) { header_downloader_.reset(); }

    if (filter_downloader_) { filter_downloader_.reset(); }

    if (block_indexer_) { block_indexer_.reset(); }
}

auto FilterOracle::Start() noexcept -> void
{
    auto lock = rLock{lock_};

    if (header_downloader_) { header_downloader_->Start(); }

    if (filter_downloader_) { filter_downloader_->Start(); }

    if (block_indexer_) {
        block_indexer_->Start();
        block_indexer_.reset();
    }
}

auto FilterOracle::Tip(const cfilter::Type type) const noexcept
    -> block::Position
{
    return database_.FilterTip(type);
}

auto FilterOracle::update_tip(
    const cfilter::Type type,
    const block::Position& pos) noexcept -> void
{
    if (false == running_) { return; }

    auto lock = rLock{lock_};
    new_tip(lock, type, pos);
}

FilterOracle::~FilterOracle() { Shutdown(); }
}  // namespace opentxs::blockchain::node::implementation
