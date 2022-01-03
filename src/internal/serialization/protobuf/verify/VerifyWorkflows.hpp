// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include "internal/serialization/protobuf/Basic.hpp"
#include "opentxs/Version.hpp"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wlanguage-extension-token"
#pragma GCC diagnostic ignored "-Wundef"
#pragma GCC diagnostic ignored "-Wdeprecated-dynamic-exception-spec"
#pragma GCC diagnostic ignored "-Wzero-as-null-pointer-constant"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Winconsistent-missing-destructor-override"
#include "serialization/protobuf/PaymentWorkflowEnums.pb.h"

#pragma GCC diagnostic pop

#include <cstdint>
#include <map>
#include <set>
#include <tuple>
#include <utility>

namespace opentxs
{
namespace proto
{
using PaymentWorkflowVersion = std::pair<std::uint32_t, PaymentWorkflowType>;
using WorkflowEventMap =
    std::map<PaymentWorkflowVersion, std::set<PaymentEventType>>;
using PaymentTypeVersion = std::pair<std::uint32_t, PaymentWorkflowType>;
using WorkflowStateMap =
    std::map<PaymentTypeVersion, std::set<PaymentWorkflowState>>;
using PaymentEventVersion = std::pair<std::uint32_t, PaymentEventType>;
using EventTransportMap =
    std::map<PaymentEventVersion, std::set<EventTransportMethod>>;

auto PaymentEventAllowedTransportMethod() noexcept -> const EventTransportMap&;
auto PaymentWorkflowAllowedEventTypes() noexcept -> const WorkflowEventMap&;
auto PaymentWorkflowAllowedInstrumentRevision() noexcept -> const VersionMap&;
auto PaymentWorkflowAllowedPaymentEvent() noexcept -> const VersionMap&;
auto PaymentWorkflowAllowedState() noexcept -> const WorkflowStateMap&;
}  // namespace proto
}  // namespace opentxs
