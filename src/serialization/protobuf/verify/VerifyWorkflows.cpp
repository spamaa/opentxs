// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "internal/serialization/protobuf/verify/VerifyWorkflows.hpp"  // IWYU pragma: associated

#include "internal/serialization/protobuf/Basic.hpp"

namespace opentxs::proto
{
auto PaymentEventAllowedTransportMethod() noexcept -> const EventTransportMap&
{
    static const auto output = EventTransportMap{
        {{1, PAYMENTEVENTTYPE_CREATE},
         {TRANSPORTMETHOD_NONE, TRANSPORTMETHOD_OT}},
        {{1, PAYMENTEVENTTYPE_CONVEY},
         {TRANSPORTMETHOD_OT, TRANSPORTMETHOD_OOB}},
        {{1, PAYMENTEVENTTYPE_CANCEL}, {TRANSPORTMETHOD_OT}},
        {{1, PAYMENTEVENTTYPE_ACCEPT}, {TRANSPORTMETHOD_OT}},
        {{1, PAYMENTEVENTTYPE_COMPLETE}, {TRANSPORTMETHOD_OT}},
        {{2, PAYMENTEVENTTYPE_CREATE},
         {TRANSPORTMETHOD_NONE, TRANSPORTMETHOD_OT}},
        {{2, PAYMENTEVENTTYPE_CONVEY},
         {TRANSPORTMETHOD_OT, TRANSPORTMETHOD_OOB}},
        {{2, PAYMENTEVENTTYPE_CANCEL}, {TRANSPORTMETHOD_OT}},
        {{2, PAYMENTEVENTTYPE_ACCEPT}, {TRANSPORTMETHOD_OT}},
        {{2, PAYMENTEVENTTYPE_COMPLETE}, {TRANSPORTMETHOD_OT}},
        {{2, PAYMENTEVENTTYPE_ABORT},
         {TRANSPORTMETHOD_NONE, TRANSPORTMETHOD_OT}},
        {{2, PAYMENTEVENTTYPE_ACKNOWLEDGE}, {TRANSPORTMETHOD_OT}},
        {{3, PAYMENTEVENTTYPE_CREATE},
         {TRANSPORTMETHOD_NONE, TRANSPORTMETHOD_OT}},
        {{3, PAYMENTEVENTTYPE_CONVEY},
         {TRANSPORTMETHOD_OT, TRANSPORTMETHOD_OOB}},
        {{3, PAYMENTEVENTTYPE_CANCEL}, {TRANSPORTMETHOD_OT}},
        {{3, PAYMENTEVENTTYPE_ACCEPT}, {TRANSPORTMETHOD_OT}},
        {{3, PAYMENTEVENTTYPE_COMPLETE}, {TRANSPORTMETHOD_OT}},
        {{3, PAYMENTEVENTTYPE_ABORT},
         {TRANSPORTMETHOD_NONE, TRANSPORTMETHOD_OT}},
        {{3, PAYMENTEVENTTYPE_ACKNOWLEDGE}, {TRANSPORTMETHOD_OT}},
        {{3, PAYMENTEVENTTYPE_EXPIRE}, {TRANSPORTMETHOD_NONE}},
        {{3, PAYMENTEVENTTYPE_REJECT}, {TRANSPORTMETHOD_OT}},
    };

    return output;
}
auto PaymentWorkflowAllowedEventTypes() noexcept -> const WorkflowEventMap&
{
    static const auto output = WorkflowEventMap{
        {{1, PAYMENTWORKFLOWTYPE_OUTGOINGCHEQUE},
         {PAYMENTEVENTTYPE_CREATE,
          PAYMENTEVENTTYPE_CONVEY,
          PAYMENTEVENTTYPE_CANCEL,
          PAYMENTEVENTTYPE_ACCEPT,
          PAYMENTEVENTTYPE_COMPLETE}},
        {{1, PAYMENTWORKFLOWTYPE_INCOMINGCHEQUE},
         {PAYMENTEVENTTYPE_CONVEY, PAYMENTEVENTTYPE_ACCEPT}},
        {{1, PAYMENTWORKFLOWTYPE_OUTGOINGINVOICE},
         {PAYMENTEVENTTYPE_CREATE,
          PAYMENTEVENTTYPE_CONVEY,
          PAYMENTEVENTTYPE_CANCEL,
          PAYMENTEVENTTYPE_ACCEPT,
          PAYMENTEVENTTYPE_COMPLETE}},
        {{1, PAYMENTWORKFLOWTYPE_INCOMINGINVOICE},
         {PAYMENTEVENTTYPE_CONVEY, PAYMENTEVENTTYPE_ACCEPT}},
        {{2, PAYMENTWORKFLOWTYPE_OUTGOINGCHEQUE},
         {PAYMENTEVENTTYPE_CREATE,
          PAYMENTEVENTTYPE_CONVEY,
          PAYMENTEVENTTYPE_CANCEL,
          PAYMENTEVENTTYPE_ACCEPT,
          PAYMENTEVENTTYPE_COMPLETE}},
        {{2, PAYMENTWORKFLOWTYPE_INCOMINGCHEQUE},
         {PAYMENTEVENTTYPE_CONVEY, PAYMENTEVENTTYPE_ACCEPT}},
        {{2, PAYMENTWORKFLOWTYPE_OUTGOINGINVOICE},
         {PAYMENTEVENTTYPE_CREATE,
          PAYMENTEVENTTYPE_CONVEY,
          PAYMENTEVENTTYPE_CANCEL,
          PAYMENTEVENTTYPE_ACCEPT,
          PAYMENTEVENTTYPE_COMPLETE}},
        {{2, PAYMENTWORKFLOWTYPE_INCOMINGINVOICE},
         {PAYMENTEVENTTYPE_CONVEY, PAYMENTEVENTTYPE_ACCEPT}},
        {{2, PAYMENTWORKFLOWTYPE_OUTGOINGTRANSFER},
         {PAYMENTEVENTTYPE_CREATE,
          PAYMENTEVENTTYPE_ABORT,
          PAYMENTEVENTTYPE_ACKNOWLEDGE,
          PAYMENTEVENTTYPE_ACCEPT,
          PAYMENTEVENTTYPE_COMPLETE}},
        {{2, PAYMENTWORKFLOWTYPE_INCOMINGTRANSFER},
         {PAYMENTEVENTTYPE_CONVEY, PAYMENTEVENTTYPE_ACCEPT}},
        {{2, PAYMENTWORKFLOWTYPE_INTERNALTRANSFER},
         {PAYMENTEVENTTYPE_CREATE,
          PAYMENTEVENTTYPE_ABORT,
          PAYMENTEVENTTYPE_ACKNOWLEDGE,
          PAYMENTEVENTTYPE_CONVEY,
          PAYMENTEVENTTYPE_ACCEPT,
          PAYMENTEVENTTYPE_COMPLETE}},
        {{3, PAYMENTWORKFLOWTYPE_OUTGOINGCHEQUE},
         {PAYMENTEVENTTYPE_CREATE,
          PAYMENTEVENTTYPE_CONVEY,
          PAYMENTEVENTTYPE_CANCEL,
          PAYMENTEVENTTYPE_ACCEPT,
          PAYMENTEVENTTYPE_COMPLETE}},
        {{3, PAYMENTWORKFLOWTYPE_INCOMINGCHEQUE},
         {PAYMENTEVENTTYPE_CONVEY, PAYMENTEVENTTYPE_ACCEPT}},
        {{3, PAYMENTWORKFLOWTYPE_OUTGOINGINVOICE},
         {PAYMENTEVENTTYPE_CREATE,
          PAYMENTEVENTTYPE_CONVEY,
          PAYMENTEVENTTYPE_CANCEL,
          PAYMENTEVENTTYPE_ACCEPT,
          PAYMENTEVENTTYPE_COMPLETE}},
        {{3, PAYMENTWORKFLOWTYPE_INCOMINGINVOICE},
         {PAYMENTEVENTTYPE_CONVEY, PAYMENTEVENTTYPE_ACCEPT}},
        {{3, PAYMENTWORKFLOWTYPE_OUTGOINGTRANSFER},
         {PAYMENTEVENTTYPE_CREATE,
          PAYMENTEVENTTYPE_ABORT,
          PAYMENTEVENTTYPE_ACKNOWLEDGE,
          PAYMENTEVENTTYPE_ACCEPT,
          PAYMENTEVENTTYPE_COMPLETE}},
        {{3, PAYMENTWORKFLOWTYPE_INCOMINGTRANSFER},
         {PAYMENTEVENTTYPE_CONVEY, PAYMENTEVENTTYPE_ACCEPT}},
        {{3, PAYMENTWORKFLOWTYPE_INTERNALTRANSFER},
         {PAYMENTEVENTTYPE_CREATE,
          PAYMENTEVENTTYPE_ABORT,
          PAYMENTEVENTTYPE_ACKNOWLEDGE,
          PAYMENTEVENTTYPE_CONVEY,
          PAYMENTEVENTTYPE_ACCEPT,
          PAYMENTEVENTTYPE_COMPLETE}},
        {{3, PAYMENTWORKFLOWTYPE_OUTGOINGCASH},
         {PAYMENTEVENTTYPE_CREATE,
          PAYMENTEVENTTYPE_CONVEY,
          PAYMENTEVENTTYPE_EXPIRE}},
        {{3, PAYMENTWORKFLOWTYPE_INCOMINGCASH},
         {PAYMENTEVENTTYPE_CONVEY,
          PAYMENTEVENTTYPE_ACCEPT,
          PAYMENTEVENTTYPE_EXPIRE,
          PAYMENTEVENTTYPE_REJECT}},
    };

    return output;
}
auto PaymentWorkflowAllowedInstrumentRevision() noexcept -> const VersionMap&
{
    static const auto output = VersionMap{
        {1, {1, 1}},
        {2, {1, 1}},
        {3, {1, 1}},
    };

    return output;
}
auto PaymentWorkflowAllowedPaymentEvent() noexcept -> const VersionMap&
{
    static const auto output = VersionMap{
        {1, {1, 1}},
        {2, {1, 2}},
        {3, {3, 3}},
    };

    return output;
}
auto PaymentWorkflowAllowedState() noexcept -> const WorkflowStateMap&
{
    static const auto output = WorkflowStateMap{
        {{1, PAYMENTWORKFLOWTYPE_OUTGOINGCHEQUE},
         {PAYMENTWORKFLOWSTATE_UNSENT,
          PAYMENTWORKFLOWSTATE_CONVEYED,
          PAYMENTWORKFLOWSTATE_CANCELLED,
          PAYMENTWORKFLOWSTATE_ACCEPTED,
          PAYMENTWORKFLOWSTATE_COMPLETED,
          PAYMENTWORKFLOWSTATE_EXPIRED}},
        {{1, PAYMENTWORKFLOWTYPE_INCOMINGCHEQUE},
         {PAYMENTWORKFLOWSTATE_CONVEYED,
          PAYMENTWORKFLOWSTATE_COMPLETED,
          PAYMENTWORKFLOWSTATE_EXPIRED}},
        {{1, PAYMENTWORKFLOWTYPE_OUTGOINGINVOICE},
         {PAYMENTWORKFLOWSTATE_UNSENT,
          PAYMENTWORKFLOWSTATE_CONVEYED,
          PAYMENTWORKFLOWSTATE_CANCELLED,
          PAYMENTWORKFLOWSTATE_ACCEPTED,
          PAYMENTWORKFLOWSTATE_COMPLETED,
          PAYMENTWORKFLOWSTATE_EXPIRED}},
        {{1, PAYMENTWORKFLOWTYPE_INCOMINGINVOICE},
         {PAYMENTWORKFLOWSTATE_CONVEYED,
          PAYMENTWORKFLOWSTATE_COMPLETED,
          PAYMENTWORKFLOWSTATE_EXPIRED}},
        {{2, PAYMENTWORKFLOWTYPE_OUTGOINGCHEQUE},
         {PAYMENTWORKFLOWSTATE_UNSENT,
          PAYMENTWORKFLOWSTATE_CONVEYED,
          PAYMENTWORKFLOWSTATE_CANCELLED,
          PAYMENTWORKFLOWSTATE_ACCEPTED,
          PAYMENTWORKFLOWSTATE_COMPLETED,
          PAYMENTWORKFLOWSTATE_EXPIRED}},
        {{2, PAYMENTWORKFLOWTYPE_INCOMINGCHEQUE},
         {PAYMENTWORKFLOWSTATE_CONVEYED,
          PAYMENTWORKFLOWSTATE_COMPLETED,
          PAYMENTWORKFLOWSTATE_EXPIRED}},
        {{2, PAYMENTWORKFLOWTYPE_OUTGOINGINVOICE},
         {PAYMENTWORKFLOWSTATE_UNSENT,
          PAYMENTWORKFLOWSTATE_CONVEYED,
          PAYMENTWORKFLOWSTATE_CANCELLED,
          PAYMENTWORKFLOWSTATE_ACCEPTED,
          PAYMENTWORKFLOWSTATE_COMPLETED,
          PAYMENTWORKFLOWSTATE_EXPIRED}},
        {{2, PAYMENTWORKFLOWTYPE_INCOMINGINVOICE},
         {PAYMENTWORKFLOWSTATE_CONVEYED,
          PAYMENTWORKFLOWSTATE_COMPLETED,
          PAYMENTWORKFLOWSTATE_EXPIRED}},
        {{2, PAYMENTWORKFLOWTYPE_OUTGOINGTRANSFER},
         {PAYMENTWORKFLOWSTATE_INITIATED,
          PAYMENTWORKFLOWSTATE_ABORTED,
          PAYMENTWORKFLOWSTATE_ACKNOWLEDGED,
          PAYMENTWORKFLOWSTATE_ACCEPTED,
          PAYMENTWORKFLOWSTATE_COMPLETED}},
        {{2, PAYMENTWORKFLOWTYPE_INCOMINGTRANSFER},
         {PAYMENTWORKFLOWSTATE_CONVEYED, PAYMENTWORKFLOWSTATE_COMPLETED}},
        {{2, PAYMENTWORKFLOWTYPE_INTERNALTRANSFER},
         {PAYMENTWORKFLOWSTATE_INITIATED,
          PAYMENTWORKFLOWSTATE_ABORTED,
          PAYMENTWORKFLOWSTATE_ACKNOWLEDGED,
          PAYMENTWORKFLOWSTATE_CONVEYED,
          PAYMENTWORKFLOWSTATE_ACCEPTED,
          PAYMENTWORKFLOWSTATE_COMPLETED}},
        {{3, PAYMENTWORKFLOWTYPE_OUTGOINGCHEQUE},
         {PAYMENTWORKFLOWSTATE_UNSENT,
          PAYMENTWORKFLOWSTATE_CONVEYED,
          PAYMENTWORKFLOWSTATE_CANCELLED,
          PAYMENTWORKFLOWSTATE_ACCEPTED,
          PAYMENTWORKFLOWSTATE_COMPLETED,
          PAYMENTWORKFLOWSTATE_EXPIRED}},
        {{3, PAYMENTWORKFLOWTYPE_INCOMINGCHEQUE},
         {PAYMENTWORKFLOWSTATE_CONVEYED,
          PAYMENTWORKFLOWSTATE_COMPLETED,
          PAYMENTWORKFLOWSTATE_EXPIRED}},
        {{3, PAYMENTWORKFLOWTYPE_OUTGOINGINVOICE},
         {PAYMENTWORKFLOWSTATE_UNSENT,
          PAYMENTWORKFLOWSTATE_CONVEYED,
          PAYMENTWORKFLOWSTATE_CANCELLED,
          PAYMENTWORKFLOWSTATE_ACCEPTED,
          PAYMENTWORKFLOWSTATE_COMPLETED,
          PAYMENTWORKFLOWSTATE_EXPIRED}},
        {{3, PAYMENTWORKFLOWTYPE_INCOMINGINVOICE},
         {PAYMENTWORKFLOWSTATE_CONVEYED,
          PAYMENTWORKFLOWSTATE_COMPLETED,
          PAYMENTWORKFLOWSTATE_EXPIRED}},
        {{3, PAYMENTWORKFLOWTYPE_OUTGOINGTRANSFER},
         {PAYMENTWORKFLOWSTATE_INITIATED,
          PAYMENTWORKFLOWSTATE_ABORTED,
          PAYMENTWORKFLOWSTATE_ACKNOWLEDGED,
          PAYMENTWORKFLOWSTATE_ACCEPTED,
          PAYMENTWORKFLOWSTATE_COMPLETED}},
        {{3, PAYMENTWORKFLOWTYPE_INCOMINGTRANSFER},
         {PAYMENTWORKFLOWSTATE_CONVEYED, PAYMENTWORKFLOWSTATE_COMPLETED}},
        {{3, PAYMENTWORKFLOWTYPE_INTERNALTRANSFER},
         {PAYMENTWORKFLOWSTATE_INITIATED,
          PAYMENTWORKFLOWSTATE_ABORTED,
          PAYMENTWORKFLOWSTATE_ACKNOWLEDGED,
          PAYMENTWORKFLOWSTATE_CONVEYED,
          PAYMENTWORKFLOWSTATE_ACCEPTED,
          PAYMENTWORKFLOWSTATE_COMPLETED}},
        {{3, PAYMENTWORKFLOWTYPE_OUTGOINGCASH},
         {PAYMENTWORKFLOWSTATE_UNSENT,
          PAYMENTWORKFLOWSTATE_CONVEYED,
          PAYMENTWORKFLOWSTATE_EXPIRED}},
        {{3, PAYMENTWORKFLOWTYPE_INCOMINGCASH},
         {PAYMENTWORKFLOWSTATE_CONVEYED,
          PAYMENTWORKFLOWSTATE_ACCEPTED,
          PAYMENTWORKFLOWSTATE_REJECTED,
          PAYMENTWORKFLOWSTATE_EXPIRED}},
    };

    return output;
}
}  // namespace opentxs::proto
