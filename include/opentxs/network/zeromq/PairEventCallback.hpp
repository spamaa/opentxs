// Copyright (c) 2010-2020 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef OPENTXS_NETWORK_ZEROMQ_PAIREVENTCALLBACK_HPP
#define OPENTXS_NETWORK_ZEROMQ_PAIREVENTCALLBACK_HPP

// IWYU pragma: no_include "opentxs/Proto.hpp"

#include "opentxs/Forward.hpp"  // IWYU pragma: associated

#include <functional>

#include "opentxs/Pimpl.hpp"
#include "opentxs/Proto.hpp"
#include "opentxs/network/zeromq/ListenCallback.hpp"
#include "opentxs/protobuf/APIArgument.pb.h"
#include "opentxs/protobuf/AcceptPendingPayment.pb.h"
#include "opentxs/protobuf/AccountData.pb.h"
#include "opentxs/protobuf/AccountEvent.pb.h"
#include "opentxs/protobuf/AddClaim.pb.h"
#include "opentxs/protobuf/AddContact.pb.h"
#include "opentxs/protobuf/AsymmetricKey.pb.h"
#include "opentxs/protobuf/Authority.pb.h"
#include "opentxs/protobuf/Bailment.pb.h"
#include "opentxs/protobuf/BailmentReply.pb.h"
#include "opentxs/protobuf/BasketItem.pb.h"
#include "opentxs/protobuf/BasketParams.pb.h"
#include "opentxs/protobuf/Bip47Address.pb.h"
#include "opentxs/protobuf/Bip47Channel.pb.h"
#include "opentxs/protobuf/Bip47Direction.pb.h"
#include "opentxs/protobuf/BitcoinBlockHeaderFields.pb.h"
#include "opentxs/protobuf/BlindedSeriesList.pb.h"
#include "opentxs/protobuf/BlockchainActivity.pb.h"
#include "opentxs/protobuf/BlockchainAddress.pb.h"
#include "opentxs/protobuf/BlockchainBlockHeader.pb.h"
#include "opentxs/protobuf/BlockchainBlockLocalData.pb.h"
#include "opentxs/protobuf/BlockchainExternalAddress.pb.h"
#include "opentxs/protobuf/BlockchainFilterHeader.pb.h"
#include "opentxs/protobuf/BlockchainInputWitness.pb.h"
#include "opentxs/protobuf/BlockchainPeerAddress.pb.h"
#include "opentxs/protobuf/BlockchainPreviousOutput.pb.h"
#include "opentxs/protobuf/BlockchainTransaction.pb.h"
#include "opentxs/protobuf/BlockchainTransactionInput.pb.h"
#include "opentxs/protobuf/BlockchainTransactionOutput.pb.h"
#include "opentxs/protobuf/BlockchainWalletKey.pb.h"
#include "opentxs/protobuf/ChildCredentialParameters.pb.h"
#include "opentxs/protobuf/Ciphertext.pb.h"
#include "opentxs/protobuf/Claim.pb.h"
#include "opentxs/protobuf/ClientContext.pb.h"
#include "opentxs/protobuf/ConnectionInfo.pb.h"
#include "opentxs/protobuf/ConnectionInfoReply.pb.h"
#include "opentxs/protobuf/Contact.pb.h"
#include "opentxs/protobuf/ContactData.pb.h"
#include "opentxs/protobuf/ContactEvent.pb.h"
#include "opentxs/protobuf/ContactItem.pb.h"
#include "opentxs/protobuf/ContactSection.pb.h"
#include "opentxs/protobuf/Context.pb.h"
#include "opentxs/protobuf/CreateInstrumentDefinition.pb.h"
#include "opentxs/protobuf/CreateNym.pb.h"
#include "opentxs/protobuf/Credential.pb.h"
#include "opentxs/protobuf/CurrencyParams.pb.h"
#include "opentxs/protobuf/Enums.pb.h"
#include "opentxs/protobuf/Envelope.pb.h"
#include "opentxs/protobuf/EquityParams.pb.h"
#include "opentxs/protobuf/EthereumBlockHeaderFields.pb.h"
#include "opentxs/protobuf/Faucet.pb.h"
#include "opentxs/protobuf/GCS.pb.h"
#include "opentxs/protobuf/GetWorkflow.pb.h"
#include "opentxs/protobuf/HDAccount.pb.h"
#include "opentxs/protobuf/HDPath.pb.h"
#include "opentxs/protobuf/HDSeed.pb.h"
#include "opentxs/protobuf/InstrumentRevision.pb.h"
#include "opentxs/protobuf/Issuer.pb.h"
#include "opentxs/protobuf/KeyCredential.pb.h"
#include "opentxs/protobuf/ListenAddress.pb.h"
#include "opentxs/protobuf/LucreTokenData.pb.h"
#include "opentxs/protobuf/MasterCredentialParameters.pb.h"
#include "opentxs/protobuf/ModifyAccount.pb.h"
#include "opentxs/protobuf/MoveFunds.pb.h"
#include "opentxs/protobuf/NoticeAcknowledgement.pb.h"
#include "opentxs/protobuf/Nym.pb.h"
#include "opentxs/protobuf/NymIDSource.pb.h"
#include "opentxs/protobuf/OTXPush.pb.h"
#include "opentxs/protobuf/OutBailment.pb.h"
#include "opentxs/protobuf/OutBailmentReply.pb.h"
#include "opentxs/protobuf/PairEvent.pb.h"
#include "opentxs/protobuf/PaymentCode.pb.h"
#include "opentxs/protobuf/PaymentEvent.pb.h"
#include "opentxs/protobuf/PaymentWorkflow.pb.h"
#include "opentxs/protobuf/PeerObject.pb.h"
#include "opentxs/protobuf/PeerReply.pb.h"
#include "opentxs/protobuf/PeerRequest.pb.h"
#include "opentxs/protobuf/PeerRequestHistory.pb.h"
#include "opentxs/protobuf/PeerRequestWorkflow.pb.h"
#include "opentxs/protobuf/PendingBailment.pb.h"
#include "opentxs/protobuf/PendingCommand.pb.h"
#include "opentxs/protobuf/Purse.pb.h"
#include "opentxs/protobuf/PurseExchange.pb.h"
#include "opentxs/protobuf/RPCCommand.pb.h"
#include "opentxs/protobuf/RPCPush.pb.h"
#include "opentxs/protobuf/RPCResponse.pb.h"
#include "opentxs/protobuf/RPCStatus.pb.h"
#include "opentxs/protobuf/RPCTask.pb.h"
#include "opentxs/protobuf/Seed.pb.h"
#include "opentxs/protobuf/SendMessage.pb.h"
#include "opentxs/protobuf/SendPayment.pb.h"
#include "opentxs/protobuf/ServerContext.pb.h"
#include "opentxs/protobuf/ServerContract.pb.h"
#include "opentxs/protobuf/ServerReply.pb.h"
#include "opentxs/protobuf/ServerRequest.pb.h"
#include "opentxs/protobuf/SessionData.pb.h"
#include "opentxs/protobuf/Signature.pb.h"
#include "opentxs/protobuf/SourceProof.pb.h"
#include "opentxs/protobuf/SpentTokenList.pb.h"
#include "opentxs/protobuf/StorageAccountIndex.pb.h"
#include "opentxs/protobuf/StorageAccounts.pb.h"
#include "opentxs/protobuf/StorageBip47AddressIndex.pb.h"
#include "opentxs/protobuf/StorageBip47ChannelList.pb.h"
#include "opentxs/protobuf/StorageBip47Contexts.pb.h"
#include "opentxs/protobuf/StorageBip47NymAddressIndex.pb.h"
#include "opentxs/protobuf/StorageBlockchainAccountList.pb.h"
#include "opentxs/protobuf/StorageBlockchainTransactions.pb.h"
#include "opentxs/protobuf/StorageContactAddressIndex.pb.h"
#include "opentxs/protobuf/StorageContactNymIndex.pb.h"
#include "opentxs/protobuf/StorageContacts.pb.h"
#include "opentxs/protobuf/StorageCredentials.pb.h"
#include "opentxs/protobuf/StorageIDList.pb.h"
#include "opentxs/protobuf/StorageIssuers.pb.h"
#include "opentxs/protobuf/StorageItemHash.pb.h"
#include "opentxs/protobuf/StorageItems.pb.h"
#include "opentxs/protobuf/StorageNotary.pb.h"
#include "opentxs/protobuf/StorageNym.pb.h"
#include "opentxs/protobuf/StorageNymList.pb.h"
#include "opentxs/protobuf/StoragePaymentWorkflows.pb.h"
#include "opentxs/protobuf/StoragePurse.pb.h"
#include "opentxs/protobuf/StorageRoot.pb.h"
#include "opentxs/protobuf/StorageSeeds.pb.h"
#include "opentxs/protobuf/StorageServers.pb.h"
#include "opentxs/protobuf/StorageThread.pb.h"
#include "opentxs/protobuf/StorageThreadItem.pb.h"
#include "opentxs/protobuf/StorageUnits.pb.h"
#include "opentxs/protobuf/StorageWorkflowIndex.pb.h"
#include "opentxs/protobuf/StorageWorkflowType.pb.h"
#include "opentxs/protobuf/StoreSecret.pb.h"
#include "opentxs/protobuf/SymmetricKey.pb.h"
#include "opentxs/protobuf/TaggedKey.pb.h"
#include "opentxs/protobuf/TaskComplete.pb.h"
#include "opentxs/protobuf/Token.pb.h"
#include "opentxs/protobuf/TransactionData.pb.h"
#include "opentxs/protobuf/UnitAccountMap.pb.h"
#include "opentxs/protobuf/UnitDefinition.pb.h"
#include "opentxs/protobuf/Verification.pb.h"
#include "opentxs/protobuf/VerificationGroup.pb.h"
#include "opentxs/protobuf/VerificationIdentity.pb.h"
#include "opentxs/protobuf/VerificationOffer.pb.h"
#include "opentxs/protobuf/VerificationSet.pb.h"
#include "opentxs/protobuf/VerifyClaim.pb.h"
#include "opentxs/protobuf/verify/APIArgument.hpp"
#include "opentxs/protobuf/verify/AcceptPendingPayment.hpp"
#include "opentxs/protobuf/verify/AccountData.hpp"
#include "opentxs/protobuf/verify/AccountEvent.hpp"
#include "opentxs/protobuf/verify/AddClaim.hpp"
#include "opentxs/protobuf/verify/AddContact.hpp"
#include "opentxs/protobuf/verify/AsymmetricKey.hpp"
#include "opentxs/protobuf/verify/Authority.hpp"
#include "opentxs/protobuf/verify/Bailment.hpp"
#include "opentxs/protobuf/verify/BailmentReply.hpp"
#include "opentxs/protobuf/verify/BasketItem.hpp"
#include "opentxs/protobuf/verify/BasketParams.hpp"
#include "opentxs/protobuf/verify/Bip47Address.hpp"
#include "opentxs/protobuf/verify/Bip47Channel.hpp"
#include "opentxs/protobuf/verify/Bip47Direction.hpp"
#include "opentxs/protobuf/verify/BitcoinBlockHeaderFields.hpp"
#include "opentxs/protobuf/verify/BlindedSeriesList.hpp"
#include "opentxs/protobuf/verify/BlockchainActivity.hpp"
#include "opentxs/protobuf/verify/BlockchainAddress.hpp"
#include "opentxs/protobuf/verify/BlockchainBlockHeader.hpp"
#include "opentxs/protobuf/verify/BlockchainBlockLocalData.hpp"
#include "opentxs/protobuf/verify/BlockchainExternalAddress.hpp"
#include "opentxs/protobuf/verify/BlockchainFilterHeader.hpp"
#include "opentxs/protobuf/verify/BlockchainInputWitness.hpp"
#include "opentxs/protobuf/verify/BlockchainPeerAddress.hpp"
#include "opentxs/protobuf/verify/BlockchainPreviousOutput.hpp"
#include "opentxs/protobuf/verify/BlockchainTransaction.hpp"
#include "opentxs/protobuf/verify/BlockchainTransactionInput.hpp"
#include "opentxs/protobuf/verify/BlockchainTransactionOutput.hpp"
#include "opentxs/protobuf/verify/BlockchainWalletKey.hpp"
#include "opentxs/protobuf/verify/ChildCredentialParameters.hpp"
#include "opentxs/protobuf/verify/Ciphertext.hpp"
#include "opentxs/protobuf/verify/Claim.hpp"
#include "opentxs/protobuf/verify/ClientContext.hpp"
#include "opentxs/protobuf/verify/ConnectionInfo.hpp"
#include "opentxs/protobuf/verify/ConnectionInfoReply.hpp"
#include "opentxs/protobuf/verify/Contact.hpp"
#include "opentxs/protobuf/verify/ContactData.hpp"
#include "opentxs/protobuf/verify/ContactEvent.hpp"
#include "opentxs/protobuf/verify/ContactItem.hpp"
#include "opentxs/protobuf/verify/ContactSection.hpp"
#include "opentxs/protobuf/verify/Context.hpp"
#include "opentxs/protobuf/verify/CreateInstrumentDefinition.hpp"
#include "opentxs/protobuf/verify/CreateNym.hpp"
#include "opentxs/protobuf/verify/Credential.hpp"
#include "opentxs/protobuf/verify/CurrencyParams.hpp"
#include "opentxs/protobuf/verify/Envelope.hpp"
#include "opentxs/protobuf/verify/EquityParams.hpp"
#include "opentxs/protobuf/verify/EthereumBlockHeaderFields.hpp"
#include "opentxs/protobuf/verify/Faucet.hpp"
#include "opentxs/protobuf/verify/GCS.hpp"
#include "opentxs/protobuf/verify/GetWorkflow.hpp"
#include "opentxs/protobuf/verify/HDAccount.hpp"
#include "opentxs/protobuf/verify/HDPath.hpp"
#include "opentxs/protobuf/verify/HDSeed.hpp"
#include "opentxs/protobuf/verify/InstrumentRevision.hpp"
#include "opentxs/protobuf/verify/Issuer.hpp"
#include "opentxs/protobuf/verify/KeyCredential.hpp"
#include "opentxs/protobuf/verify/ListenAddress.hpp"
#include "opentxs/protobuf/verify/LucreTokenData.hpp"
#include "opentxs/protobuf/verify/MasterCredentialParameters.hpp"
#include "opentxs/protobuf/verify/ModifyAccount.hpp"
#include "opentxs/protobuf/verify/MoveFunds.hpp"
#include "opentxs/protobuf/verify/NoticeAcknowledgement.hpp"
#include "opentxs/protobuf/verify/Nym.hpp"
#include "opentxs/protobuf/verify/NymIDSource.hpp"
#include "opentxs/protobuf/verify/OTXPush.hpp"
#include "opentxs/protobuf/verify/OutBailment.hpp"
#include "opentxs/protobuf/verify/OutBailmentReply.hpp"
#include "opentxs/protobuf/verify/PairEvent.hpp"
#include "opentxs/protobuf/verify/PaymentCode.hpp"
#include "opentxs/protobuf/verify/PaymentEvent.hpp"
#include "opentxs/protobuf/verify/PaymentWorkflow.hpp"
#include "opentxs/protobuf/verify/PeerObject.hpp"
#include "opentxs/protobuf/verify/PeerReply.hpp"
#include "opentxs/protobuf/verify/PeerRequest.hpp"
#include "opentxs/protobuf/verify/PeerRequestHistory.hpp"
#include "opentxs/protobuf/verify/PeerRequestWorkflow.hpp"
#include "opentxs/protobuf/verify/PendingBailment.hpp"
#include "opentxs/protobuf/verify/PendingCommand.hpp"
#include "opentxs/protobuf/verify/Purse.hpp"
#include "opentxs/protobuf/verify/PurseExchange.hpp"
#include "opentxs/protobuf/verify/RPCCommand.hpp"
#include "opentxs/protobuf/verify/RPCPush.hpp"
#include "opentxs/protobuf/verify/RPCResponse.hpp"
#include "opentxs/protobuf/verify/RPCStatus.hpp"
#include "opentxs/protobuf/verify/RPCTask.hpp"
#include "opentxs/protobuf/verify/Seed.hpp"
#include "opentxs/protobuf/verify/SendMessage.hpp"
#include "opentxs/protobuf/verify/SendPayment.hpp"
#include "opentxs/protobuf/verify/ServerContext.hpp"
#include "opentxs/protobuf/verify/ServerContract.hpp"
#include "opentxs/protobuf/verify/ServerReply.hpp"
#include "opentxs/protobuf/verify/ServerRequest.hpp"
#include "opentxs/protobuf/verify/SessionData.hpp"
#include "opentxs/protobuf/verify/Signature.hpp"
#include "opentxs/protobuf/verify/Signature.hpp"
#include "opentxs/protobuf/verify/SourceProof.hpp"
#include "opentxs/protobuf/verify/SpentTokenList.hpp"
#include "opentxs/protobuf/verify/StorageAccountIndex.hpp"
#include "opentxs/protobuf/verify/StorageAccounts.hpp"
#include "opentxs/protobuf/verify/StorageBip47AddressIndex.hpp"
#include "opentxs/protobuf/verify/StorageBip47ChannelList.hpp"
#include "opentxs/protobuf/verify/StorageBip47Contexts.hpp"
#include "opentxs/protobuf/verify/StorageBip47NymAddressIndex.hpp"
#include "opentxs/protobuf/verify/StorageBlockchainAccountList.hpp"
#include "opentxs/protobuf/verify/StorageBlockchainTransactions.hpp"
#include "opentxs/protobuf/verify/StorageContactAddressIndex.hpp"
#include "opentxs/protobuf/verify/StorageContactNymIndex.hpp"
#include "opentxs/protobuf/verify/StorageContacts.hpp"
#include "opentxs/protobuf/verify/StorageCredentials.hpp"
#include "opentxs/protobuf/verify/StorageIDList.hpp"
#include "opentxs/protobuf/verify/StorageIssuers.hpp"
#include "opentxs/protobuf/verify/StorageItemHash.hpp"
#include "opentxs/protobuf/verify/StorageItems.hpp"
#include "opentxs/protobuf/verify/StorageNotary.hpp"
#include "opentxs/protobuf/verify/StorageNym.hpp"
#include "opentxs/protobuf/verify/StorageNymList.hpp"
#include "opentxs/protobuf/verify/StoragePaymentWorkflows.hpp"
#include "opentxs/protobuf/verify/StoragePurse.hpp"
#include "opentxs/protobuf/verify/StorageRoot.hpp"
#include "opentxs/protobuf/verify/StorageSeeds.hpp"
#include "opentxs/protobuf/verify/StorageServers.hpp"
#include "opentxs/protobuf/verify/StorageThread.hpp"
#include "opentxs/protobuf/verify/StorageThreadItem.hpp"
#include "opentxs/protobuf/verify/StorageUnits.hpp"
#include "opentxs/protobuf/verify/StorageWorkflowIndex.hpp"
#include "opentxs/protobuf/verify/StorageWorkflowType.hpp"
#include "opentxs/protobuf/verify/StoreSecret.hpp"
#include "opentxs/protobuf/verify/SymmetricKey.hpp"
#include "opentxs/protobuf/verify/TaggedKey.hpp"
#include "opentxs/protobuf/verify/TaskComplete.hpp"
#include "opentxs/protobuf/verify/Token.hpp"
#include "opentxs/protobuf/verify/TransactionData.hpp"
#include "opentxs/protobuf/verify/UnitAccountMap.hpp"
#include "opentxs/protobuf/verify/UnitDefinition.hpp"
#include "opentxs/protobuf/verify/Verification.hpp"
#include "opentxs/protobuf/verify/VerificationGroup.hpp"
#include "opentxs/protobuf/verify/VerificationIdentity.hpp"
#include "opentxs/protobuf/verify/VerificationOffer.hpp"
#include "opentxs/protobuf/verify/VerificationSet.hpp"
#include "opentxs/protobuf/verify/VerifyClaim.hpp"
#include "opentxs/protobuf/verify/VerifyCredentials.hpp"

#ifdef SWIG
// clang-format off
%ignore opentxs::Pimpl<opentxs::network::zeromq::PairEventCallback>::Pimpl(opentxs::network::zeromq::PairEventCallback const &);
%ignore opentxs::Pimpl<opentxs::network::zeromq::PairEventCallback>::operator opentxs::network::zeromq::PairEventCallback&;
%ignore opentxs::Pimpl<opentxs::network::zeromq::PairEventCallback>::operator const opentxs::network::zeromq::PairEventCallback &;
%rename(assign) operator=(const opentxs::network::zeromq::PairEventCallback&);
%rename(ZMQPairEventCallback) opentxs::network::zeromq::PairEventCallback;
%template(OTZMQPairEventCallback) opentxs::Pimpl<opentxs::network::zeromq::PairEventCallback>;
// clang-format on
#endif  // SWIG

namespace opentxs
{
namespace network
{
namespace zeromq
{
class PairEventCallback;
}  // namespace zeromq
}  // namespace network

using OTZMQPairEventCallback = Pimpl<network::zeromq::PairEventCallback>;
}  // namespace opentxs

namespace opentxs
{
namespace network
{
namespace zeromq
{
class PairEventCallback : virtual public ListenCallback
{
public:
    using ReceiveCallback = std::function<void(const proto::PairEvent&)>;

#ifndef SWIG
    OPENTXS_EXPORT static OTZMQPairEventCallback Factory(
        ReceiveCallback callback);
#endif
    OPENTXS_EXPORT static opentxs::Pimpl<
        opentxs::network::zeromq::PairEventCallback>
    Factory(PairEventCallbackSwig* callback);

    OPENTXS_EXPORT ~PairEventCallback() override = default;

protected:
    PairEventCallback() = default;

private:
    friend OTZMQPairEventCallback;

#ifndef _WIN32
    PairEventCallback* clone() const override = 0;
#endif

    PairEventCallback(const PairEventCallback&) = delete;
    PairEventCallback(PairEventCallback&&) = delete;
    PairEventCallback& operator=(const PairEventCallback&) = delete;
    PairEventCallback& operator=(PairEventCallback&&) = delete;
};
}  // namespace zeromq
}  // namespace network
}  // namespace opentxs
#endif
