// Copyright (c) 2010-2019 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "Helpers.hpp"

namespace
{
TEST_F(Test_StartStop, init_opentxs) {}

TEST_F(Test_StartStop, all)
{
    EXPECT_TRUE(api_.Blockchain().Start(b::Type::Bitcoin));
    EXPECT_TRUE(api_.Blockchain().Start(b::Type::Bitcoin_testnet3));
    EXPECT_TRUE(api_.Blockchain().Start(b::Type::BitcoinCash));
    EXPECT_TRUE(api_.Blockchain().Start(b::Type::BitcoinCash_testnet3));
    EXPECT_FALSE(api_.Blockchain().Start(b::Type::Ethereum_frontier));
    EXPECT_FALSE(api_.Blockchain().Start(b::Type::Ethereum_ropsten));
    EXPECT_FALSE(api_.Blockchain().Start(b::Type::Litecoin));
    EXPECT_FALSE(api_.Blockchain().Start(b::Type::Litecoin_testnet4));
    EXPECT_FALSE(api_.Blockchain().Stop(b::Type::Litecoin_testnet4));
    EXPECT_FALSE(api_.Blockchain().Stop(b::Type::Litecoin));
    EXPECT_FALSE(api_.Blockchain().Stop(b::Type::Ethereum_ropsten));
    EXPECT_FALSE(api_.Blockchain().Stop(b::Type::Ethereum_frontier));
    EXPECT_TRUE(api_.Blockchain().Stop(b::Type::BitcoinCash_testnet3));
    EXPECT_TRUE(api_.Blockchain().Stop(b::Type::BitcoinCash));
    EXPECT_TRUE(api_.Blockchain().Stop(b::Type::Bitcoin_testnet3));
    EXPECT_TRUE(api_.Blockchain().Stop(b::Type::Bitcoin));
}
}  // namespace
