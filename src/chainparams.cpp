// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/merkle.h>
#include <tinyformat.h>
#include <util/moneystr.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <versionbitsinfo.h>

#include <assert.h>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

// This part of the code is meant to mine the genesis block
const arith_uint256 maxUint = UintToArith256(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
static void MineGenesis(CBlockHeader& genesisBlock, const uint256& powLimit, uint32_t nTime)
{
    genesisBlock.nTime = nTime;
    genesisBlock.nNonce = 0;

    printf("NOTE: Genesis nTime = %u \n", genesisBlock.nTime);
    printf("WARN: Genesis nNonce (BLANK!) = %u \n", genesisBlock.nNonce);

    arith_uint256 besthash;
    memset(&besthash, 0xFF, 32);
    arith_uint256 hashTarget = UintToArith256(powLimit);
    printf("Target: %s\n", hashTarget.GetHex().c_str());
    arith_uint256 newhash = UintToArith256(genesisBlock.GetHash());
    while (newhash > hashTarget) {
        genesisBlock.nNonce++;
        if (genesisBlock.nNonce == 0) {
            printf("NONCE WRAPPED, incrementing time\n");
            ++genesisBlock.nTime;
        }
        // If nothing found after trying for a while, print status
        if ((genesisBlock.nNonce & 0xffff) == 0)
            printf("nonce %08X: hash = %s \r",
                genesisBlock.nNonce, newhash.ToString().c_str(),
                hashTarget.ToString().c_str());

        if (newhash < besthash) {
            besthash = newhash;
            printf("New best: %s\n", newhash.GetHex().c_str());
        }
        newhash = UintToArith256(genesisBlock.GetHash());
    }
    printf("\nGenesis nTime = %u \n", genesisBlock.nTime);
    printf("Genesis nNonce = %u \n", genesisBlock.nNonce);
    printf("Genesis nBits: %08x\n", genesisBlock.nBits);
    printf("Genesis Hash = %s\n", newhash.ToString().c_str());
    printf("Genesis Hash Merkle Root = %s\n", genesisBlock.hashMerkleRoot.ToString().c_str());
    printf("Genesis Hash Witness Merkle Root = %s\n", genesisBlock.hashWitnessMerkleRoot.ToString().c_str());
}

int64_t CChainParams::GetProofOfStakeReward(const CBlockIndex* pindexPrev, int64_t nFees) const
{
    int64_t nSubsidy;

    nSubsidy = (pindexPrev->nMoneySupply / COIN) * GetCoinYearReward() / (365 * 24 * (60 * 60 / nTargetSpacing));

    return nSubsidy + nFees;
};

int64_t CChainParams::GetMaxSmsgFeeRateDelta(int64_t smsg_fee_prev) const
{
    return (smsg_fee_prev * consensus.smsg_fee_max_delta_percent) / 1000000;
};


bool CChainParams::IsBech32Prefix(const std::vector<unsigned char>& vchPrefixIn) const
{
    for (auto& hrp : bech32Prefixes) {
        if (vchPrefixIn == hrp) {
            return true;
        }
    }

    return false;
};

bool CChainParams::IsBech32Prefix(const std::vector<unsigned char>& vchPrefixIn, CChainParams::Base58Type& rtype) const
{
    for (size_t k = 0; k < MAX_BASE58_TYPES; ++k) {
        auto& hrp = bech32Prefixes[k];
        if (vchPrefixIn == hrp) {
            rtype = static_cast<CChainParams::Base58Type>(k);
            return true;
        }
    }

    return false;
};

bool CChainParams::IsBech32Prefix(const char* ps, size_t slen, CChainParams::Base58Type& rtype) const
{
    for (size_t k = 0; k < MAX_BASE58_TYPES; ++k) {
        const auto& hrp = bech32Prefixes[k];
        size_t hrplen = hrp.size();
        if (hrplen > 0 && slen > hrplen && strncmp(ps, (const char*)&hrp[0], hrplen) == 0) {
            rtype = static_cast<CChainParams::Base58Type>(k);
            return true;
        }
    }

    return false;
};

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime = nTime;
    genesis.nBits = nBits;
    genesis.nNonce = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

const std::pair<const char*, CAmount> regTestOutputs[] = {
    std::make_pair("0771e79337a6c03ef6f59b7e16fdff97cb4c052f", 28800000 * COIN),
    std::make_pair("d72f98a68aa0ddb2bcd5d5236133fca4b716116a", 28800000 * COIN),
    std::make_pair("4af0ecde8daaa8ddf010e176cd7d983c2055fd77", 28800000 * COIN),
    std::make_pair("333dd84caa587b09974437279e2f0223f5fcef9d", 28800000 * COIN),
    std::make_pair("46b38169bd7a394e9163e4de66e31ad8f8309015", 28800000 * COIN),
    std::make_pair("c433cddb95166bf9ca88fe6a0a132d1a83ac4b48", 28800000 * COIN),
    std::make_pair("712a1272096031f524e5e7d483f38f48e470188a", 28800000 * COIN),
    std::make_pair("9d2ea1d2f594229d3021c98c37d74b398f981fbf", 28800000 * COIN),
    std::make_pair("566ea779be1404add415f5c241dbc1d2e2cddf02", 28800000 * COIN),
    std::make_pair("9157712b73ff408032166da0cd1104f6015060db", 28800000 * COIN)
};
const size_t nGenesisOutputsRegtest = sizeof(regTestOutputs) / sizeof(regTestOutputs[0]);

const std::pair<const char*, CAmount> genesisOutputsTestnet[] = {
    std::make_pair("0771e79337a6c03ef6f59b7e16fdff97cb4c052f", 28800000 * COIN),
    std::make_pair("d72f98a68aa0ddb2bcd5d5236133fca4b716116a", 28800000 * COIN),
    std::make_pair("4af0ecde8daaa8ddf010e176cd7d983c2055fd77", 28800000 * COIN),
    std::make_pair("333dd84caa587b09974437279e2f0223f5fcef9d", 28800000 * COIN),
    std::make_pair("46b38169bd7a394e9163e4de66e31ad8f8309015", 28800000 * COIN),
    std::make_pair("c433cddb95166bf9ca88fe6a0a132d1a83ac4b48", 28800000 * COIN),
    std::make_pair("712a1272096031f524e5e7d483f38f48e470188a", 28800000 * COIN),
    std::make_pair("9d2ea1d2f594229d3021c98c37d74b398f981fbf", 28800000 * COIN),
    std::make_pair("566ea779be1404add415f5c241dbc1d2e2cddf02", 28800000 * COIN),
    std::make_pair("9157712b73ff408032166da0cd1104f6015060db", 28800000 * COIN)
};
const size_t nGenesisOutputsTestnet = sizeof(genesisOutputsTestnet) / sizeof(genesisOutputsTestnet[0]);

const std::pair<const char*, CAmount> genesisOutputs[] = {
    std::make_pair("4bb5b701023e17c32c0cc1cbbaf895110ef0f920", 14400000 * COIN),
    std::make_pair("ab6c3617682d3de8c90a4ae2b5bb75ad9d428544", 14400000 * COIN),
    std::make_pair("119e3995e6ed8a0404935eb0c6d011c050a3f7b9", 14400000 * COIN),
    std::make_pair("82ba19de741557c123bad505b0e9ad78a8b6d39b", 14400000 * COIN),
    std::make_pair("c58ac867ca5fe49e35fc742e8ecc7700f43d8de9", 14400000 * COIN),
    std::make_pair("1f412aaa3eb83fef657736dd18169c6a905fb4f7", 14400000 * COIN),
    std::make_pair("c606d8b3563d4985b6f799556adca4e3fb8b2e6c", 14400000 * COIN),
    std::make_pair("56778d1a5d9f3f25aa233955456e300b6cf53a3c", 14400000 * COIN),
    std::make_pair("6e392f27a95eaa782f99187c347ec049fcad8a9a", 14400000 * COIN),
    std::make_pair("b5fb3775f2bb31aaa1b5925ad09af9f2b08bf952", 14400000 * COIN),
    std::make_pair("1bfc58f310de241dd57c7ba641df0738eb001eba", 14400000 * COIN),
    std::make_pair("011fdd438fcd397234560efa13e8f4e5278ab966", 14400000 * COIN),
    std::make_pair("73b1646e7a9d3577beb80da4d30c89e63dbe576e", 14400000 * COIN),
    std::make_pair("2933cf9d3f077aa4a963c3fd4f2351983e7aff24", 14400000 * COIN),
    std::make_pair("a571dd7a5e64d0d9f8b3c34f62e512bb82eb3ca4", 14400000 * COIN),
    std::make_pair("72edbc3f92728646e2cfb1b7cb8f1be14ab8c5fc", 14400000 * COIN),
    std::make_pair("b462173b71103a6f0498e55f7f3f403b62d74999", 14400000 * COIN),
    std::make_pair("a8ad63f07702bd0378603143a88f53e8364cf5c5", 14400000 * COIN),
    std::make_pair("c6198f94e6b0037eebbac7671f6ee58267654ad8", 14400000 * COIN),
    std::make_pair("47433c5f1dd1948e692fb30758652733666dad13", 13900000 * COIN),
    std::make_pair("5fdf9173001aa20d8d4b84243cb258df1b19765e", 125000 * COIN),
    std::make_pair("0391e7c6ec2a5519ac71053e4cf9632a6d1a02a3", 125000 * COIN),
    std::make_pair("5de62de4299cbcfefbd087bff0ab0f950f42ec98", 125000 * COIN),
    std::make_pair("6ed424eb2caea4e33c3d9ac75735e35a6575b779", 125000 * COIN)
};
const size_t nGenesisOutputs = sizeof(genesisOutputs) / sizeof(genesisOutputs[0]);

static CBlock CreateGenesisBlockRegTest(uint32_t nTime, uint32_t nNonce, uint32_t nBits)
{
    const char* pszTimestamp = "Capricoin+ 00000000000000000007316856900e76b4f7a9139cfbfba89842c8d196cd5f91";

    CMutableTransaction txNew;
    txNew.nVersion = CAPRICOINPLUS_TXN_VERSION;
    txNew.SetType(TXN_COINBASE);
    txNew.vin.resize(1);
    uint32_t nHeight = 0; // bip34
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp)) << OP_RETURN << nHeight;

    txNew.vpout.resize(nGenesisOutputsRegtest);
    for (size_t k = 0; k < nGenesisOutputsRegtest; ++k) {
        OUTPUT_PTR<CTxOutStandard> out = MAKE_OUTPUT<CTxOutStandard>();
        out->nValue = regTestOutputs[k].second;
        out->scriptPubKey = CScript() << OP_DUP << OP_HASH160 << ParseHex(regTestOutputs[k].first) << OP_EQUALVERIFY << OP_CHECKSIG;
        txNew.vpout[k] = out;
    }

    CBlock genesis;
    genesis.nTime = nTime;
    genesis.nBits = nBits;
    genesis.nNonce = nNonce;
    genesis.nVersion = CAPRICOINPLUS_BLOCK_VERSION;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));

    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    genesis.hashWitnessMerkleRoot = BlockWitnessMerkleRoot(genesis);

    return genesis;
}

static CBlock CreateGenesisBlockTestNet(uint32_t nTime, uint32_t nNonce, uint32_t nBits)
{
    const char* pszTimestamp = "Capricoin+ 00000000000000000007316856900e76b4f7a9139cfbfba89842c8d196cd5f91";

    CMutableTransaction txNew;
    txNew.nVersion = CAPRICOINPLUS_TXN_VERSION;
    txNew.SetType(TXN_COINBASE);
    txNew.vin.resize(1);
    uint32_t nHeight = 0; // bip34
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp)) << OP_RETURN << nHeight;

    txNew.vpout.resize(nGenesisOutputsTestnet);
    for (size_t k = 0; k < nGenesisOutputsTestnet; ++k) {
        OUTPUT_PTR<CTxOutStandard> out = MAKE_OUTPUT<CTxOutStandard>();
        out->nValue = genesisOutputsTestnet[k].second;
        out->scriptPubKey = CScript() << OP_DUP << OP_HASH160 << ParseHex(genesisOutputsTestnet[k].first) << OP_EQUALVERIFY << OP_CHECKSIG;
        txNew.vpout[k] = out;
    }

    CBlock genesis;
    genesis.nTime = nTime;
    genesis.nBits = nBits;
    genesis.nNonce = nNonce;
    genesis.nVersion = CAPRICOINPLUS_BLOCK_VERSION;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));

    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    genesis.hashWitnessMerkleRoot = BlockWitnessMerkleRoot(genesis);

    return genesis;
}

static CBlock CreateGenesisBlockMainNet(uint32_t nTime, uint32_t nNonce, uint32_t nBits)
{
    const char* pszTimestamp = "Capricoin+ 00000000000000000007316856900e76b4f7a9139cfbfba89842c8d196cd5f91";

    CMutableTransaction txNew;
    txNew.nVersion = CAPRICOINPLUS_TXN_VERSION;
    txNew.SetType(TXN_COINBASE);

    txNew.vin.resize(1);
    uint32_t nHeight = 0; // bip34
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp)) << OP_RETURN << nHeight;

    txNew.vpout.resize(nGenesisOutputs);
    for (size_t k = 0; k < nGenesisOutputs; ++k) {
        OUTPUT_PTR<CTxOutStandard> out = MAKE_OUTPUT<CTxOutStandard>();
        out->nValue = genesisOutputs[k].second;
        out->scriptPubKey = CScript() << OP_DUP << OP_HASH160 << ParseHex(genesisOutputs[k].first) << OP_EQUALVERIFY << OP_CHECKSIG;
        txNew.vpout[k] = out;
    }

    CBlock genesis;
    genesis.nTime = nTime;
    genesis.nBits = nBits;
    genesis.nNonce = nNonce;
    genesis.nVersion = CAPRICOINPLUS_BLOCK_VERSION;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));

    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    genesis.hashWitnessMerkleRoot = BlockWitnessMerkleRoot(genesis);

    return genesis;
}

/**
 * Main network
 */
class CMainParams : public CChainParams
{
public:
    CMainParams()
    {
        strNetworkID = "main";

        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP34Height = 0;
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.OpIsCoinstakeTime = 0;
        consensus.fAllowOpIsCoinstakeWithP2PKH = false;
        consensus.nPaidSmsgTime = 0;
        consensus.csp2shTime = 0;
        consensus.smsg_fee_time = 0;
        consensus.bulletproof_time = 0;
        consensus.rct_time = 0;
        consensus.smsg_difficulty_time = 0;

        consensus.smsg_fee_period = 5040;
        consensus.smsg_fee_funding_tx_per_k = 200000;
        consensus.smsg_fee_msg_per_day_per_k = 50000;
        consensus.smsg_fee_max_delta_percent = 43;
        consensus.smsg_min_difficulty = 0x1effffff;
        consensus.smsg_difficulty_max_delta = 0xffff;

        consensus.powLimit = uint256S("000000000000bfffffffffffffffffffffffffffffffffffffffffffffffffff");

        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016;       // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999;   // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1462060800; // May 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800;   // May 1st, 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1479168000; // November 15th, 2016.
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1510704000;   // November 15th, 2017.

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000010001");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x5a1e8651002ce2d5a43144e4e62b4a91b8189e976175fa4e69195c21607d1bf9"); // 560766

        consensus.nMinRCTOutputDepth = 12;

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0x21;
        pchMessageStart[1] = 0x05;
        pchMessageStart[2] = 0x60;
        pchMessageStart[3] = 0x19;
        nDefaultPort = 11111;
        nBIP44ID = 0x800001b4;

        nModifierInterval = 10 * 60;  // 10 minutes
        nStakeMinConfirmations = 240; // 240 confirmations or roughly 4 hours
        nTargetSpacing = 60;          // 1 minute
        nTargetTimespan = 24 * 60;    // 24 mins

        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        genesis = CreateGenesisBlockMainNet(1577836800, 9967772, 0x1f00ffff);
        // MineGenesis(genesis, consensus.powLimit, 1577836800);
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x000000cd73f9b36d570feea64a5db4c719d888b69c927f22c2af07c9eecea90b"));
        assert(genesis.hashMerkleRoot == uint256S("0x070818e3b7dc95c49ffa37d094743c331a3e2f516619975d3c359378a6d3026c"));
        assert(genesis.hashWitnessMerkleRoot == uint256S("0xc2dc3f95a291b6778a37c0883a10e88265a4c836a5fd0e5a18b50980fc402230"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as a oneshot if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        vSeeds.emplace_back("maindns1.capricoin.org");
        vSeeds.emplace_back("maindns2.capricoin.org");
        vSeeds.emplace_back("maindns3.capricoin.org");
        vSeeds.emplace_back("maindns4.capricoin.org");

        base58Prefixes[PUBKEY_ADDRESS] = {0x12}; // 8
        base58Prefixes[SCRIPT_ADDRESS] = {0x32}; // M
        base58Prefixes[PUBKEY_ADDRESS_256] = {0x13};
        base58Prefixes[SCRIPT_ADDRESS_256] = {0x33};
        base58Prefixes[SECRET_KEY] = {0x92};
        base58Prefixes[EXT_PUBLIC_KEY] = {0x03, 0x9f, 0xa8, 0xa0};     // mcpb
        base58Prefixes[EXT_SECRET_KEY] = {0x03, 0x9f, 0xa9, 0x25};     // mcpv
        base58Prefixes[STEALTH_ADDRESS] = {0x14};                      // S
        base58Prefixes[EXT_KEY_HASH] = {0x4b};                         // X
        base58Prefixes[EXT_ACC_HASH] = {0x17};                         // A
        base58Prefixes[EXT_PUBLIC_KEY_BTC] = {0x04, 0x88, 0xB2, 0x1E}; // xpub
        base58Prefixes[EXT_SECRET_KEY_BTC] = {0x04, 0x88, 0xAD, 0xE4}; // xprv

        bech32Prefixes[PUBKEY_ADDRESS].assign("ch", (const char*)"ch" + 2);
        bech32Prefixes[SCRIPT_ADDRESS].assign("cr", (const char*)"cr" + 2);
        bech32Prefixes[PUBKEY_ADDRESS_256].assign("cl", (const char*)"cl" + 2);
        bech32Prefixes[SCRIPT_ADDRESS_256].assign("cj", (const char*)"cj" + 2);
        bech32Prefixes[SECRET_KEY].assign("cx", (const char*)"cx" + 2);
        bech32Prefixes[EXT_PUBLIC_KEY].assign("cep", (const char*)"cep" + 3);
        bech32Prefixes[EXT_SECRET_KEY].assign("cex", (const char*)"cex" + 3);
        bech32Prefixes[STEALTH_ADDRESS].assign("cs", (const char*)"cs" + 2);
        bech32Prefixes[EXT_KEY_HASH].assign("cek", (const char*)"cek" + 3);
        bech32Prefixes[EXT_ACC_HASH].assign("cea", (const char*)"cea" + 3);
        bech32Prefixes[STAKE_ONLY_PKADDR].assign("ccs", (const char*)"ccs" + 3);

        bech32_hrp = "cp";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = {};

        chainTxData = ChainTxData{
            // Data from rpc: getchaintxstats
            /* nTime    */ 0,
            /* nTxCount */ 0,
            /* dTxRate  */ 0};

        /* disable fallback fee on mainnet */
        m_fallback_fee_enabled = false;
    }

    void SetOld()
    {
        consensus.BIP16Exception = uint256S("0x00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22");
        consensus.BIP34Height = 227931;
        consensus.BIP34Hash = uint256S("0x000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8");
        consensus.BIP65Height = 388381; // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
        consensus.BIP66Height = 363725; // 00000000000000000379eaa19dce8c9b722d46ae6a57c2f1a988119488b50931
        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

        genesis = CreateGenesisBlock(1231006505, 2083236893, 0x1d00ffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 5);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "bc";
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams
{
public:
    CTestNetParams()
    {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP34Height = 0;
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.OpIsCoinstakeTime = 0;
        consensus.fAllowOpIsCoinstakeWithP2PKH = true; // TODO: clear for next testnet
        consensus.nPaidSmsgTime = 0;
        consensus.csp2shTime = 0;
        consensus.smsg_fee_time = 0;
        consensus.bulletproof_time = 0;
        consensus.rct_time = 0;
        consensus.smsg_difficulty_time = 0;

        consensus.smsg_fee_period = 5040;
        consensus.smsg_fee_funding_tx_per_k = 200000;
        consensus.smsg_fee_msg_per_day_per_k = 50000;
        consensus.smsg_fee_max_delta_percent = 43;
        consensus.smsg_min_difficulty = 0x1effffff;
        consensus.smsg_difficulty_max_delta = 0xffff;

        consensus.powLimit = uint256S("000000000005ffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016;       // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999;   // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1456790400; // March 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800;   // May 1st, 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1462060800; // May 1st 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1493596800;   // May 1st 2017

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000010001");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x51143e8e5a5fd68f0aebdb8eca15950826db6cc3d7ed8aec447444aff74174bc"); // 511910

        consensus.nMinRCTOutputDepth = 12;

        pchMessageStart[0] = 0x16;
        pchMessageStart[1] = 0x23;
        pchMessageStart[2] = 0x1d;
        pchMessageStart[3] = 0x0b;
        nDefaultPort = 12111;
        nBIP44ID = 0x80000001;

        nModifierInterval = 10 * 60;  // 10 minutes
        nStakeMinConfirmations = 240; // 240 confirmations or roughly 4 hours
        nTargetSpacing = 60;          // 1 minute
        nTargetTimespan = 24 * 60;    // 24 mins

        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        genesis = CreateGenesisBlockTestNet(1574847000, 6542589, 0x1f00ffff);
        // MineGenesis(genesis, consensus.powLimit, 1574847000);
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x0000008f2c8ee4519ea09d2b0299665db8ac1b41f192c9b20f2966a7cf26c3cb"));
        assert(genesis.hashMerkleRoot == uint256S("0x5b65d14be35919c2e6bc31cad4d832162e96c7523490efc2f73ee34f40a1bfad"));
        assert(genesis.hashWitnessMerkleRoot == uint256S("0x0363370a5996b32fad71c61cef55182fbcde9b6de58d73a8946b2c181e00feaf"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.emplace_back("testdns1.capricoin.org");
        vSeeds.emplace_back("testdns2.capricoin.org");
        vSeeds.emplace_back("testdns3.capricoin.org");
        vSeeds.emplace_back("testdns4.capricoin.org");

        base58Prefixes[PUBKEY_ADDRESS] = {0x7f}; // t
        base58Prefixes[SCRIPT_ADDRESS] = {0x6e}; // m
        base58Prefixes[PUBKEY_ADDRESS_256] = {0x80};
        base58Prefixes[SCRIPT_ADDRESS_256] = {0x6f};
        base58Prefixes[SECRET_KEY] = {0xff};
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x31, 0x32, 0xac};     // tcpb
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x31, 0x33, 0x30};     // tcpv
        base58Prefixes[STEALTH_ADDRESS] = {0x15};                      // T
        base58Prefixes[EXT_KEY_HASH] = {0x89};                         // x
        base58Prefixes[EXT_ACC_HASH] = {0x53};                         // a
        base58Prefixes[EXT_PUBLIC_KEY_BTC] = {0x04, 0x35, 0x87, 0xCF}; // tpub
        base58Prefixes[EXT_SECRET_KEY_BTC] = {0x04, 0x35, 0x83, 0x94}; // tprv

        bech32Prefixes[PUBKEY_ADDRESS].assign("tch", (const char*)"tch" + 3);
        bech32Prefixes[SCRIPT_ADDRESS].assign("tcr", (const char*)"tcr" + 3);
        bech32Prefixes[PUBKEY_ADDRESS_256].assign("tcl", (const char*)"tcl" + 3);
        bech32Prefixes[SCRIPT_ADDRESS_256].assign("tcj", (const char*)"tcj" + 3);
        bech32Prefixes[SECRET_KEY].assign("tcx", (const char*)"tcx" + 3);
        bech32Prefixes[EXT_PUBLIC_KEY].assign("tcep", (const char*)"tcep" + 4);
        bech32Prefixes[EXT_SECRET_KEY].assign("tcex", (const char*)"tcex" + 4);
        bech32Prefixes[STEALTH_ADDRESS].assign("tcs", (const char*)"tcs" + 3);
        bech32Prefixes[EXT_KEY_HASH].assign("tcek", (const char*)"tcek" + 4);
        bech32Prefixes[EXT_ACC_HASH].assign("tcea", (const char*)"tcea" + 4);
        bech32Prefixes[STAKE_ONLY_PKADDR].assign("tccs", (const char*)"tccs" + 4);

        bech32_hrp = "tcp";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;

        checkpointData = {};

        chainTxData = ChainTxData{
            // Data from rpc: getchaintxstats
            /* nTime    */ 0,
            /* nTxCount */ 0,
            /* dTxRate  */ 0};

        /* enable fallback fee on testnet */
        m_fallback_fee_enabled = true;
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams
{
public:
    explicit CRegTestParams(const ArgsManager& args)
    {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP16Exception = uint256();
        consensus.BIP34Height = 500; // BIP34 activated on regtest (Used in functional tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in functional tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in functional tests)
        consensus.OpIsCoinstakeTime = 0;
        consensus.fAllowOpIsCoinstakeWithP2PKH = false;
        consensus.nPaidSmsgTime = 0;
        consensus.csp2shTime = 0;
        consensus.smsg_fee_time = 0;
        consensus.bulletproof_time = 0;
        consensus.rct_time = 0;
        consensus.smsg_difficulty_time = 0;

        consensus.smsg_fee_period = 50;
        consensus.smsg_fee_funding_tx_per_k = 200000;
        consensus.smsg_fee_msg_per_day_per_k = 50000;
        consensus.smsg_fee_max_delta_percent = 4300;
        consensus.smsg_min_difficulty = 0x1f0fffff;
        consensus.smsg_difficulty_max_delta = 0xffff;

        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144;       // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        consensus.nMinRCTOutputDepth = 2;

        pchMessageStart[0] = 0x16;
        pchMessageStart[1] = 0x23;
        pchMessageStart[2] = 0x1d;
        pchMessageStart[3] = 0x0b;
        nDefaultPort = 13111;
        nBIP44ID = 0x80000001;

        nModifierInterval = 60; // 1 minute
        nStakeMinConfirmations = 12;
        nTargetSpacing = 5;        // 5 seconds
        nTargetTimespan = 16 * 60; // 16 mins
        nStakeTimestampMask = 0;

        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        UpdateVersionBitsParametersFromArgs(args);

        genesis = CreateGenesisBlockRegTest(1574847000, 6542589, 0x1f00ffff);
        // MineGenesis(genesis, consensus.powLimit, 1574847000);
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x0000008f2c8ee4519ea09d2b0299665db8ac1b41f192c9b20f2966a7cf26c3cb"));
        assert(genesis.hashMerkleRoot == uint256S("0x5b65d14be35919c2e6bc31cad4d832162e96c7523490efc2f73ee34f40a1bfad"));
        assert(genesis.hashWitnessMerkleRoot == uint256S("0x0363370a5996b32fad71c61cef55182fbcde9b6de58d73a8946b2c181e00feaf"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = {};

        base58Prefixes[PUBKEY_ADDRESS] = {0x7f}; // t
        base58Prefixes[SCRIPT_ADDRESS] = {0x6e}; // m
        base58Prefixes[PUBKEY_ADDRESS_256] = {0x80};
        base58Prefixes[SCRIPT_ADDRESS_256] = {0x6f};
        base58Prefixes[SECRET_KEY] = {0xff};
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x31, 0x32, 0xac};     // tcpb
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x31, 0x33, 0x30};     // tcpv
        base58Prefixes[STEALTH_ADDRESS] = {0x15};                      // T
        base58Prefixes[EXT_KEY_HASH] = {0x89};                         // x
        base58Prefixes[EXT_ACC_HASH] = {0x53};                         // a
        base58Prefixes[EXT_PUBLIC_KEY_BTC] = {0x04, 0x35, 0x87, 0xCF}; // tpub
        base58Prefixes[EXT_SECRET_KEY_BTC] = {0x04, 0x35, 0x83, 0x94}; // tprv

        bech32Prefixes[PUBKEY_ADDRESS].assign("tch", (const char*)"tch" + 3);
        bech32Prefixes[SCRIPT_ADDRESS].assign("tcr", (const char*)"tcr" + 3);
        bech32Prefixes[PUBKEY_ADDRESS_256].assign("tcl", (const char*)"tcl" + 3);
        bech32Prefixes[SCRIPT_ADDRESS_256].assign("tcj", (const char*)"tcj" + 3);
        bech32Prefixes[SECRET_KEY].assign("tcx", (const char*)"tcx" + 3);
        bech32Prefixes[EXT_PUBLIC_KEY].assign("tcep", (const char*)"tcep" + 4);
        bech32Prefixes[EXT_SECRET_KEY].assign("tcex", (const char*)"tcex" + 4);
        bech32Prefixes[STEALTH_ADDRESS].assign("tcs", (const char*)"tcs" + 3);
        bech32Prefixes[EXT_KEY_HASH].assign("tcek", (const char*)"tcek" + 4);
        bech32Prefixes[EXT_ACC_HASH].assign("tcea", (const char*)"tcea" + 4);
        bech32Prefixes[STAKE_ONLY_PKADDR].assign("tccs", (const char*)"tccs" + 4);

        bech32_hrp = "rtcp";

        chainTxData = ChainTxData{
            0,
            0,
            0};

        /* enable fallback fee on regtest */
        m_fallback_fee_enabled = true;
    }

    void SetOld()
    {
        genesis = CreateGenesisBlock(1296688602, 2, 0x207fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        /*
        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        */

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 196);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "bcrt";
    }

    /**
     * Allows modifying the Version Bits regtest parameters.
     */
    void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
    void UpdateVersionBitsParametersFromArgs(const ArgsManager& args);
};

void CRegTestParams::UpdateVersionBitsParametersFromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-vbparams"))
        return;

    for (const std::string& strDeployment : args.GetArgs("-vbparams")) {
        std::vector<std::string> vDeploymentParams;
        boost::split(vDeploymentParams, strDeployment, boost::is_any_of(":"));
        if (vDeploymentParams.size() != 3) {
            throw std::runtime_error("Version bits parameters malformed, expecting deployment:start:end");
        }
        int64_t nStartTime, nTimeout;
        if (!ParseInt64(vDeploymentParams[1], &nStartTime)) {
            throw std::runtime_error(strprintf("Invalid nStartTime (%s)", vDeploymentParams[1]));
        }
        if (!ParseInt64(vDeploymentParams[2], &nTimeout)) {
            throw std::runtime_error(strprintf("Invalid nTimeout (%s)", vDeploymentParams[2]));
        }
        bool found = false;
        for (int j = 0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
            if (vDeploymentParams[0] == VersionBitsDeploymentInfo[j].name) {
                UpdateVersionBitsParameters(Consensus::DeploymentPos(j), nStartTime, nTimeout);
                found = true;
                LogPrintf("Setting version bits activation parameters for %s to start=%ld, timeout=%ld\n", vDeploymentParams[0], nStartTime, nTimeout);
                break;
            }
        }
        if (!found) {
            throw std::runtime_error(strprintf("Invalid deployment (%s)", vDeploymentParams[0]));
        }
    }
}

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams& Params()
{
    assert(globalChainParams);
    return *globalChainParams;
}

const CChainParams* pParams()
{
    return globalChainParams.get();
};

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams(gArgs));
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}

void SetOldParams(std::unique_ptr<CChainParams>& params)
{
    if (params->NetworkID() == CBaseChainParams::MAIN) {
        return ((CMainParams*)params.get())->SetOld();
    }
    if (params->NetworkID() == CBaseChainParams::REGTEST) {
        return ((CRegTestParams*)params.get())->SetOld();
    }
};

void ResetParams(std::string sNetworkId, bool fCapricoinPlusModeIn)
{
    // Hack to pass old unit tests
    globalChainParams = CreateChainParams(sNetworkId);
    if (!fCapricoinPlusModeIn) {
        SetOldParams(globalChainParams);
    }
};

/**
 * Mutable handle to regtest params
 */
CChainParams& RegtestParams()
{
    return *globalChainParams.get();
};
