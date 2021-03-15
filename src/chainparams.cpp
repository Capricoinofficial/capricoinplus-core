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
// const arith_uint256 maxUint = UintToArith256(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
// static void MineGenesis(CBlockHeader& genesisBlock, const uint256& powLimit, uint32_t nTime)
// {
//     genesisBlock.nTime = nTime;
//     genesisBlock.nNonce = 0;

//     printf("NOTE: Genesis nTime = %u \n", genesisBlock.nTime);
//     printf("WARN: Genesis nNonce (BLANK!) = %u \n", genesisBlock.nNonce);

//     arith_uint256 besthash;
//     memset(&besthash, 0xFF, 32);
//     arith_uint256 hashTarget = UintToArith256(powLimit);
//     printf("Target: %s\n", hashTarget.GetHex().c_str());
//     arith_uint256 newhash = UintToArith256(genesisBlock.GetHash());
//     while (newhash > hashTarget) {
//         genesisBlock.nNonce++;
//         if (genesisBlock.nNonce == 0) {
//             printf("NONCE WRAPPED, incrementing time\n");
//             ++genesisBlock.nTime;
//         }
//         // If nothing found after trying for a while, print status
//         if ((genesisBlock.nNonce & 0xffff) == 0)
//             printf("nonce %08X: hash = %s \r",
//                 genesisBlock.nNonce, newhash.ToString().c_str(),
//                 hashTarget.ToString().c_str());

//         if (newhash < besthash) {
//             besthash = newhash;
//             printf("New best: %s\n", newhash.GetHex().c_str());
//         }
//         newhash = UintToArith256(genesisBlock.GetHash());
//     }
//     printf("\nGenesis nTime = %u \n", genesisBlock.nTime);
//     printf("Genesis nNonce = %u \n", genesisBlock.nNonce);
//     printf("Genesis nBits: %08x\n", genesisBlock.nBits);
//     printf("Genesis Hash = %s\n", newhash.ToString().c_str());
//     printf("Genesis Hash Merkle Root = %s\n", genesisBlock.hashMerkleRoot.ToString().c_str());
//     printf("Genesis Hash Witness Merkle Root = %s\n", genesisBlock.hashWitnessMerkleRoot.ToString().c_str());
// }

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
    std::make_pair("9157712b73ff408032166da0cd1104f6015060db", 28800000 * COIN)};
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
    std::make_pair("9157712b73ff408032166da0cd1104f6015060db", 28800000 * COIN)};
const size_t nGenesisOutputsTestnet = sizeof(genesisOutputsTestnet) / sizeof(genesisOutputsTestnet[0]);

const std::pair<const char*, CAmount> genesisOutputs[] = {
    std::make_pair("8064137791265f99b633e3ebccc721590559e1db", 9600000 * COIN),
    std::make_pair("9dd8fb5ac2698d70dec877a0d7dc61d0f4e148c1", 9600000 * COIN),
    std::make_pair("cd01712ef433483395652611239fc102032fcd78", 9600000 * COIN),
    std::make_pair("04860494ef7f5d9b1ff03fc3658df985fb921829", 9600000 * COIN),
    std::make_pair("d2b872b57ea6d5fb5f3f1a7cb8f68c7ed3d0fb9a", 9600000 * COIN),
    std::make_pair("ee5779c825e3690049440698d54ef4796fd4172c", 9600000 * COIN),
    std::make_pair("d8186f79450d7135dfcb0e2febd490f0f0d3b5ce", 9600000 * COIN),
    std::make_pair("db42699332a15f4fc0ee952a40911947ba03e5c0", 9600000 * COIN),
    std::make_pair("6bdd0f98183a5f85636d733178180c90a5de78f3", 9600000 * COIN),
    std::make_pair("e110429da488b1b7d5a31fc0a028a07ce9ee38dd", 9600000 * COIN),
    std::make_pair("be425f4239b5a2c10d15ee965eaada180473f7b3", 9600000 * COIN),
    std::make_pair("4c7c429e8ec87879d1d494dd5e6c275190519e87", 9600000 * COIN),
    std::make_pair("95399d0a28ec3b3dba346b43343c0ac76a95f19b", 9600000 * COIN),
    std::make_pair("38cbc08ba62f9fb5eddd41010fb3cd2401e9dcb5", 9600000 * COIN),
    std::make_pair("b52b517c9e6bf98daf5d5c05cc06b6ab420f268f", 9600000 * COIN),
    std::make_pair("b817cb8c9c5c5a80a19e16d3886fbbde30f68093", 9600000 * COIN),
    std::make_pair("780085a7aeb0c8d1e2f3a5c413a7823df11bc0a7", 9600000 * COIN),
    std::make_pair("cd3d0df7df3b001ea61adec099e1107eb16dc75c", 9600000 * COIN),
    std::make_pair("95f9d59c8318941f815c00d75632c76f021adf94", 9600000 * COIN),
    std::make_pair("6b061304cd6cc53f59de6f73294ccb58f8d523da", 9600000 * COIN),
    std::make_pair("18258003482b4be66ecc261719638c0a6465355a", 9600000 * COIN),
    std::make_pair("111407d33fa4e61596f85efa1527b5a2bbcc040b", 9600000 * COIN),
    std::make_pair("a37193b5e4b2e3fe64b0096720fb0fc9f35a6663", 9600000 * COIN),
    std::make_pair("1dcdbc606e0ab29e86148e3bf47868fcefdf4818", 9600000 * COIN),
    std::make_pair("3d93f3abd6d938c3001767dac421c0d9e30b4eb3", 9600000 * COIN),
    std::make_pair("d43c05f22283750d52bcf7215b571fae8a0cef13", 9600000 * COIN),
    std::make_pair("d22119751fcd37de4b2594d04c837465ee380ce7", 9600000 * COIN),
    std::make_pair("d876b222e055e16a7c25db1591c298bd7e43cad8", 9600000 * COIN),
    std::make_pair("d370b51c3c6057930755f2bc20cc49e60e13b320", 9600000 * COIN),
    std::make_pair("3f50437321200896d773cfc106d5c0ec4608b73b", 8600000 * COIN),
    std::make_pair("d6fb9846b0391a2fe551200ab6abe4bd75da2c26", 100000 * COIN),
    std::make_pair("2e838b37660930cd7cdbaa27d7789482ee0b65ca", 100000 * COIN),
    std::make_pair("e24a1939fe74be88643fba5acf4c89b02cf2b766", 100000 * COIN),
    std::make_pair("8009fcb03ab33bced4297e3d0c04145777e7e80b", 100000 * COIN),
    std::make_pair("42bbf228d4b5b598f0a67ea930b3d8d4fa21d00c", 100000 * COIN),
    std::make_pair("9a8f92d2e71d3112f35e9370cb5b8e2642feb477", 100000 * COIN),
    std::make_pair("9c03f2a324b003237afaa7a75be161a4fa57ee91", 100000 * COIN),
    std::make_pair("7775081d45ff950d7e2d3d555a41f4736168cd1f", 100000 * COIN),
    std::make_pair("36a557c49657db83d801fce5cd2288572c618c7a", 100000 * COIN),
    std::make_pair("3058a24b18235176f2a0dbb1306b08194eed069f", 100000 * COIN)};
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
        consensus.rct_fix_time = 1617235200;
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
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000003dcd9f6068c3774d2ec");

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
        nBIP44ID = 0x800001d4;

        nModifierInterval = 10 * 60;  // 10 minutes
        nStakeMinConfirmations = 240; // 240 confirmations or roughly 4 hours
        nTargetSpacing = 60;          // 1 minute
        nTargetTimespan = 24 * 60;    // 24 mins

        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 1;
        m_assumed_chain_state_size = 1;

        genesis = CreateGenesisBlockMainNet(1577836800, 400587, 0x1f00ffff);
        // MineGenesis(genesis, consensus.powLimit, 1577836800);
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x000000a9d134165ec65a4eaf31a2f035a8a6378fd888f69ad56c8d45ea93d34f"));
        assert(genesis.hashMerkleRoot == uint256S("0xab31a61a0dd0295ab93d1a42bb15ebfe70360e5fb30f385c3e8316e22dd18479"));
        assert(genesis.hashWitnessMerkleRoot == uint256S("0x47ee528ebc554fd8a6054fcab29087c7a613d68da3bcce6f5e5a4d8ef1d2b697"));

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

        checkpointData = {
            {
                {5000, uint256S("0xf314525635ba0f7fe65a4c5b58d5b8ed9e8244d633c3b492daa6116b9edea194")},
                {10000, uint256S("0xdddd67c9fe83e2e6be596c3aa221f366af65c62983367f8bd65663f64c422d75")},
                {20000, uint256S("0xee4bc451b9230ff7b48879928decd59a935c85ee33a6aa571462380849ef5eb6")},
                {30000, uint256S("0x31394117fadf6f3ad270405e23fdd40e29a1a92ff9e6f2a6eff6f18b61b29e65")},
                {40000, uint256S("0xfee3357b3a8f568a11df0c5fcf6ae8c68bb5ebbaabf2a46e122b5938eaf4aab1")},
                {50000, uint256S("0xd5fc9756e246a74fbf4c52330c18e8fd1195ad04cd2729a20ddbca97799f65bb")},
                {60000, uint256S("0x1b8cce36766bba43e3018a846a4b4938dc04a389b6b632dc611ae832d84810c3")},
                {70000, uint256S("0xa69d2eb24505b88947c4c9091e18d7d7726455d2faacd2558671f52daef02864")},
                {80000, uint256S("0x69c12ce7eac09662adb263267da6d84fa0e8b81a37978867ef05d0b8d46b436b")},
                {90000, uint256S("0xcc9670d6897ca5478f2d65bf0be42e08774ca18402afae2b2bac0d81982c4424")},
                {100000, uint256S("0x1a02fdb5a0fff97ff9d354a19bc646dfe6637fe8254561d92f3b014658179bdc")},
                {110000, uint256S("0x3e6235f03ad5924e6431360081d4ebc0bd6cf3e1203601fd8513629ed650b3fa")},
                {120000, uint256S("0x0c5cc99abe30fe51f76ff0c71cade4c42f97c802234518f66eba74170bfd7230")},
                {150000, uint256S("0xfeb9979e179b674dd5517b8fcf5b69c5e5810cd1d02c87966d9ae3fff7c66cb3")},
                {200000, uint256S("0xf8a3cc833723e23e2b5221166a35cc3149ef3d402d4d591748a163a37667d4d0")},
                {250000, uint256S("0x03873ae9d63ea235f85dc79de70d44eec1eca0451feace2f35ebfc248382f840")},
                {300000, uint256S("0x996faada82f7e75124ac0a661ce3c390fdf0097124929af76349f3867c8c24f4")},
                {350000, uint256S("0x8d8b9d1770cb2a8720fe4423fe33a176eb618155b7314caacd1734a639b31c42")},
                {365000, uint256S("0x11e866ece83fe502de6b3810057a2652f994e1a1e2ab22dfc1d9315285673b74")},
                {400000, uint256S("0xfaa697fa663149d38f7300c1679f8b55d65a1a4ef236c1a95e5952f149bcfd35")},
                {500000, uint256S("0x4f0cddd5ea142db7cfcb18db927de8bf1c24f4fa92653e5bb31870fd1a1b5691")},
                {600000, uint256S("0x89e2fcfcddcb2674c35e3ce3a83c7c7fceb647d1bf4b5b756ab005fec86c21dc")},
                {601950, uint256S("0xbd690073add5047fb3289c7df606b9b58334793a81d826aa178a8f7ec5ef2182")},

            }};

        chainTxData = ChainTxData{
            // Data from rpc: getchaintxstats
            /* nTime    */ 1615812464,
            /* nTxCount */ 636598,
            /* dTxRate  */ 0.017};

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
        consensus.rct_fix_time = 1615833800;
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
        consensus.nMinimumChainWork = uint256S("0x00000000000000000000000000000000000000000000002996399ab1fb637840");

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
        m_assumed_blockchain_size = 1;
        m_assumed_chain_state_size = 1;

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

        checkpointData = {
            {
                {5000, uint256S("0x552fbfcf63470d8571bc2287b4f8854502f6554b330fc91c110c9b3c6b03bdc7")},
                {10000, uint256S("0xc50427872920660ddc6e81ad3c2a6e2361c1c956196df0361fc1e70feba0e280")},
                {50000, uint256S("0x349cf4e02ec8f11fbcc5f2e4fa5e479e97123fbd7a0b390c4453324975939075")},
                {100000, uint256S("0x4a9af02f24f6ed859bb2b67dde29b5e19fb2a2bd546c0c3f57dc5d78d35870ee")},
                {150000, uint256S("0x38eb0799b43f9e13c74adedcadf07d8f65163f897e2eba0a3c086bbcf37138ab")},
                {175000, uint256S("0xb5b824ddfe0e6a5e35252fec724ea6a1bf0d0898e00ad578bf28dc3df283a353")},
                {300000, uint256S("0x193c17e75838b1f567f6f044e4efbe268f279dc26034f0150d9cc81d60aaffc4")},
                {400000, uint256S("0x91532b1904da390cc11382a1213d94b9f6d65b33fc61d325f120e49a35ae6240")},
                {500000, uint256S("0x194d73035aac29960f037669c3b7ea8a5afc43f5b7eabd82a412ca842b7ab110")},
                {582750, uint256S("0x5bc46d0187dbd256775a668f761493a207b7dd9d886a8987ecc36d6e46279641")},
            }
        };

        chainTxData = ChainTxData{
            // Data from rpc: getchaintxstats
            /* nTime    */ 1615812848,
            /* nTxCount */ 582888,
            /* dTxRate  */ 0.001};

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
