// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/block.h"

#include "hash.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "chainparams.h"
#include "consensus/params.h"
#include "crypto/common.h"
#include "streams.h"

#include <cstdlib>

uint256 CBlockHeader::GetHash(const Consensus::Params& consensusParams) const
{
    CDataStream ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << *this;

    const auto pbegin = (const unsigned char *)&ss.begin()[0];
    uint256 hash;

    const HashAlgorithm algo = consensusParams.PowAlgorithmForTime(nTime);
    switch (algo) {
        case HashAlgorithm::SHA256:
            CSHA256().Write(pbegin, ss.size()).Finalize((unsigned char*)&hash);
            break;
        case HashAlgorithm::SHA256d:
            CHash256().Write(pbegin, ss.size()).Finalize((unsigned char*)&hash);
            break;
        case HashAlgorithm::RIPEMD160:
            CRIPEMD160().Write(pbegin, ss.size()).Finalize((unsigned char*)&hash);
            break;
        case HashAlgorithm::HASH160:
            CHash160().Write(pbegin, ss.size()).Finalize((unsigned char*)&hash);
            break;
        case HashAlgorithm::NUM_HASH_ALGOS:
            // Should be impossible
            abort();
    }

    return hash;
}

uint256 CBlockHeader::GetHash() const
{
    const Consensus::Params& consensusParams = Params().GetConsensus();
    return GetHash(consensusParams);
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (unsigned int i = 0; i < vtx.size(); i++)
    {
        s << "  " << vtx[i]->ToString() << "\n";
    }
    return s.str();
}

int64_t GetBlockWeight(const CBlock& block)
{
    // This implements the weight = (stripped_size * 4) + witness_size formula,
    // using only serialization with and without witness data. As witness_size
    // is equal to total_size - stripped_size, this formula is identical to:
    // weight = (stripped_size * 3) + total_size.
    return ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * (WITNESS_SCALE_FACTOR - 1) + ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION);
}
