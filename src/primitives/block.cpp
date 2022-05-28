// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2019 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/block.h"

#include "arith_uint256.h"

#include "crypto/common.h"
#include "hashwrapper.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "patternsearch.h"




blake3_hasher hasher;


uint256 CBlockHeader::GetHash() const
{
    /*
    uint256 midHash = GetMidHash();
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, &midHash, 32);
    uint8_t output[BLAKE3_OUT_LEN];
    blake3_hasher_finalize(&hasher, output, BLAKE3_OUT_LEN);
    //std::memcpy(&midHash, &output, 32);
    midHash = uint256(output);
    return midHash;
    */

    //for (size_t i = 0; i < BLAKE3_OUT_LEN; i++) {
    //    printf("%02x", output[i]);
    //}

    /*uint256 cacheBlockHash=Hash(BEGIN(nVersion), END(nFinalCalculation));
    if(!patternsearch::pattern_verify( midHash, nStartLocation, nFinalCalculation)){
        return uint256S("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    }else{
        return cacheBlockHash;
    }*/
    
    /*static unsigned char pblank[1];

    const typename pbegin = BEGIN(nVersion);
    const typename pend = END(nNonce);
    //Initialize a blake3_hasher in the default hashing mode.
    blake3_hasher_init(&hasher);

    blake3_hasher_update( &hasher, (pbegin == pend ? pblank : (unsigned char*)&pbegin[0]), (pend - pbegin) * sizeof(pbegin[0]) );

    // Finalize the hash. BLAKE3_OUT_LEN is the default output length, 32 bytes.
    uint256 hash1;
    blake3_hasher_finalize(&hasher, (unsigned char*)&hash1, BLAKE3_OUT_LEN);
    return hash1;*/
    return HashBlake3(BEGIN(nVersion), END(nNonce));
}

uint256 CBlockHeader::GetMidHash() const
{
    return Hash(BEGIN(nVersion), END(nNonce));
    //return SerializeHash(*this);
}

uint256 CBlockHeader::FindBestPatternHash(int& collisions,char *scratchpad,int nThreads) {

        uint256 smallestHashSoFar = uint256S("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        uint32_t smallestHashLocation=0;
        uint32_t smallestHashFinalCalculation=0;


        if(nThreads==0){
            return smallestHashSoFar;
        }

        uint256 midHash = GetMidHash();

        //Threads can only be a power of 2
        int newThreadNumber = 1;
        while(newThreadNumber < nThreads){
            newThreadNumber*=2;
        }
        nThreads=newThreadNumber;


        std::vector< std::pair<uint32_t,uint32_t> > results =patternsearch::pattern_search( midHash,scratchpad,nThreads);
        //uint32_t candidateStartLocation=0;
        //uint32_t candidateFinalCalculation=0;

        collisions=results.size();
        uint256 fullHash = smallestHashSoFar;

        for (unsigned i=0; i < results.size(); i++) {

            //nStartLocation = results[i].first;
            //nFinalCalculation = results[i].second;
            fullHash = Hash(BEGIN(nVersion), END(nNonce));
            //LogPrintf("Consider Candidate:%s\n",fullHash.ToString());
            //LogPrintf("against:%s\n",smallestHashSoFar.ToString());

            if(UintToArith256(fullHash)<UintToArith256(smallestHashSoFar)){
                //LogPrintf("New Best Candidate:%s\n",fullHash.ToString());
                //if better, update location
                //printf("best hash so far for the nonce\n");
                smallestHashSoFar=fullHash;
                smallestHashLocation=results[i].first;
                smallestHashFinalCalculation=results[i].second;
            }
        }

        //nStartLocation = smallestHashLocation;
        //nFinalCalculation = smallestHashFinalCalculation;
        //printf("fbph %d %d\n", nStartLocation, nFinalCalculation);
        return smallestHashSoFar;
    }

//uint256 CBlockHeader::GetHash() const { return SerializeHash(*this); }
std::string CBlockHeader::ToString() const
{
    std::stringstream s;
    s << strprintf(
        "CBlock(hash=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u)\n",
        GetHash().ToString(), nVersion, hashPrevBlock.ToString(), hashMerkleRoot.ToString(), nTime, nBits, nNonce);
    //for (unsigned int i = 0; i < vtx.size(); i++)
    //{
    //    s << "  " << vtx[i]->ToString() << "\n";
    //}
    return s.str();
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf(
        "CBlock(hash=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u)\n",
        GetHash().ToString(), nVersion, hashPrevBlock.ToString(), hashMerkleRoot.ToString(), nTime, nBits, nNonce);
    for (unsigned int i = 0; i < vtx.size(); i++)
    {
        s << "  " << vtx[i]->ToString() << "\n";
    }
    return s.str();
}

uint64_t CBlock::GetBlockSize() const
{
    if (nBlockSize == 0)
        nBlockSize = ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION);
    return nBlockSize;
}


arith_uint256 GetWorkForDifficultyBits(uint32_t nBits)
{
    arith_uint256 bnTarget;
    bool fNegative;
    bool fOverflow;
    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);
    if (fNegative || fOverflow || bnTarget == 0)
        return 0;
    // We need to compute 2**256 / (bnTarget+1), but we can't represent 2**256
    // as it's too large for a arith_uint256. However, as 2**256 is at least as large
    // as bnTarget+1, it is equal to ((2**256 - bnTarget - 1) / (bnTarget+1)) + 1,
    // or ~bnTarget / (nTarget+1) + 1.
    return (~bnTarget / (bnTarget + 1)) + 1;
}
