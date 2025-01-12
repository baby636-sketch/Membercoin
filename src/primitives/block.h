// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2021 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_BLOCK_H
#define BITCOIN_PRIMITIVES_BLOCK_H

#include "primitives/transaction.h"
#include "protocol.h"
#include "serialize.h"
#include "uint256.h"


class arith_uint256;

const uint32_t BIP_009_MASK = 0x20000000;
const uint32_t BASE_VERSION = 0x20000000;
const uint32_t FORK_BIT_2MB = 0x10000000; // Vote for 2MB fork
const bool DEFAULT_2MB_VOTE = false;

class CXThinBlock;
class CThinBlock;
class CompactBlock;
class CGrapheneBlock;

/** Get the work equivalent for the supplied nBits of difficulty */
arith_uint256 GetWorkForDifficultyBits(uint32_t nBits);

/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */
class CBlockHeader
{
public:
    // header
    static const int32_t CURRENT_VERSION = BASE_VERSION;
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;
    //uint32_t nStartLocation=0;
    //uint32_t nFinalCalculation=0;

    CBlockHeader() { SetNull(); }
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(this->nVersion);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);
        //READWRITE(nStartLocation);
        //READWRITE(nFinalCalculation);
    }

    bool operator==(const CBlockHeader &b)
    {
        return (nVersion == b.nVersion && hashPrevBlock == b.hashPrevBlock && hashMerkleRoot == b.hashMerkleRoot &&
                nTime == b.nTime && nBits == b.nBits && nNonce == b.nNonce );
    }

    void SetNull()
    {
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0;
        nBits = 0;
        nNonce = 0;
        //nStartLocation = 0;
        //nFinalCalculation = 0;
    }

    bool IsNull() const { return (nBits == 0); }
    uint256 GetHash() const;
    uint256 GetMidHash() const;
    
    int64_t GetBlockTime() const { return (int64_t)nTime; }

    std::string ToString() const;
};
/** The expected size of a serialized block header */
static const unsigned int SERIALIZED_HEADER_SIZE = ::GetSerializeSize(CBlockHeader(), SER_NETWORK, PROTOCOL_VERSION);

class CBlock : public CBlockHeader
{
private:
    // memory only
    mutable uint64_t nBlockSize; // Serialized block size in bytes

public:
    // Xpress Validation: (memory only)
    //! Orphans, or Missing transactions that have been re-requested, are stored here.
    std::set<uint256> setUnVerifiedTxns;

    // Xpress Validation: (memory only)
    //! A flag which when true indicates that Xpress validation is enabled for this block.
    bool fXVal;

public:
    // network and disk
    std::vector<CTransactionRef> vtx;

    // memory only
    // 0.11: mutable std::vector<uint256> vMerkleTree;
    mutable bool fChecked;
    mutable bool fExcessive; // Is the block "excessive"

    CBlock() { SetNull(); }
    CBlock(const CBlockHeader &header)
    {
        SetNull();
        *((CBlockHeader *)this) = header;
    }

    static bool VersionKnown(int32_t nVersion, int32_t voteBits)
    {
        if (nVersion >= 1 && nVersion <= 4)
            return true;
        // BIP009 / versionbits:
        if (nVersion & BIP_009_MASK)
        {
            uint32_t v = nVersion & ~BIP_009_MASK;
            if ((v & ~voteBits) == 0)
                return true;
        }
        return false;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(*(CBlockHeader *)this);
        READWRITE(vtx);
    }

    uint64_t GetHeight() const // Returns the block's height as specified in its coinbase transaction
    {
        if (nVersion < 2)
            throw std::runtime_error("Block does not contain height");
        const CScript &sig = vtx[0]->vin[0].scriptSig;
        int numlen = sig[0];
        if (numlen == OP_0)
            return 0;
        if ((numlen >= OP_1) && (numlen <= OP_16))
            return numlen - OP_1 + 1;
        // Did you call this on a pre BIP34, or it could be a deliberately invalid block
        if ((int)sig.size() - 1 < numlen)
            throw std::runtime_error("Invalid block height");
        std::vector<unsigned char> heightScript(numlen);
        copy(sig.begin() + 1, sig.begin() + 1 + numlen, heightScript.begin());
        CScriptNum coinbaseHeight(heightScript, false, numlen);
        return coinbaseHeight.getint();
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        fChecked = false;
        fExcessive = false;
        fXVal = false;
        nBlockSize = 0;
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion = nVersion;
        block.hashPrevBlock = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime = nTime;
        block.nBits = nBits;
        block.nNonce = nNonce;
        //block.nStartLocation    = nStartLocation;
        //block.nFinalCalculation = nFinalCalculation;
        return block;
    }

    std::string ToString() const;

    // Return the serialized block size in bytes. This is only done once and then the result stored
    // in nBlockSize for future reference, saving unncessary and expensive serializations.
    uint64_t GetBlockSize() const;
};

/**
 * Used for thin type blocks that we want to reconstruct into a full block. All the data
 * necessary to recreate the block are held within the thinrelay objects which are subsequently
 * stored within this class as smart pointers.
 */
class CBlockThinRelay : public CBlock
{
public:
    //! thinrelay block types: (memory only)
    std::shared_ptr<CThinBlock> thinblock;
    std::shared_ptr<CXThinBlock> xthinblock;
    std::shared_ptr<CompactBlock> cmpctblock;
    std::shared_ptr<CGrapheneBlock> grapheneblock;

    //! Track the current block size during reconstruction: (memory only)
    uint64_t nCurrentBlockSize;

    CBlockThinRelay() { SetNull(); }
    ~CBlockThinRelay() { SetNull(); }
    void SetNull()
    {
        CBlock::SetNull();
        nCurrentBlockSize = 0;
        thinblock.reset();
        xthinblock.reset();
        cmpctblock.reset();
        grapheneblock.reset();
    }
};

/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
struct CBlockLocator
{
    std::vector<uint256> vHave;

    CBlockLocator() {}
    CBlockLocator(const std::vector<uint256> &vHaveIn) { vHave = vHaveIn; }
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vHave);
    }

    void SetNull() { vHave.clear(); }
    bool IsNull() const { return vHave.empty(); }
};

typedef std::shared_ptr<CBlock> CBlockRef;
typedef std::shared_ptr<const CBlock> ConstCBlockRef;

static inline CBlockRef MakeBlockRef() { return std::make_shared<CBlock>(); }
template <typename Blk>
static inline CBlockRef MakeBlockRef(Blk &&blkIn)
{
    return std::make_shared<CBlock>(std::forward<Blk>(blkIn));
}

#endif // BITCOIN_PRIMITIVES_BLOCK_H
