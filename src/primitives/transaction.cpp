// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2019 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/transaction.h"

#include "hashwrapper.h"
#include "policy/policy.h"
#include "tinyformat.h"
#include "utilstrencodings.h"

#include "arith_uint256.h"


std::string COutPoint::ToString() const { return strprintf("COutPoint(%s, %u)", hash.ToString().substr(0, 10), n); }
CTxIn::CTxIn(COutPoint prevoutIn, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = prevoutIn;
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

CTxIn::CTxIn(uint256 hashPrevTx, uint32_t nOut, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = COutPoint(hashPrevTx, nOut);
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

std::string CTxIn::ToString() const
{
    std::string str;
    str += "CTxIn(";
    str += prevout.ToString();
    if (prevout.IsNull())
        str += strprintf(", coinbase %s", HexStr(scriptSig));
    else
        str += strprintf(", scriptSig=%s", HexStr(scriptSig).substr(0, 24));
    if (nSequence != SEQUENCE_FINAL)
        str += strprintf(", nSequence=%u", nSequence);
    str += ")";
    return str;
}

CTxOut::CTxOut(const CAmount &nValueIn, CScript scriptPubKeyIn)
{
    nValue = nValueIn;
    scriptPubKey = scriptPubKeyIn;
}

uint256 CTxOut::GetHash() const { return SerializeHash(*this); }
std::string CTxOut::ToString() const
{
    return strprintf(
        "CTxOut(nValue=%d.%08d, scriptPubKey=%s)", nValue / COIN, nValue % COIN, HexStr(scriptPubKey).substr(0, 30));
}

CMutableTransaction::CMutableTransaction() : nVersion(CTransaction::CURRENT_VERSION), nLockTime(0) {}
CMutableTransaction::CMutableTransaction(const CTransaction &tx)
    : nVersion(tx.nVersion), vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime)
{
}

uint256 CMutableTransaction::GetHash() const { return SerializeHash(*this); }
void CTransaction::UpdateHash() const { *const_cast<uint256 *>(&hash) = SerializeHash(*this); }
CTransaction::CTransaction() : nTxSize(0), nVersion(CTransaction::CURRENT_VERSION), vin(), vout(), nLockTime(0) {}
CTransaction::CTransaction(const CMutableTransaction &tx)
    : nTxSize(0), nVersion(tx.nVersion), vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime)
{
    UpdateHash();
}

CTransaction::CTransaction(CMutableTransaction &&tx)
    : nTxSize(0), nVersion(tx.nVersion), vin(std::move(tx.vin)), vout(std::move(tx.vout)), nLockTime(tx.nLockTime)
{
    UpdateHash();
}

CTransaction::CTransaction(const CTransaction &tx)
    : nTxSize(tx.nTxSize.load()), nVersion(tx.nVersion), vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime)
{
    UpdateHash();
};

CTransaction &CTransaction::operator=(const CTransaction &tx)
{
    nTxSize.store(tx.nTxSize);
    *const_cast<int *>(&nVersion) = tx.nVersion;
    *const_cast<std::vector<CTxIn> *>(&vin) = tx.vin;
    *const_cast<std::vector<CTxOut> *>(&vout) = tx.vout;
    *const_cast<unsigned int *>(&nLockTime) = tx.nLockTime;
    *const_cast<uint256 *>(&hash) = tx.hash;
    return *this;
}

bool CTransaction::IsEquivalentTo(const CTransaction &tx) const
{
    CMutableTransaction tx1 = *this;
    CMutableTransaction tx2 = tx;
    for (unsigned int i = 0; i < tx1.vin.size(); i++)
        tx1.vin[i].scriptSig = CScript();
    for (unsigned int i = 0; i < tx2.vin.size(); i++)
        tx2.vin[i].scriptSig = CScript();
    return CTransaction(tx1) == CTransaction(tx2);
}

CAmount CTransaction::GetValueOut() const
{
    CAmount nValueOut = 0;
    for (std::vector<CTxOut>::const_iterator it(vout.begin()); it != vout.end(); ++it)
    {
        nValueOut += it->nValue;
        if (!MoneyRange(it->nValue) || !MoneyRange(nValueOut))
            throw std::runtime_error("CTransaction::GetValueOut(): value out of range");
    }
    return nValueOut;
}

double CTransaction::ComputePriority(double dPriorityInputs, unsigned int nSize) const
{
    nSize = CalculateModifiedSize(nSize);
    if (nSize == 0)
        return 0.0;

    return dPriorityInputs / nSize;
}

unsigned int CTransaction::CalculateModifiedSize(unsigned int nSize) const
{
    // In order to avoid disincentivizing cleaning up the UTXO set we don't count
    // the constant overhead for each txin and up to 110 bytes of scriptSig (which
    // is enough to cover a compressed pubkey p2sh redemption) for priority.
    // Providing any more cleanup incentive than making additional inputs free would
    // risk encouraging people to create junk outputs to redeem later.
    if (nSize == 0)
        nSize = GetTxSize();
    for (std::vector<CTxIn>::const_iterator it(vin.begin()); it != vin.end(); ++it)
    {
        unsigned int offset = 41U + std::min(110U, (unsigned int)it->scriptSig.size());
        if (nSize > offset)
            nSize -= offset;
    }
    return nSize;
}

std::string CTransaction::ToString() const
{
    std::string str;
    str += strprintf("CTransaction(hash=%s, ver=%d, vin.size=%u, vout.size=%u, nLockTime=%u)\n",
        GetHash().ToString().substr(0, 10), nVersion, vin.size(), vout.size(), nLockTime);
    for (unsigned int i = 0; i < vin.size(); i++)
        str += "    " + vin[i].ToString() + "\n";
    for (unsigned int i = 0; i < vout.size(); i++)
        str += "    " + vout[i].ToString() + "\n";
    return str;
}

size_t CTransaction::GetTxSize() const
{
    if (nTxSize == 0)
        nTxSize = ::GetSerializeSize(*this, SER_NETWORK, CTransaction::CURRENT_VERSION);
    return nTxSize;
}


bool CTransaction::HasData() const
{
    for (auto &out : vout)
    {
        if ((out.scriptPubKey.size() >= 1) && (out.scriptPubKey[0] == OP_RETURN))
            return true;
    }
    return false;
}

bool CTransaction::HasData(uint32_t dataID) const
{
    for (auto &out : vout)
    {
        if ((out.scriptPubKey.size() >= 6) && (out.scriptPubKey[0] == OP_RETURN) &&
            (out.scriptPubKey[1] == 4)) // IDs must be 4 bytes so check that the pushdata opcode is correct
        {
            uint32_t thisProto = ReadLE32(&out.scriptPubKey[2]);
            if (thisProto == dataID)
                return true;
        }
    }
    return false;
}

CAmount CTxOut::GetValueWithInterest(int outputBlockHeight, int valuationHeight) const{

    return GetInterest(nValue, outputBlockHeight, valuationHeight);
    //return nValue;
}

static int ONEDAY=1108;
static int MAXINTERESTPERIOD=ONEDAY*365;
static int MAXINTERESTPERIODPLUSONE=ONEDAY*365+1;

static uint64_t rateTable[1108*365+1];

CAmount getRateForAmount(int periods, CAmount theAmount){

    //CBigNum amount256(theAmount);
    //CBigNum rate256(rateTable[periods]);
    //CBigNum rate0256(rateTable[0]);
    //CBigNum result=(amount256*rate256)/rate0256;
    //return  result.getuint64()-theAmount;

    const arith_uint256 amount256=arith_uint256(theAmount);
    const arith_uint256 rate256=arith_uint256(rateTable[periods]);
    const arith_uint256 rate0256=arith_uint256(rateTable[0]);
    const arith_uint256 product=amount256*rate256;
    const arith_uint256 result=product/rate0256;
    return result.GetLow64()-theAmount;
}

std::string initRateTable(){
    std::string str;

    rateTable[0]=1;
    rateTable[0]=rateTable[0]<<62;
    
    //Interest rate on each block 1+(1/2^22)
    for(int i=1;i<MAXINTERESTPERIOD+1;i++){
        rateTable[i]=rateTable[i-1]+(rateTable[i-1]>>22);
        str += strprintf("%d %x\n",i,rateTable[i]);
    }

    for(int i=0;i<MAXINTERESTPERIOD;i++){
        str += strprintf("rate: %d %d\n",i,getRateForAmount(i,COIN*100));
    }

    return str;
}




CAmount GetInterest(CAmount nValue, int outputBlockHeight, int valuationHeight){

    //These conditions generally should not occur
    if(outputBlockHeight<0 || valuationHeight<0 || valuationHeight<outputBlockHeight){
        return nValue;
    }

    int blocks=std::min(MAXINTERESTPERIOD,valuationHeight-outputBlockHeight);

    CAmount standardInterest=getRateForAmount(blocks, nValue);

    return nValue+standardInterest;
}